package vuln

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)

// FindingXSS describes a discovered potential XSS
type FindingXSS struct {
	Type            string            `json:"type"`
	URL             string            `json:"url"`
	Context         string            `json:"context,omitempty"`
	Payload         string            `json:"payload,omitempty"`
	ResponseSnippet string            `json:"response_snippet,omitempty"`
	PostedTo        string            `json:"posted_to,omitempty"`
	PostedData      map[string]string `json:"posted_data,omitempty"`
	Timestamp       string            `json:"timestamp"`
}

// PostedPayload used for stored detection
type PostedPayload struct {
	URL    string
	Method string
	Data   map[string]string
	Marker string
}

// Scanner holds scanning state
type Scanner struct {
	StartURL      *url.URL
	Client        *http.Client
	Visited       map[string]bool
	VisitedMu     sync.RWMutex
	Queue         chan crawlJob
	Findings      []FindingXSS
	FindingsMu    sync.Mutex
	Posted        []PostedPayload
	PostedMu      sync.Mutex
	Workers       int
	Active        int32
	MaxPages      int
	PageCount     int
	PageCountMu   sync.Mutex
	MaxDepth      int
	UseChrome     bool
	Chromectx     context.Context
	ChromeCancel  context.CancelFunc
	PayloadsBasic []string
	PayloadsFull  []string
	Intensity     string // basic|full|both
	Throttle      time.Duration
}

// crawlJob for queue
type crawlJob struct {
	URL   string
	Depth int
}

// helper: create marker
func makeMarker() string {
	b := make([]byte, 6)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("mk%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// basic and full payload lists (expandable)
func defaultPayloads() ([]string, []string) {
	basic := []string{
		`<svg/onload=alert(1)>`,
		`"><svg/onload=alert(1)>`,
		`'><img src=x onerror=alert(1)>`,
		`<script>alert(1)</script>`,
		`"><script>alert(1)</script>`,
	}
	full := []string{
		`<svg/onload=alert(1)>`,
		`"><svg/onload=alert(1)>`,
		`'><img src=x onerror=alert(1)>`,
		`"><img src=x onerror=alert(1)>`,
		`"><input autofocus onfocus=alert(1)>`,
		`"><svg><g/onload=alert(1)></svg>`,
		`"><body onload=alert(1)>`,
		`"><iframe srcdoc='<script>alert(1)</script>'></iframe>`,
		`" onmouseover=alert(1) x="`,
		`' onfocus=alert(1) x='`,
		`${alert(1)}`, // template-like
		`&lt;script&gt;alert(1)&lt;/script&gt;`,
		`javascript:alert(1)`,
	}
	return basic, full
}

// create scanner
func newScanner(start string, workers, maxPages, maxDepth int, intensity string, useChrome bool, throttle time.Duration) (*Scanner, error) {
	parsed, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	s := &Scanner{
		StartURL:  parsed,
		Client:    client,
		Visited:   make(map[string]bool),
		Queue:     make(chan crawlJob, 1000),
		Findings:  []FindingXSS{},
		Posted:    []PostedPayload{},
		Workers:   workers,
		MaxPages:  maxPages,
		MaxDepth:  maxDepth,
		UseChrome: useChrome,
		Intensity: intensity,
		Throttle:  throttle,
	}
	basic, full := defaultPayloads()
	s.PayloadsBasic = basic
	s.PayloadsFull = full

	if useChrome {
		ctx, cancel := chromedp.NewContext(context.Background())
		s.Chromectx = ctx
		s.ChromeCancel = cancel
	}
	return s, nil
}

// add finding
func (s *Scanner) addFinding(f FindingXSS) {
	s.FindingsMu.Lock()
	defer s.FindingsMu.Unlock()
	f.Timestamp = time.Now().UTC().Format(time.RFC3339)
	s.Findings = append(s.Findings, f)
	log.Printf("[FINDING] %s %s\n", f.Type, f.URL)
}

// mark posted for stored detection
func (s *Scanner) recordPosted(p PostedPayload) {
	s.PostedMu.Lock()
	s.Posted = append(s.Posted, p)
	s.PostedMu.Unlock()
}

// mark visited
func (s *Scanner) markVisited(u string) bool {
	s.VisitedMu.Lock()
	defer s.VisitedMu.Unlock()
	if s.Visited[u] {
		return false
	}
	s.Visited[u] = true
	s.PageCountMu.Lock()
	s.PageCount++
	s.PageCountMu.Unlock()
	return true
}

// same origin check
func (s *Scanner) sameOrigin(u *url.URL) bool {
	return u.Scheme == s.StartURL.Scheme && eqHost(u.Host, s.StartURL.Host)
}

func eqHost(a, b string) bool {
	// simple host compare (includes port if present)
	return strings.EqualFold(a, b)
}

// normalize and ensure same origin, remove fragment
func (s *Scanner) normalize(base, href string) (string, error) {
	if href == "" {
		return "", fmt.Errorf("empty")
	}
	parsedBase, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	parsedHref, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", err
	}
	resolved := parsedBase.ResolveReference(parsedHref)
	resolved.Fragment = ""
	if !s.sameOrigin(resolved) {
		return "", fmt.Errorf("different origin")
	}
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme")
	}
	return resolved.String(), nil
}

// fetch a URL with headers
func (s *Scanner) fetch(u string, extra map[string]string) (int, string, string, error) {
	// throttle
	if s.Throttle > 0 {
		time.Sleep(s.Throttle)
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", "GoXSSScanner/1.0")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	mt, _, _ := mime.ParseMediaType(ct)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	return resp.StatusCode, string(bodyBytes), mt, nil
}

// post form urlencoded
func (s *Scanner) postForm(u string, data url.Values, extra map[string]string) (int, string, string, error) {
	if s.Throttle > 0 {
		time.Sleep(s.Throttle)
	}
	req, err := http.NewRequest("POST", u, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "GoXSSScanner/1.0")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	mt, _, _ := mime.ParseMediaType(ct)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	return resp.StatusCode, string(bodyBytes), mt, nil
}

// snippet helper
func snippetAround(body, marker string, r int) string {
	idx := strings.Index(body, marker)
	if idx == -1 {
		if len(body) <= 200 {
			return body
		}
		return body[:200] + "..."
	}
	start := idx - r
	if start < 0 {
		start = 0
	}
	end := idx + len(marker) + r
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// fuzz URL params
func (s *Scanner) fuzzParams(rawurl string) {
	parsed, err := url.Parse(rawurl)
	if err != nil {
		return
	}
	q := parsed.Query()
	if len(q) == 0 {
		return
	}
	payloads := s.PayloadsBasic
	if s.Intensity == "full" {
		payloads = s.PayloadsFull
	}
	if s.Intensity == "both" {
		payloads = append(payloads, s.PayloadsFull...)
	}
	// limit per param for speed
	for name := range q {
		if len(q.Get(name)) > 2048 {
			continue
		}
		for i, p := range payloads {
			// throttle number of payloads in basic mode
			if s.Intensity == "basic" && i > 6 {
				break
			}
			marker := makeMarker()
			payload := insertMarker(p, marker)
			q.Set(name, payload)
			parsed.RawQuery = q.Encode()
			test := parsed.String()
			_, body, _, err := s.fetch(test, map[string]string{"Referer": s.StartURL.String()})
			if err != nil {
				continue
			}
			if strings.Contains(body, payload) {
				s.addFinding(FindingXSS{
					Type:            "reflected",
					URL:             test,
					Context:         fmt.Sprintf("param-%s", name),
					Payload:         payload,
					ResponseSnippet: snippetAround(body, payload, 120),
				})
			}
			// encoded variant check
			if strings.Contains(body, htmlEscape(payload)) {
				s.addFinding(FindingXSS{
					Type:            "reflected-encoded",
					URL:             test,
					Context:         fmt.Sprintf("param-%s", name),
					Payload:         payload,
					ResponseSnippet: snippetAround(body, htmlEscape(payload), 120),
				})
			}
		}
	}
}

// helper to insert marker
func insertMarker(p, marker string) string {
	if strings.Contains(p, "alert(1)") {
		return strings.Replace(p, "alert(1)", "alert(1);/*"+marker+"*/", 1)
	}
	return p + "/*" + marker + "*/"
}

// html escape simple
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// fuzz forms on a page
func (s *Scanner) fuzzForms(pageURL, body string) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return
	}
	payloads := s.PayloadsBasic
	if s.Intensity == "full" {
		payloads = s.PayloadsFull
	}
	if s.Intensity == "both" {
		payloads = append(payloads, s.PayloadsFull...)
	}

	doc.Find("form").Each(func(i int, f *goquery.Selection) {
		method, _ := f.Attr("method")
		action, _ := f.Attr("action")
		if action == "" {
			action = pageURL
		} else {
			n, err := s.normalize(pageURL, action)
			if err == nil {
				action = n
			} else {
				action = pageURL
			}
		}
		method = strings.ToUpper(method)
		if method == "" {
			method = "GET"
		}
		// collect input names
		data := map[string]string{}
		f.Find("input,textarea,select").Each(func(i int, inp *goquery.Selection) {
			name, ok := inp.Attr("name")
			if !ok || strings.TrimSpace(name) == "" {
				return
			}
			val, _ := inp.Attr("value")
			data[name] = val
		})
		// fuzz each param
		for name := range data {
			orig := data[name]
			for i, p := range payloads {
				if s.Intensity == "basic" && i > 6 {
					break
				}
				marker := makeMarker()
				payload := insertMarker(p, marker)
				data[name] = payload
				posted := map[string]string{}
				for k, v := range data {
					posted[k] = v
				}
				s.recordPosted(PostedPayload{URL: action, Method: method, Data: posted, Marker: payload})
				// submit
				if method == "POST" {
					form := url.Values{}
					for k, v := range data {
						form.Set(k, v)
					}
					_, respBody, _, err := s.postForm(action, form, map[string]string{"Referer": s.StartURL.String()})
					if err == nil {
						if strings.Contains(respBody, payload) {
							s.addFinding(FindingXSS{
								Type:            "reflected-form",
								URL:             action,
								Context:         fmt.Sprintf("form-%s", name),
								Payload:         payload,
								ResponseSnippet: snippetAround(respBody, payload, 120),
								PostedTo:        action,
								PostedData:      posted,
							})
						}
					}
				} else {
					u, err := url.Parse(action)
					if err == nil {
						q := u.Query()
						for k, v := range data {
							q.Set(k, v)
						}
						u.RawQuery = q.Encode()
						_, respBody, _, err := s.fetch(u.String(), map[string]string{"Referer": s.StartURL.String()})
						if err == nil && strings.Contains(respBody, payload) {
							s.addFinding(FindingXSS{
								Type:            "reflected-form",
								URL:             u.String(),
								Context:         fmt.Sprintf("form-%s", name),
								Payload:         payload,
								ResponseSnippet: snippetAround(respBody, payload, 120),
								PostedTo:        u.String(),
								PostedData:      posted,
							})
						}
					}
				}
				// restore
				data[name] = orig
			}
		}
	})
}

// analyze response for stored markers
func (s *Scanner) analyzeForStoredMarkers(pageURL, body string) {
	s.PostedMu.Lock()
	defer s.PostedMu.Unlock()
	for _, p := range s.Posted {
		if p.Marker == "" {
			continue
		}
		if strings.Contains(body, p.Marker) {
			s.addFinding(FindingXSS{
				Type:            "stored-reflection",
				URL:             pageURL,
				Payload:         p.Marker,
				ResponseSnippet: snippetAround(body, p.Marker, 120),
				PostedTo:        p.URL,
				PostedData:      p.Data,
			})
		}
	}
}

// dom check using chromedp
func (s *Scanner) domCheck(u string) {
	if !s.UseChrome || s.Chromectx == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.Chromectx, 20*time.Second)
	defer cancel()
	var html string
	err := chromedp.Run(ctx,
		chromedp.Navigate(u),
		chromedp.Sleep(1200*time.Millisecond),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	if err != nil {
		log.Printf("[chromedp] %v\n", err)
		return
	}
	// look for payload fragments
	payloads := s.PayloadsBasic
	if s.Intensity == "full" {
		payloads = s.PayloadsFull
	}
	for _, p := range payloads {
		if strings.Contains(html, p) {
			s.addFinding(FindingXSS{
				Type:            "dom-reflection",
				URL:             u,
				Context:         "chromedp",
				ResponseSnippet: snippetAround(html, p, 120),
			})
		}
	}
	// suspicious JS patterns
	re := regexp.MustCompile(`(document\.write|innerHTML|outerHTML|eval\(|setTimeout\(|setInterval\()`)
	m := re.FindString(html)
	if m != "" {
		s.addFinding(FindingXSS{
			Type:    "dom-suspicious-code",
			URL:     u,
			Context: m,
		})
	}
}

// worker
func (s *Scanner) worker(wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range s.Queue {
		atomic.AddInt32(&s.Active, 1)
		// page count guard
		s.PageCountMu.Lock()
		if s.PageCount >= s.MaxPages {
			s.PageCountMu.Unlock()
			atomic.AddInt32(&s.Active, -1)
			return
		}
		s.PageCountMu.Unlock()
		// ensure single visit
		if !s.markVisited(job.URL) {
			atomic.AddInt32(&s.Active, -1)
			continue
		}
		log.Printf("[crawl] %s (depth %d)\n", job.URL, job.Depth)
		headers := map[string]string{"Referer": s.StartURL.String()}
		_, body, ctype, err := s.fetch(job.URL, headers)
		if err != nil {
			log.Printf("[error] fetch %s: %v\n", job.URL, err)
			atomic.AddInt32(&s.Active, -1)
			continue
		}
		// analyze stored markers
		s.analyzeForStoredMarkers(job.URL, body)

		// quick raw payload detection (non-marked)
		for _, p := range append(s.PayloadsBasic, s.PayloadsFull...) {
			if strings.Contains(body, p) {
				s.addFinding(FindingXSS{
					Type:            "reflected-raw",
					URL:             job.URL,
					Context:         "raw",
					ResponseSnippet: snippetAround(body, p, 120),
				})
			}
		}

		// parse links and forms if HTML
		if strings.Contains(strings.ToLower(ctype), "text/html") && job.Depth < s.MaxDepth {
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
			if err == nil {
				// links
				doc.Find("a[href]").Each(func(i int, sel *goquery.Selection) {
					href, _ := sel.Attr("href")
					n, err := s.normalize(job.URL, href)
					if err == nil {
						s.enqueue(n, job.Depth+1)
					}
				})
				// scripts & iframes
				doc.Find("iframe[src],script[src]").Each(func(i int, sel *goquery.Selection) {
					src, _ := sel.Attr("src")
					n, err := s.normalize(job.URL, src)
					if err == nil {
						s.enqueue(n, job.Depth+1)
					}
				})
				// forms
				s.fuzzForms(job.URL, body)
			}
		}

		// fuzz URL params
		s.fuzzParams(job.URL)

		// optional DOM check
		if s.UseChrome && strings.Contains(strings.ToLower(ctype), "text/html") {
			s.domCheck(job.URL)
		}
		atomic.AddInt32(&s.Active, -1)
	}
}

// enqueue helper
func (s *Scanner) enqueue(u string, depth int) {
	u = strings.Split(u, "#")[0]
	s.VisitedMu.RLock()
	if s.Visited[u] {
		s.VisitedMu.RUnlock()
		return
	}
	s.VisitedMu.RUnlock()
	// guard page count
	s.PageCountMu.Lock()
	if s.PageCount >= s.MaxPages {
		s.PageCountMu.Unlock()
		return
	}
	s.PageCountMu.Unlock()
	select {
	case s.Queue <- crawlJob{URL: u, Depth: depth}:
	default:
		// queue full: drop politely
	}
}

// run scanning
func (s *Scanner) run() {
	var wg sync.WaitGroup
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go s.worker(&wg)
	}
	// seed
	s.enqueue(s.StartURL.String(), 0)

	// simple termination: wait until queue drained and workers idle
	// we'll poll and close queue when conditions met
	for {
		time.Sleep(500 * time.Millisecond)
		s.PageCountMu.Lock()
		done := s.PageCount >= s.MaxPages
		s.PageCountMu.Unlock()
		if done && len(s.Queue) == 0 && atomic.LoadInt32(&s.Active) == 0 {
			break
		}
		if len(s.Queue) == 0 && atomic.LoadInt32(&s.Active) == 0 {
			// no queued jobs — give workers a bit to finish
			time.Sleep(800 * time.Millisecond)
			if len(s.Queue) == 0 && atomic.LoadInt32(&s.Active) == 0 {
				break
			}
		}
	}
	close(s.Queue)
	wg.Wait()
	// shutdown chromedp
	if s.ChromeCancel != nil {
		s.ChromeCancel()
	}
}

// generate HTML report
func generateHTMLReport(out string, target string, findings []FindingXSS) error {
	const tpl = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>XSS Scan Report - {{.Target}}</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial;line-height:1.45;padding:18px;background:#fafafa;color:#111}
.container{max-width:1000px;margin:0 auto;background:#fff;padding:18px;border-radius:10px;box-shadow:0 6px 30px rgba(0,0,0,.08)}
h1{font-size:22px}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{padding:8px;border:1px solid #eee;text-align:left;font-size:13px}
code{background:#f4f4f4;padding:2px 6px;border-radius:4px}
.bad{color:#b83b3b;font-weight:600}
</style>
</head>
<body>
<div class="container">
<h1>XSS Scan Report</h1>
<p><strong>Target:</strong> {{.Target}}</p>
<p><strong>Generated:</strong> {{.Generated}}</p>
<p><strong>Findings:</strong> {{len .Findings}}</p>

{{if .Findings}}
<table>
<thead><tr><th>#</th><th>Type</th><th>URL</th><th>Context</th><th>Payload / Snippet</th><th>Time</th></tr></thead>
<tbody>
{{range $i, $f := .Findings}}
<tr>
<td>{{add $i 1}}</td>
<td>{{$f.Type}}</td>
<td><a href="{{$f.URL}}" target="_blank">{{$f.URL}}</a></td>
<td>{{$f.Context}}</td>
<td><pre style="white-space:pre-wrap;margin:0">{{if $f.Payload}}{{$f.Payload}}{{else}}{{$f.ResponseSnippet}}{{end}}</pre></td>
<td>{{$f.Timestamp}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>No findings recorded.</p>
{{end}}

<hr>
<p style="font-size:12px;color:#666">Report generated by xss_scanner_domain.go — only for authorized testing.</p>
</div>
</body>
</html>`

	funcMap := template.FuncMap{"add": func(a, b int) int { return a + b }}
	t, err := template.New("report").Funcs(funcMap).Parse(tpl)
	if err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	data := map[string]interface{}{
		"Target":    target,
		"Generated": time.Now().UTC().Format(time.RFC3339),
		"Findings":  findings,
	}
	return t.Execute(f, data)
}

// RunXSSScan is a wrapper to integrate with the TUI
func RunXSSScan(target string, headers map[string]string, cookies string, reportPath string) error {
	// intensity: basic | full | both
	intensity := "both"

	// chrome dom check disabled by default (TUI shouldn't force chrome)
	useChrome := false

	scanner, err := newScanner(target,
		10,                   // workers
		200,                  // max pages
		6,                    // max depth
		intensity,            // intensity
		useChrome,            // dom check
		300*time.Millisecond, // throttle
	)
	if err != nil {
		return err
	}

	// add headers + cookies
	extra := map[string]string{}
	for k, v := range headers {
		extra[k] = v
	}
	if cookies != "" {
		extra["Cookie"] = cookies
	}

	// start scan


	// wait
	scanner.run()

	// generate HTML report
	return generateHTMLReport(reportPath, target, scanner.Findings)
}
