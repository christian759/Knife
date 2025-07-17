package recon

import (
	"fmt"
	"knife/util"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly"
	"github.com/likexian/whois"
)

// Search for a username across a list of sites provided by the user
func SearchUser(username string, sites []string) {
	fmt.Println("Searching for user:", username)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	found := make(chan string, len(sites))

	for _, site := range sites {
		wg.Add(1)
		go func(site string) {
			defer wg.Done()
			url := strings.TrimRight(site, "/") + "/" + username
			req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			resp, err := http.DefaultClient.Do(req)
			if err == nil && resp.StatusCode == 200 {
				found <- url
			}
			if resp != nil {
				resp.Body.Close()
			}
		}(site)
	}

	go func() {
		wg.Wait()
		close(found)
	}()

	for url := range found {
		fmt.Println("Found:", url)
	}
}

// Dork searching with concurrency and more flexible dork input
func DorkSearching(dork string, engine string, maxResults int) []string {
	results := []string{}
	c := colly.NewCollector(
		colly.UserAgent("Mozilla/5.0"),
		colly.Async(true),
	)
	c.Limit(&colly.LimitRule{Parallelism: 5})

	resultSet := make(map[string]struct{})
	mu := sync.Mutex{}

	c.OnHTML("a", func(e *colly.HTMLElement) {
		href := e.Attr("href")
		if strings.HasPrefix(href, "http") {
			mu.Lock()
			if len(resultSet) < maxResults {
				resultSet[href] = struct{}{}
			}
			mu.Unlock()
		}
	})

	var searchURL string
	escapedQuery := url.QueryEscape(dork)
	switch engine {
	case "google":
		searchURL = fmt.Sprintf("https://www.google.com/search?q=%s", escapedQuery)
	case "duckduck":
		searchURL = fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", escapedQuery)
	default:
		fmt.Println("Unsupported search engine.")
		return results
	}

	c.Visit(searchURL)
	c.Wait()

	for link := range resultSet {
		results = append(results, link)
	}
	return results
}

// WHOIS RECON
func LookupWhois(website string) {
	result, err := whois.Whois(website)
	if err != nil {
		fmt.Println("WHOIS lookup failed:", err)
		return
	}
	fmt.Println("WHOIS Lookup result:")
	fmt.Println(result)
}

// DNS RECON
type DNSRecord struct {
	A           []string
	AAAA        []string
	MX          []string
	NS          []string
	TXT         []string
	CNAME       string
	HasWildcard bool
}

func DNSRecon(domain string) {
	var result DNSRecord

	// A
	if ips, err := net.LookupHost(domain); err == nil {
		result.A = ips
	}

	// AAAA
	if ips, err := net.LookupIP(domain); err == nil {
		for _, ip := range ips {
			if ip.To4() == nil {
				result.AAAA = append(result.AAAA, ip.String())
			}
		}
	}

	// MX
	if mxRecords, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxRecords {
			result.MX = append(result.MX, fmt.Sprintf("%s (%d)", mx.Host, mx.Pref))
		}
	}

	// NS
	if ns, err := net.LookupNS(domain); err == nil {
		for _, n := range ns {
			result.NS = append(result.NS, n.Host)
		}
	}

	// TXT
	if txts, err := net.LookupTXT(domain); err == nil {
		result.TXT = txts
	}

	// CNAME
	if cname, err := net.LookupCNAME(domain); err == nil && !strings.EqualFold(cname, domain+".") {
		result.CNAME = cname
	}

	// Wildcard test (resolve a likely non-existent subdomain)
	wildTest := "unlikely-" + util.RandString(10) + "." + domain
	if wildcardIPs, err := net.LookupHost(wildTest); err == nil && len(wildcardIPs) > 0 {
		result.HasWildcard = true
	}

	fmt.Println("== DNS Records ==")
	fmt.Println("A:", result.A)
	fmt.Println("AAAA:", result.AAAA)
	fmt.Println("MX:", result.MX)
	fmt.Println("NS:", result.NS)
	fmt.Println("TXT:", result.TXT)
	fmt.Println("CNAME:", result.CNAME)
	fmt.Println("Wildcard DNS Detected:", result.HasWildcard)
}

// EMAIL HUNTER
func EmailHunter(domain string, maxDepth int, strict bool) {
	emailSet := make(map[string]struct{})

	c := colly.NewCollector(
		colly.MaxDepth(maxDepth),
		colly.AllowedDomains(domain, "www."+domain),
		colly.Async(true),
	)
	c.Limit(&colly.LimitRule{Parallelism: 10})

	// Regex for emails
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@` + regexp.QuoteMeta(domain))

	// On every HTML page
	c.OnHTML("body", func(e *colly.HTMLElement) {
		matches := emailRegex.FindAllString(e.Text, -1)
		for _, email := range matches {
			email = strings.ToLower(email)
			emailSet[email] = struct{}{}
		}
	})

	// On links (to follow internal pages)
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if strings.Contains(link, domain) {
			_ = c.Visit(link)
		}
	})

	c.OnError(func(r *colly.Response, err error) {
		fmt.Printf("Error: %s (%d)\n", r.Request.URL, r.StatusCode)
	})

	startURL := "https://" + domain
	err := c.Visit(startURL)
	if err != nil {
		fmt.Println("Crawl error:", err)
	}
	c.Wait()

	// Convert map to slice
	var emails []string
	for email := range emailSet {
		if !strict || strings.HasSuffix(email, "@"+domain) {
			emails = append(emails, email)
		}
	}

	fmt.Println("📬 Emails found:")
	for _, email := range emails {
		fmt.Println(" -", email)
	}
}

// PORT SCANNER (TCP/UDP, concurrent)
func PortScanner(target string, ports []int, timeout time.Duration, udp bool) {
	results := make(map[string]string)
	portsChan := make(chan int, 100)
	resultsChan := make(chan struct {
		Port   int
		Banner string
	}, 100)

	worker := func() {
		for port := range portsChan {
			var address string
			if strings.Contains(target, ":") && !strings.HasPrefix(target, "[") {
				address = fmt.Sprintf("[%s]:%d", target, port)
			} else {
				address = fmt.Sprintf("%s:%d", target, port)
			}
			if udp {
				conn, err := net.DialTimeout("udp", address, timeout)
				if err == nil {
					_ = conn.Close()
					resultsChan <- struct {
						Port   int
						Banner string
					}{port, "open (UDP)"}
				}
			} else {
				conn, err := net.DialTimeout("tcp", address, timeout)
				if err == nil {
					_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					buff := make([]byte, 1024)
					n, _ := conn.Read(buff)
					banner := strings.TrimSpace(string(buff[:n]))
					if banner == "" {
						banner = "open"
					}
					_ = conn.Close()
					resultsChan <- struct {
						Port   int
						Banner string
					}{port, banner}
				}
			}
		}
	}

	// Start workers
	for i := 0; i < 100; i++ {
		go worker()
	}

	// Feed ports
	go func() {
		for _, port := range ports {
			portsChan <- port
		}
		close(portsChan)
	}()

	// Collect results
	for range ports {
		select {
		case r := <-resultsChan:
			proto := "tcp"
			if udp {
				proto = "udp"
			}
			results[fmt.Sprintf("%s/%d", proto, r.Port)] = r.Banner
		case <-time.After(timeout + 1*time.Second):
			// Skip timeout ports
		}
	}

	fmt.Println("✅ Results:")
	for port, banner := range results {
		fmt.Printf(" - %s: %s\n", port, banner)
	}
}

// HEADER ANALYZER
func HeaderAnalyzer(target string) {
	results := make(map[string]string)

	// Ensure scheme is there
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		results["error"] = "invalid request"
		print(results)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		results["error"] = "connection failed"
		print(results)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		key := strings.ToLower(k)
		// Only extract juicy headers
		switch key {
		case "server", "x-powered-by", "set-cookie", "content-type",
			"strict-transport-security", "content-security-policy",
			"x-frame-options", "x-xss-protection", "x-content-type-options":
			results[k] = strings.Join(v, "; ")
		}
	}

	results["Status"] = resp.Status

	fmt.Println("📡 Header Scan Results:")
	for k, v := range results {
		fmt.Printf(" - %s: %s\n", k, v)
	}

}
