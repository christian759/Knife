package recon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly"
	"github.com/likexian/whois"
)

// 1. Username Enumeration: Returns all URLs where the username exists.
func SearchUser(ctx context.Context, username string, sites []string) ([]string, error) {
	var wg sync.WaitGroup
	found := make(chan string, len(sites))
	client := &http.Client{Timeout: 8 * time.Second}

	for _, site := range sites {
		wg.Add(1)
		go func(site string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				profileURL := strings.TrimRight(site, "/") + "/" + username
				req, err := http.NewRequestWithContext(ctx, "GET", profileURL, nil)
				if err != nil {
					return
				}
				resp, err := client.Do(req)
				if err == nil && resp.StatusCode == 200 {
					found <- profileURL
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		}(site)
	}

	go func() {
		wg.Wait()
		close(found)
	}()

	var results []string
	for url := range found {
		results = append(results, url)
	}
	sort.Strings(results)
	return results, nil
}

// 2. Dork Search: Returns a list of found URLs from Google or DuckDuckGo.
func DorkSearch(query, engine string, maxResults int) ([]string, error) {
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
	escaped := url.QueryEscape(query)
	switch strings.ToLower(engine) {
	case "google":
		searchURL = "https://www.google.com/search?q=" + escaped
	case "duckduckgo", "duckduck":
		searchURL = "https://html.duckduckgo.com/html/?q=" + escaped
	default:
		return nil, fmt.Errorf("unsupported search engine")
	}

	_ = c.Visit(searchURL)
	c.Wait()

	var results []string
	for link := range resultSet {
		results = append(results, link)
	}
	sort.Strings(results)
	return results, nil
}

// 3. WHOIS Lookup: Returns the raw WHOIS string.
func WhoisLookup(domain string) (string, error) {
	return whois.Whois(domain)
}

// 4. DNS Recon: Returns all major DNS records and wildcard detection.
type DNSReconResult struct {
	A           []string
	AAAA        []string
	MX          []string
	NS          []string
	TXT         []string
	CNAME       string
	HasWildcard bool
}

func DNSRecon(domain string) DNSReconResult {
	var res DNSReconResult

	if ips, _ := net.LookupHost(domain); len(ips) > 0 {
		res.A = ips
	}
	if ips, _ := net.LookupIP(domain); len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() == nil {
				res.AAAA = append(res.AAAA, ip.String())
			}
		}
	}
	if mxs, _ := net.LookupMX(domain); len(mxs) > 0 {
		for _, mx := range mxs {
			res.MX = append(res.MX, fmt.Sprintf("%s (%d)", mx.Host, mx.Pref))
		}
	}
	if nss, _ := net.LookupNS(domain); len(nss) > 0 {
		for _, ns := range nss {
			res.NS = append(res.NS, ns.Host)
		}
	}
	if txts, _ := net.LookupTXT(domain); len(txts) > 0 {
		res.TXT = txts
	}
	if cname, err := net.LookupCNAME(domain); err == nil && !strings.EqualFold(cname, domain+".") {
		res.CNAME = cname
	}
	// Wildcard detection
	wild := "wildcard-" + randomString(10) + "." + domain
	if ips, _ := net.LookupHost(wild); len(ips) > 0 {
		res.HasWildcard = true
	}
	return res
}

// 5. Email Hunter: Returns all emails found on the domain (optionally strict).
func EmailHunter(domain string, maxDepth int, strict bool) ([]string, error) {
	emailSet := make(map[string]struct{})
	c := colly.NewCollector(
		colly.MaxDepth(maxDepth),
		colly.AllowedDomains(domain, "www."+domain),
		colly.Async(true),
	)
	c.Limit(&colly.LimitRule{Parallelism: 10})

	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@` + regexp.QuoteMeta(domain))

	c.OnHTML("body", func(e *colly.HTMLElement) {
		matches := emailRegex.FindAllString(e.Text, -1)
		for _, email := range matches {
			emailSet[strings.ToLower(email)] = struct{}{}
		}
	})
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if strings.Contains(link, domain) {
			_ = c.Visit(link)
		}
	})

	startURL := "https://" + domain
	_ = c.Visit(startURL)
	c.Wait()

	var emails []string
	for email := range emailSet {
		if !strict || strings.HasSuffix(email, "@"+domain) {
			emails = append(emails, email)
		}
	}
	sort.Strings(emails)
	return emails, nil
}

// 6. Port Scanner: Returns open ports and banners (TCP or UDP).
type PortResult struct {
	Port   int
	Proto  string
	Banner string
}

func PortScan(target string, ports []int, timeout time.Duration, udp bool) []PortResult {
	var wg sync.WaitGroup
	results := make(chan PortResult, len(ports))

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			// Use net.JoinHostPort for proper IPv4/IPv6 formatting
			address := net.JoinHostPort(target, fmt.Sprintf("%d", port))
			if udp {
				conn, err := net.DialTimeout("udp", address, timeout)
				if err == nil {
					_ = conn.Close()
					results <- PortResult{Port: port, Proto: "udp", Banner: "open"}
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
					results <- PortResult{Port: port, Proto: "tcp", Banner: banner}
				}
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var out []PortResult
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// 7. Header Analyzer: Returns a map of interesting headers.
func HeaderAnalyze(target string) (map[string]string, error) {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	client := &http.Client{Timeout: 6 * time.Second}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := map[string]string{"Status": resp.Status}
	for k, v := range resp.Header {
		key := strings.ToLower(k)
		switch key {
		case "server", "x-powered-by", "set-cookie", "content-type",
			"strict-transport-security", "content-security-policy",
			"x-frame-options", "x-xss-protection", "x-content-type-options":
			headers[k] = strings.Join(v, "; ")
		}
	}
	return headers, nil
}

// --- Utility ---
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(time.Nanosecond) // ensure different seed
	}
	return string(b)
}
