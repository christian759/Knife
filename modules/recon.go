package modules

import (
	"fmt"
	"knife/util"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gocolly/colly"
	"github.com/likexian/whois"
)

var socialsite = map[string]string{
	"facebook":  "https://web.facebook.com/",
	"twitter":   "https://x.com/",
	"github":    "https://github.com/",
	"tiktok":    "https://www.tiktok.com/@",
	"youtube":   "https://www.youtube/@",
	"instagram": "https://www.instagram/",
	"twitch":    "https://www.twitch.tv/",
	"medium":    "https://medium.com/@",
	"linkedin":  "https://www.linkedin.com/in/",
	"threads":   "https://www.threads.com/",
}

// searching for users in various web
func search_user(user string) {
	fmt.Println("Found: ")
	for name, site := range socialsite {
		trialsite := site + user
		_, err := http.Get(trialsite)
		if err != nil {
			panic(err)
		} else {
			fmt.Printf("%s: %s \n", name, trialsite)
		}
	}
}

// presently it only support google and duckduckgo
func dork_searching(word string, websites []string, strict bool, engine string) map[string]string {
	results := make(map[string]string)

	if websites == nil {
		for name, _ := range socialsite {
			websites = append(websites, name)
		}
	}

	for _, site := range websites {
		// Build the query
		var query string
		if strict {
			query = fmt.Sprintf("site:%s \"%s\"", site, word)
		} else {
			query = fmt.Sprintf("site:%s %s", site, word)
		}
		escapedQuery := url.QueryEscape(query)

		// Choose search engine
		var searchURL string
		if engine == "google" {
			searchURL = fmt.Sprintf("https://www.google.com/search?q=%s", escapedQuery)
		} else {
			searchURL = fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", escapedQuery)
		}

		// Create collector
		c := colly.NewCollector(
			colly.UserAgent("Mozilla/5.0"),
		)

		// Extract result links
		c.OnHTML("a", func(e *colly.HTMLElement) {
			href := e.Attr("href")

			if engine == "google" && strings.HasPrefix(href, "/url?q=") {
				cleaned := strings.Split(strings.TrimPrefix(href, "/url?q="), "&")[0]
				if strings.HasPrefix(cleaned, "http") {
					results[query] = cleaned
				}
			}

			if engine == "duck" && strings.Contains(e.Attr("class"), "result__a") {
				href := e.Attr("href")
				if strings.HasPrefix(href, "http") {
					results[query] = href
				}
			}
		})

		// Visit search URL
		err := c.Visit(searchURL)
		if err != nil {
			log.Println("Failed to fetch:", err)
			continue
		}
	}

	return results
}

// WHOIS RECON
func lookupWhois(website string) {
	result, _ := whois.Whois(website)
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
	)

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
		panic(err)
	}

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
