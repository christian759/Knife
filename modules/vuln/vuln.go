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

// --- types ---
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
}

type FindingC struct {
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

var findings []FindingC

// ScanURL runs the checks and automatically writes an HTML report at the end.
// pass reportFilename as desired (e.g. "report.html"); if empty, a timestamped filename will be generated.
func ScanURL(target string, extraHeaders map[string]string, cookies string, reportFilename string) error {
	// reset findings for each run
	findings = []FindingC{}

	// clients
	defaultClient := &http.Client{Timeout: 15 * time.Second}
	noRedirectClient := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Println("[+] Starting scan:", target)
	found := false

	for _, check := range vulns {
		u, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}

		var req *http.Request
		var testURL string

		if check.Method == "POST" {
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

		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}

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

		headerStr := ""
		for k, v := range resp.Header {
			headerStr += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ","))
		}

		// Open redirect special case
		if check.Name == "Open Redirect" {
			loc := resp.Header.Get("Location")
			if loc != "" {
				lowerLoc := strings.ToLower(strings.TrimSpace(loc))
				if strings.HasPrefix(lowerLoc, "//evil.com") ||
					strings.Contains(lowerLoc, "://evil.com") ||
					strings.Contains(lowerLoc, "evil.com") {
					fmt.Printf("[!] Potential %-30s | Param: %-10s | Method: %-4s | Status: %d | URL: %s | Location: %s\n",
						check.Name, check.Param, check.Method, resp.StatusCode, testURL, loc)
					f := FindingC{
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
		}

		pat := check.Match
		if pat == "" {
			pat = "(?i)"
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
			ev := ""
			if bodyMatched {
				ev = findRegexSnippet(re, bodyStr, 200)
			} else {
				ev = findRegexSnippet(re, headerStr, 200)
			}

			fmt.Printf("[!] Potential %-30s | Param: %-10s | Method: %-4s | Status: %d | URL: %s\n",
				check.Name, check.Param, check.Method, resp.StatusCode, testURL)

			f := FindingC{
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
				Notes:         "",
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

	// Write report automatically
	if err := WriteReport(reportFilename); err != nil {
		return fmt.Errorf("scan finished but failed to write report: %w", err)
	}

	return nil
}
