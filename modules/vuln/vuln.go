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
	{"XSS (Reflected)", "q", "<script>alert(1)</script>", `<script>alert\\(1\\)\u003c/script>`, "GET"},
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
var allUnifiedFindings []UnifiedFinding // Global to collect all findings

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

// RunAllVulnScanners runs ALL vulnerability scanners and collects findings
func RunAllVulnScanners(target string, headers map[string]string, cookies string) error {
	// Reset global findings
	allUnifiedFindings = []UnifiedFinding{}
	
	fmt.Println("[+] Starting comprehensive vulnerability scan")
	fmt.Println("[+] Target:", target)
	fmt.Println()
	
	// Standard config for all scanners
	workers := 10
	maxPages := 50
	maxDepth := 2
	throttle := 200 * time.Millisecond
	
	// 1. XSS Scanner
	fmt.Println("[*] Running XSS Scanner...")
	xssScanner, err := newScanner(target, workers, maxPages, maxDepth, "normal", false, throttle)
	if err == nil {
		xssScanner.run()
		for _, f := range xssScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertXSSFinding(f))
		}
		fmt.Printf("[✓] XSS Scanner complete: %d findings\n", len(xssScanner.Findings))
	} else {
		fmt.Printf("[!] XSS Scanner error: %v\n", err)
	}
	
	// 2. CSRF Scanner
	fmt.Println("[*] Running CSRF Scanner...")
	csrfScanner, err := NewCSRFScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		csrfScanner.Run()
		for _, f := range csrfScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertCSRFFinding(f))
		}
		fmt.Printf("[✓] CSRF Scanner complete: %d findings\n", len(csrfScanner.Findings))
	} else {
		fmt.Printf("[!] CSRF Scanner error: %v\n", err)
	}
	
	// 3. LFI Scanner
	fmt.Println("[*] Running LFI Scanner...")
	lfiScanner, err := NewLFIScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		lfiScanner.Run()
		for _, f := range lfiScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertLFIFinding(f))
		}
		fmt.Printf("[✓] LFI Scanner complete: %d findings\n", len(lfiScanner.Findings))
	} else {
		fmt.Printf("[!] LFI Scanner error: %v\n", err)
	}
	
	// 4. SSRF Scanner
	fmt.Println("[*] Running SSRF Scanner...")
	ssrfScanner, err := NewSSRFScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		ssrfScanner.Run()
		for _, f := range ssrfScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertSSRFFinding(f))
		}
		fmt.Printf("[✓] SSRF Scanner complete: %d findings\n", len(ssrfScanner.Findings))
	} else {
		fmt.Printf("[!] SSRF Scanner error: %v\n", err)
	}
	
	// 5. Command Injection Scanner
	fmt.Println("[*] Running Command Injection Scanner...")
	cmdInjScanner, err := NewCmdInjScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		cmdInjScanner.Run()
		for _, f := range cmdInjScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertCmdInjFinding(f))
		}
		fmt.Printf("[✓] Command Injection Scanner complete: %d findings\n", len(cmdInjScanner.Findings))
	} else {
		fmt.Printf("[!] Command Injection Scanner error: %v\n", err)
	}
	
	// 6. RCE Scanner
	fmt.Println("[*] Running RCE Scanner...")
	rceScanner, err := NewRCEScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		rceScanner.Run()
		for _, f := range rceScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertRCEFinding(f))
		}
		fmt.Printf("[✓] RCE Scanner complete: %d findings\n", len(rceScanner.Findings))
	} else {
		fmt.Printf("[!] RCE Scanner error: %v\n", err)
	}
	
	// 7. Directory Traversal Scanner
	fmt.Println("[*] Running Directory Traversal Scanner...")
	traversalScanner, err := NewTraversalScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		traversalScanner.Run()
		for _, f := range traversalScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertTraversalFinding(f))
		}
		fmt.Printf("[✓] Directory Traversal Scanner complete: %d findings\n", len(traversalScanner.Findings))
	} else {
		fmt.Printf("[!] Directory Traversal Scanner error: %v\n", err)
	}
	
	// 8. XXE Scanner
	fmt.Println("[*] Running XXE Scanner...")
	xxeScanner, err := NewXXEScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		xxeScanner.Run()
		for _, f := range xxeScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertXXEFinding(f))
		}
		fmt.Printf("[✓] XXE Scanner complete: %d findings\n", len(xxeScanner.Findings))
	} else {
		fmt.Printf("[!] XXE Scanner error: %v\n", err)
	}
	
	// 9. Open Redirect Scanner
	fmt.Println("[*] Running Open Redirect Scanner...")
	redirectScanner, err := NewRedirectScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		redirectScanner.Run()
		for _, f := range redirectScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertRedirectFinding(f))
		}
		fmt.Printf("[✓] Open Redirect Scanner complete: %d findings\n", len(redirectScanner.Findings))
	} else {
		fmt.Printf("[!] Open Redirect Scanner error: %v\n", err)
	}
	
	fmt.Println()
	fmt.Printf("[+] Scan complete! Total findings: %d\n", len(allUnifiedFindings))
	
	// Write unified report
	err = WriteUnifiedReport(allUnifiedFindings, "", target)
	if err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	
	return nil
}
