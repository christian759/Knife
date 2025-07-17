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
	{"Open Redirect", "next", "//evil.com", `(?i)Location:\s*https?://evil\.com`, "GET"},
	{"Command Injection", "ip", "127.0.0.1; cat /etc/passwd", `root:x:0:0`, "GET"},
	{"SSRF", "url", "http://127.0.0.1:80", `Server|Apache|nginx|Bad Request`, "GET"},
	{"CSRF", "", "", `Set-Cookie`, "GET"},
	{"RCE (Basic)", "cmd", "echo knife", `knife`, "GET"},
	{"Directory Traversal", "path", "../../../../etc/passwd", `root:x:0:0`, "GET"},
	{"XXE", "xml", `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`, `root:x:0:0`, "POST"},
}

func ScanURL(target string, extraHeaders map[string]string, cookies string) {
	client := &http.Client{Timeout: 15 * time.Second}
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

		if check.Method == "POST" {
			data := url.Values{}
			if check.Param != "" {
				data.Set(check.Param, check.Payload)
			}
			req, err = http.NewRequest("POST", target, strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			testURL = target + " (POST param: " + check.Param + "=" + check.Payload + ")"
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

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[-] %s request failed: %v\n", check.Name, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := strings.ToLower(string(body))
		matchPattern := strings.ToLower(check.Match)
		headerStr := ""
		for k, v := range resp.Header {
			headerStr += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ","))
		}

		// Use regex for matching
		matched, _ := regexp.MatchString(matchPattern, bodyStr)
		headerMatched, _ := regexp.MatchString(matchPattern, strings.ToLower(headerStr))

		if matched || headerMatched {
			fmt.Printf("[!] Potential %-30s | Param: %-10s | Method: %-4s | Status: %d | URL: %s\n", check.Name, check.Param, check.Method, resp.StatusCode, testURL)
			found = true
		}
	}

	if !found {
		fmt.Println("[+] Scan complete. No obvious vulnerabilities detected.")
	} else {
		fmt.Println("[!] Scan complete. Review findings above.")
	}
}
