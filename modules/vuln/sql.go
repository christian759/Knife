package vuln

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type FindingSQL struct {
	Target          string            `json:"target"`
	StatusCode      int               `json:"status_code"`
	ServerHeader    string            `json:"server_header"`
	SecurityHeaders map[string]string `json:"security_headers"`
	Cookies         []CookieInfo      `json:"cookies"`
	TechMatches     []string          `json:"tech_matches"`
	TLSEnabled      bool              `json:"tls_enabled"`
	TLSVersion      string            `json:"tls_version"`
	ErrorBanners    []string          `json:"error_banners"`
	ReflectedInputs []string          `json:"reflected_inputs"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
	SameSite string `json:"same_site"`
}

var results []FindingSQL
var client = &http.Client{Timeout: 20 * time.Second}

var techPatterns = map[string]*regexp.Regexp{
	"WordPress":     regexp.MustCompile(`(?i)wp-content|wordpress`),
	"PHP":           regexp.MustCompile(`(?i)\.php|php/`),
	"ASP.NET":       regexp.MustCompile(`(?i)\.aspx|asp.net`),
	"Laravel":       regexp.MustCompile(`(?i)laravel|x-powered-by: laravel`),
	"Node.js":       regexp.MustCompile(`(?i)x-powered-by: express|node`),
	"React":         regexp.MustCompile(`(?i)react|data-reactroot`),
	"Angular":       regexp.MustCompile(`(?i)angular|ng-version`),
	"Django":        regexp.MustCompile(`(?i)csrfmiddlewaretoken|django`),
	"Ruby on Rails": regexp.MustCompile(`(?i)_rails_session|ror`),
}

var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax`),
	regexp.MustCompile(`(?i)PDOException`),
	regexp.MustCompile(`(?i)MySQL error`),
	regexp.MustCompile(`(?i)Warning: pg_`),
	regexp.MustCompile(`(?i)ODBC Driver`),
	regexp.MustCompile(`(?i)RuntimeException`),
	regexp.MustCompile(`(?i)Stack trace:`),
}

func getManualURLs() []string {
	fmt.Println("Enter URLs to analyze (one per line).")
	fmt.Println("Press ENTER on empty line to finish:")
	var urls []string
	sc := bufio.NewScanner(os.Stdin)
	for {
		sc.Scan()
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			break
		}
		urls = append(urls, line)
	}
	return urls
}

func analyzeURL(target string) FindingSQL {
	result := FindingSQL{Target: target}
	u, err := url.Parse(target)
	if err != nil {
		fmt.Println("❌ Invalid URL:", target)
		return result
	}

	if u.Scheme == "https" {
		result.TLSEnabled = true
		version := tlsCheck(u.Host)
		result.TLSVersion = version
	}

	resp, body, ok := fetch("GET", target, nil)
	if !ok {
		return result
	}

	result.StatusCode = resp.StatusCode
	result.ServerHeader = resp.Header.Get("Server")

	result.SecurityHeaders = extractSecurityHeaders(resp)
	result.Cookies = extractCookies(resp)

	result.TechMatches = detectTech(resp, body)
	result.ErrorBanners = detectErrors(body)
	result.ReflectedInputs = detectReflections(target, body)

	return result
}

func fetch(method, target string, form url.Values) (*http.Response, string, bool) {
	var req *http.Request
	var err error
	if form == nil {
		req, err = http.NewRequest(method, target, nil)
	} else {
		req, err = http.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if err != nil {
		fmt.Println("❌ Request error:", err)
		return nil, "", false
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("❌ HTTP error:", err)
		return nil, "", false
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	body := string(data)
	return resp, body, true
}

func tlsCheck(host string) string {
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{})
	if err != nil {
		return "Connection Failed"
	}
	defer conn.Close()

	switch conn.ConnectionState().Version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown / Deprecated"
	}
}

func extractSecurityHeaders(resp *http.Response) map[string]string {
	secHeaders := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	m := make(map[string]string)
	for _, h := range secHeaders {
		if v := resp.Header.Get(h); v != "" {
			m[h] = v
		} else {
			m[h] = "❌ Missing"
		}
	}
	return m
}

func sameSiteToString(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Unknown"
	}
}

func extractCookies(resp *http.Response) []CookieInfo {
	cookies := []CookieInfo{}
	for _, c := range resp.Cookies() {
		ci := CookieInfo{
			Name:     c.Name,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: sameSiteToString(c.SameSite),
		}
		cookies = append(cookies, ci)
	}
	return cookies
}

func detectTech(resp *http.Response, body string) []string {
	var matches []string

	for name, re := range techPatterns {
		// search in headers
		for k, v := range resp.Header {
			header := fmt.Sprintf("%s: %s", k, strings.Join(v, ","))
			if re.MatchString(header) {
				matches = append(matches, name)
			}
		}
		// search in body
		if re.MatchString(body) {
			matches = append(matches, name)
		}
	}
	return unique(matches)
}

func detectErrors(body string) []string {
	var banners []string
	for _, re := range errorPatterns {
		if re.MatchString(body) {
			// store a short preview instead of full line (safe)
			sub := re.FindString(body)
			banners = append(banners, sub)
		}
	}
	return unique(banners)
}

func detectReflections(target, body string) []string {
	u, _ := url.Parse(target)
	params := u.Query()
	var reflections []string
	for key := range params {
		if strings.Contains(body, params.Get(key)) {
			// parameter value returned in page => potential XSS surface
			reflections = append(reflections, key)
		}
	}
	return unique(reflections)
}

func unique(arr []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range arr {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
