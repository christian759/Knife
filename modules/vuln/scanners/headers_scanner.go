package scanners

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FindingHeader describes a discovered security header issue
type FindingHeader struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Header    string `json:"header"`
	Status    string `json:"status"` // "Missing" or "Misconfigured"
	Evidence  string `json:"evidence"`
	Timestamp string `json:"timestamp"`
}

// HeadersScanner checks for security headers
type HeadersScanner struct {
	Target   string
	Client   *http.Client
	Findings []FindingHeader
	Subtype  string
}

// NewHeadersScanner creates a new headers scanner
func NewHeadersScanner(target string, subtype string) *HeadersScanner {
	return &HeadersScanner{
		Target:  target,
		Client:  &http.Client{Timeout: 10 * time.Second},
		Subtype: normalizeSubtype(subtype),
	}
}

// Run executes the headers scan
func (s *HeadersScanner) Run() {
	resp, err := s.Client.Get(s.Target)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	switch s.Subtype {
	case "transport_policy":
		s.checkHeader(resp, "Strict-Transport-Security", "Missing HSTS")
		s.checkHeader(resp, "Cross-Origin-Opener-Policy", "Missing COOP")
		s.checkHeader(resp, "Cross-Origin-Resource-Policy", "Missing CORP")
	case "legacy_headers":
		s.checkHeader(resp, "X-Frame-Options", "Missing XFO (Clickjacking risk)")
		s.checkHeader(resp, "X-Content-Type-Options", "Missing XCTO (MIME sniffing risk)")
	default: // browser_policy and fallback
		s.checkHeader(resp, "Content-Security-Policy", "Missing CSP")
		s.checkHeader(resp, "Strict-Transport-Security", "Missing HSTS")
		s.checkHeader(resp, "X-Frame-Options", "Missing XFO (Clickjacking risk)")
		s.checkHeader(resp, "X-Content-Type-Options", "Missing XCTO (MIME sniffing risk)")
		s.checkHeader(resp, "Referrer-Policy", "Missing Referrer-Policy")
		s.checkHeader(resp, "Permissions-Policy", "Missing Permissions-Policy")
		s.checkHeader(resp, "Cross-Origin-Opener-Policy", "Missing COOP")
		s.checkHeader(resp, "Cross-Origin-Resource-Policy", "Missing CORP")
	}

	if s.Subtype != "transport_policy" {
		s.checkHeaderPolicy(resp, "X-Content-Type-Options", []string{"nosniff"}, "Header should be set to nosniff")
		s.checkHeaderPolicy(resp, "X-Frame-Options", []string{"deny", "sameorigin"}, "Header should be DENY or SAMEORIGIN")
		s.checkHeaderPolicy(resp, "Referrer-Policy", []string{"strict-origin-when-cross-origin", "no-referrer", "same-origin"}, "Header should use a restrictive referrer policy")
		s.checkCSPPolicy(resp)
	}
	s.checkHSTS(resp)
	if s.Subtype != "legacy_headers" {
		s.checkCookieFlags(resp)
	}

	// Check for Server header (Information Disclosure)
	server := resp.Header.Get("Server")
	if server != "" {
		s.Findings = append(s.Findings, FindingHeader{
			Type:      "Information Disclosure",
			URL:       s.Target,
			Header:    "Server",
			Status:    "Present",
			Evidence:  fmt.Sprintf("Server header reveals version: %s", server),
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}
}

func (s *HeadersScanner) checkHeader(resp *http.Response, header, name string) {
	val := resp.Header.Get(header)
	if val == "" {
		s.Findings = append(s.Findings, FindingHeader{
			Type:      "Security Header Missing",
			URL:       s.Target,
			Header:    header,
			Status:    "Missing",
			Evidence:  fmt.Sprintf("%s is not set.", header),
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}
}

func (s *HeadersScanner) checkHeaderPolicy(resp *http.Response, header string, allowed []string, message string) {
	val := strings.ToLower(strings.TrimSpace(resp.Header.Get(header)))
	if val == "" {
		return
	}
	for _, a := range allowed {
		if strings.Contains(val, a) {
			return
		}
	}
	s.Findings = append(s.Findings, FindingHeader{
		Type:      "Security Header Misconfiguration",
		URL:       s.Target,
		Header:    header,
		Status:    "Misconfigured",
		Evidence:  fmt.Sprintf("%s. Current value: %s", message, resp.Header.Get(header)),
		Timestamp: time.Now().Format(time.RFC3339),
	})
}

func (s *HeadersScanner) checkCSPPolicy(resp *http.Response) {
	csp := strings.ToLower(resp.Header.Get("Content-Security-Policy"))
	if csp == "" {
		return
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "*") {
		s.Findings = append(s.Findings, FindingHeader{
			Type:      "Security Header Misconfiguration",
			URL:       s.Target,
			Header:    "Content-Security-Policy",
			Status:    "Misconfigured",
			Evidence:  "CSP contains weak directives (unsafe-inline/unsafe-eval/wildcard).",
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}
}

func (s *HeadersScanner) checkHSTS(resp *http.Response) {
	hsts := strings.ToLower(resp.Header.Get("Strict-Transport-Security"))
	if hsts == "" {
		return
	}
	if !strings.Contains(hsts, "max-age=") {
		s.Findings = append(s.Findings, FindingHeader{
			Type:      "Security Header Misconfiguration",
			URL:       s.Target,
			Header:    "Strict-Transport-Security",
			Status:    "Misconfigured",
			Evidence:  "HSTS missing max-age directive.",
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}
}

func (s *HeadersScanner) checkCookieFlags(resp *http.Response) {
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		lc := strings.ToLower(cookie)
		if !strings.Contains(lc, "secure") || !strings.Contains(lc, "httponly") || !strings.Contains(lc, "samesite") {
			s.Findings = append(s.Findings, FindingHeader{
				Type:      "Cookie Security Misconfiguration",
				URL:       s.Target,
				Header:    "Set-Cookie",
				Status:    "Misconfigured",
				Evidence:  fmt.Sprintf("Cookie missing one or more flags (Secure/HttpOnly/SameSite): %s", cookie),
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}
}

func (s *HeadersScanner) GetFindings() []FindingHeader {
	return s.Findings
}
