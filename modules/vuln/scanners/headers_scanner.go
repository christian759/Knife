package vuln

import (
	"fmt"
	"net/http"
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
}

// NewHeadersScanner creates a new headers scanner
func NewHeadersScanner(target string) *HeadersScanner {
	return &HeadersScanner{
		Target: target,
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Run executes the headers scan
func (s *HeadersScanner) Run() {
	resp, err := s.Client.Get(s.Target)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	s.checkHeader(resp, "Content-Security-Policy", "Missing CSP")
	s.checkHeader(resp, "Strict-Transport-Security", "Missing HSTS")
	s.checkHeader(resp, "X-Frame-Options", "Missing XFO (Clickjacking risk)")
	s.checkHeader(resp, "X-Content-Type-Options", "Missing XCTO (MIME sniffing risk)")
	s.checkHeader(resp, "Referrer-Policy", "Missing Referrer-Policy")
	s.checkHeader(resp, "Permissions-Policy", "Missing Permissions-Policy")
	
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

func (s *HeadersScanner) GetFindings() []FindingHeader {
	return s.Findings
}
