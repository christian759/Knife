package engine

import (
	"fmt"
	"strings"
	"time"

	"knife/modules/vuln/db"
	"knife/modules/vuln/scanners"
)

// UnifiedFinding represents a vulnerability finding from any scanner
// This provides a common structure for reporting all vulnerability types
type UnifiedFinding struct {
	// Core fields
	Type      string    `json:"type"`      // e.g., "XSS", "CSRF", "SQL Injection"
	Name      string    `json:"name"`      // Detailed vulnerability name
	URL       string    `json:"url"`       // Affected URL
	Severity  string    `json:"severity"`  // Critical, High, Medium, Low
	Timestamp time.Time `json:"timestamp"` // When the finding was discovered

	// Request details
	Method  string `json:"method,omitempty"`  // GET, POST, etc.
	Param   string `json:"param,omitempty"`   // Vulnerable parameter
	Payload string `json:"payload,omitempty"` // Payload that triggered the finding

	// Response details
	StatusCode      int    `json:"status_code,omitempty"`
	Evidence        string `json:"evidence,omitempty"`         // Matched content or proof
	ResponseSnippet string `json:"response_snippet,omitempty"` // Truncated response

	// Additional context
	Context      string            `json:"context,omitempty"`       // Additional context (e.g., DOM, Headers)
	Location     string            `json:"location,omitempty"`      // For redirects
	FormAction   string            `json:"form_action,omitempty"`   // For CSRF
	MissingToken bool              `json:"missing_token,omitempty"` // For CSRF
	PostedData   map[string]string `json:"posted_data,omitempty"`   // For stored XSS
	CVE          string            `json:"cve,omitempty"`           // Linked CVE ID

	// Raw finding data (for detailed inspection)
	RawFinding interface{} `json:"-"` // Original scanner-specific finding
}

// ScanProgress represents the current state of a scanning operation
type ScanProgress struct {
	ScannerName   string
	Status        string // "running", "completed", "failed"
	FindingsCount int
	PagesScanned  int
	Error         error
}

// ScannerType is an alias for db.ScannerType
type ScannerType = db.ScannerType

const (
	ScannerXSS                = db.ScannerXSS
	ScannerCSRF               = db.ScannerCSRF
	ScannerSQL                = db.ScannerSQL
	ScannerLFI                = db.ScannerLFI
	ScannerSSRF               = db.ScannerSSRF
	ScannerCommandInjection   = db.ScannerCommandInjection
	ScannerRCE                = db.ScannerRCE
	ScannerDirectoryTraversal = db.ScannerDirectoryTraversal
	ScannerXXE                = db.ScannerXXE
	ScannerOpenRedirect       = db.ScannerOpenRedirect
	ScannerHeaders            = db.ScannerHeaders
	ScannerFiles              = db.ScannerFiles
	ScannerNetwork            = db.ScannerNetwork
)

// ScannerInfo provides metadata about a scanner
type ScannerInfo struct {
	Type        ScannerType
	Name        string
	Description string
	Severity    string // Default severity level for this scanner type
}

// GetScannerInfo returns information about all available scanners
func GetScannerInfo() []ScannerInfo {
	return []ScannerInfo{
		{
			Type:        ScannerXSS,
			Name:        "Cross-Site Scripting (XSS)",
			Description: "Detects reflected, stored, and DOM-based XSS vulnerabilities",
			Severity:    "High",
		},
		{
			Type:        ScannerCSRF,
			Name:        "Cross-Site Request Forgery (CSRF)",
			Description: "Identifies missing anti-CSRF tokens in forms",
			Severity:    "Medium",
		},
		{
			Type:        ScannerSQL,
			Name:        "SQL Injection",
			Description: "Detects SQL injection vulnerabilities via error-based and blind techniques",
			Severity:    "High",
		},
		{
			Type:        ScannerLFI,
			Name:        "Local File Inclusion (LFI)",
			Description: "Tests for file inclusion vulnerabilities and path traversal",
			Severity:    "High",
		},
		{
			Type:        ScannerSSRF,
			Name:        "Server-Side Request Forgery (SSRF)",
			Description: "Detects SSRF vulnerabilities that allow internal network access",
			Severity:    "High",
		},
		{
			Type:        ScannerCommandInjection,
			Name:        "Command Injection",
			Description: "Identifies OS command injection vulnerabilities",
			Severity:    "Critical",
		},
		{
			Type:        ScannerRCE,
			Name:        "Remote Code Execution (RCE)",
			Description: "Detects remote code execution vulnerabilities",
			Severity:    "Critical",
		},
		{
			Type:        ScannerDirectoryTraversal,
			Name:        "Directory Traversal",
			Description: "Tests for directory traversal and path manipulation vulnerabilities",
			Severity:    "High",
		},
		{
			Type:        ScannerXXE,
			Name:        "XML External Entity (XXE)",
			Description: "Detects XXE injection vulnerabilities in XML parsers",
			Severity:    "High",
		},
		{
			Type:        ScannerOpenRedirect,
			Name:        "Open Redirect",
			Description: "Identifies unvalidated redirect vulnerabilities",
			Severity:    "Medium",
		},
		{
			Type:        ScannerHeaders,
			Name:        "Security Headers",
			Description: "Checks for missing or misconfigured HTTP security headers",
			Severity:    "Low",
		},
		{
			Type:        ScannerFiles,
			Name:        "Sensitive Files",
			Description: "Discovers exposed sensitive files and directories",
			Severity:    "High",
		},
		{
			Type:        ScannerNetwork,
			Name:        "Network Exposure & Privilege Escalation",
			Description: "Finds exposed web/network services and likely privilege-escalation paths",
			Severity:    "High",
		},
	}
}

// ConvertXSSFinding converts scanners.FindingXSS to UnifiedFinding
func ConvertXSSFinding(f scanners.FindingXSS) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "XSS",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "High",
		Timestamp:       timestamp,
		Payload:         f.Payload,
		Evidence:        f.Context, // Use Context as evidence
		Context:         f.Context,
		ResponseSnippet: f.ResponseSnippet,
		PostedData:      f.PostedData,
		RawFinding:      f,
	}
}

// ConvertCSRFFinding converts scanners.FindingCSRF to UnifiedFinding
func ConvertCSRFFinding(f scanners.FindingCSRF) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:         "CSRF",
		Name:         f.Type,
		URL:          f.URL,
		Severity:     "Medium",
		Timestamp:    timestamp,
		FormAction:   f.FormAction,
		Method:       f.FormMethod,
		MissingToken: f.MissingToken,
		Evidence:     f.Evidence,
		RawFinding:   f,
	}
}

// ConvertLFIFinding converts scanners.FindingLFI to UnifiedFinding
func ConvertLFIFinding(f scanners.FindingLFI) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "LFI",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "High",
		Timestamp:       timestamp,
		Param:           f.Param,
		Payload:         f.Payload,
		Evidence:        f.Evidence,
		ResponseSnippet: f.ResponseSnippet,
		RawFinding:      f,
	}
}

// ConvertSSRFFinding converts scanners.FindingSSRF to UnifiedFinding
func ConvertSSRFFinding(f scanners.FindingSSRF) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "SSRF",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "High",
		Timestamp:       timestamp,
		Param:           f.Param,
		Payload:         f.Payload,
		Evidence:        f.Evidence,
		ResponseSnippet: f.ResponseSnippet,
		RawFinding:      f,
	}
}

// ConvertCmdInjFinding converts scanners.FindingCmdInj to UnifiedFinding
func ConvertCmdInjFinding(f scanners.FindingCmdInj) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "Command Injection",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "Critical",
		Timestamp:       timestamp,
		Param:           f.Param,
		Payload:         f.Payload,
		Evidence:        f.Evidence,
		ResponseSnippet: f.ResponseSnippet,
		RawFinding:      f,
	}
}

// ConvertRCEFinding converts scanners.FindingRCE to UnifiedFinding
func ConvertRCEFinding(f scanners.FindingRCE) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "RCE",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "Critical",
		Timestamp:       timestamp,
		Param:           f.Param,
		Payload:         f.Payload,
		Evidence:        f.Evidence,
		ResponseSnippet: f.ResponseSnippet,
		RawFinding:      f,
	}
}

// ConvertTraversalFinding converts scanners.FindingTraversal to UnifiedFinding
func ConvertTraversalFinding(f scanners.FindingTraversal) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "Directory Traversal",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "High",
		Timestamp:       timestamp,
		Param:           f.Param,
		Payload:         f.Payload,
		Evidence:        f.Evidence,
		ResponseSnippet: f.ResponseSnippet,
		RawFinding:      f,
	}
}

// ConvertXXEFinding converts scanners.FindingXXE to UnifiedFinding
func ConvertXXEFinding(f scanners.FindingXXE) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "XXE",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "High",
		Timestamp:       timestamp,
		Param:           f.Param,
		Payload:         f.Payload,
		Evidence:        f.Evidence,
		ResponseSnippet: f.ResponseSnippet,
		RawFinding:      f,
	}
}

// ConvertSQLFinding converts scanners.FindingSQL to UnifiedFinding
func ConvertSQLFinding(f scanners.FindingSQL) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:            "SQL Injection",
		Name:            f.Type,
		URL:             f.URL,
		Severity:        "High",
		Timestamp:       timestamp,
		Param:           f.Param,
		Payload:         f.Payload,
		Evidence:        f.Evidence,
		ResponseSnippet: f.ResponseSnippet,
		RawFinding:      f,
	}
}

// ConvertHeaderFinding converts scanners.FindingHeader to UnifiedFinding
func ConvertHeaderFinding(f scanners.FindingHeader) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:       "Security Header",
		Name:       f.Type,
		URL:        f.URL,
		Severity:   "Low",
		Timestamp:  timestamp,
		Evidence:   f.Evidence,
		RawFinding: f,
	}
}

// ConvertFileFinding converts scanners.FindingFile to UnifiedFinding
func ConvertFileFinding(f scanners.FindingFile) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	evidence := f.Evidence
	if f.Confidence != "" {
		evidence = fmt.Sprintf("confidence=%s | %s", f.Confidence, evidence)
	}
	return UnifiedFinding{
		Type:       "Sensitive File",
		Name:       f.Type,
		URL:        f.URL,
		Severity:   "High",
		Timestamp:  timestamp,
		StatusCode: f.StatusCode,
		Evidence:   evidence,
		RawFinding: f,
	}
}

// ConvertRedirectFinding converts scanners.FindingRedirect to UnifiedFinding
func ConvertRedirectFinding(f scanners.FindingRedirect) UnifiedFinding {
	timestamp, _ := time.Parse(time.RFC3339, f.Timestamp)
	return UnifiedFinding{
		Type:       "Open Redirect",
		Name:       f.Type,
		URL:        f.URL,
		Severity:   "Medium",
		Timestamp:  timestamp,
		Param:      f.Param,
		Payload:    f.Payload,
		Location:   f.RedirectLocation,
		RawFinding: f,
	}
}

// ConvertNetworkFinding converts NetworkFinding to UnifiedFinding
func ConvertNetworkFinding(f scanners.NetworkFinding, target string) UnifiedFinding {
	url := target
	if f.Endpoint != "" {
		url = f.Endpoint
	}
	evidence := fmt.Sprintf("status=%s protocol=%s", f.State, f.Protocol)
	if f.Banner != "" {
		evidence += fmt.Sprintf(" banner=%s", f.Banner)
	}
	if f.Risk != "" {
		evidence += fmt.Sprintf(" risk=%s", f.Risk)
	}
	if f.Recommendation != "" {
		evidence += fmt.Sprintf(" recommendation=%s", f.Recommendation)
	}
	if f.PrivEscPath {
		evidence += " priv_esc_path=true"
	}
	if f.Category != "" {
		evidence += fmt.Sprintf(" category=%s", f.Category)
	}

	severity := "Medium"
	switch {
	case strings.Contains(strings.ToLower(f.Risk), "critical"):
		severity = "Critical"
	case strings.Contains(strings.ToLower(f.Risk), "high"):
		severity = "High"
	case strings.Contains(strings.ToLower(f.Risk), "low"):
		severity = "Low"
	}

	name := fmt.Sprintf("Open Port: %d (%s)", f.Port, f.Service)
	if f.PrivEscPath {
		name = fmt.Sprintf("Priv-Esc Path: %d (%s)", f.Port, f.Service)
	}

	return UnifiedFinding{
		Type:       "Network Service",
		Name:       name,
		URL:        url,
		Severity:   severity,
		Timestamp:  time.Now(),
		Evidence:   evidence,
		RawFinding: f,
	}
}
