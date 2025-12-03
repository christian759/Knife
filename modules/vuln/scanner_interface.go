package vuln

import "time"

// UnifiedFinding represents a vulnerability finding from any scanner
// This provides a common structure for reporting all vulnerability types
type UnifiedFinding struct {
	// Core fields
	Type      string    `json:"type"`       // e.g., "XSS", "CSRF", "SQL Injection"
	Name      string    `json:"name"`       // Detailed vulnerability name
	URL       string    `json:"url"`        // Affected URL
	Severity  string    `json:"severity"`   // Critical, High, Medium, Low
	Timestamp time.Time `json:"timestamp"`  // When the finding was discovered
	
	// Request details
	Method     string `json:"method,omitempty"`      // GET, POST, etc.
	Param      string `json:"param,omitempty"`       // Vulnerable parameter
	Payload    string `json:"payload,omitempty"`     // Payload that triggered the finding
	
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
	
	// Raw finding data (for detailed inspection)
	RawFinding interface{} `json:"-"` // Original scanner-specific finding
}

// ScanProgress represents the current state of a scanning operation
type ScanProgress struct {
	ScannerName    string
	Status         string // "running", "completed", "failed"
	FindingsCount  int
	PagesScanned   int
	Error          error
}

// ScannerType represents the type of vulnerability scanner
type ScannerType string

const (
	ScannerXSS               ScannerType = "xss"
	ScannerCSRF              ScannerType = "csrf"
	ScannerSQL               ScannerType = "sql"
	ScannerLFI               ScannerType = "lfi"
	ScannerSSRF              ScannerType = "ssrf"
	ScannerCommandInjection  ScannerType = "command_injection"
	ScannerRCE               ScannerType = "rce"
	ScannerDirectoryTraversal ScannerType = "directory_traversal"
	ScannerXXE               ScannerType = "xxe"
	ScannerOpenRedirect      ScannerType = "open_redirect"
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
	}
}

// ConvertXSSFinding converts FindingXSS to UnifiedFinding
func ConvertXSSFinding(f FindingXSS) UnifiedFinding {
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

// ConvertCSRFFinding converts FindingCSRF to UnifiedFinding
func ConvertCSRFFinding(f FindingCSRF) UnifiedFinding {
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

// ConvertLFIFinding converts FindingLFI to UnifiedFinding
func ConvertLFIFinding(f FindingLFI) UnifiedFinding {
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

// ConvertSSRFFinding converts FindingSSRF to UnifiedFinding
func ConvertSSRFFinding(f FindingSSRF) UnifiedFinding {
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

// ConvertCmdInjFinding converts FindingCmdInj to UnifiedFinding
func ConvertCmdInjFinding(f FindingCmdInj) UnifiedFinding {
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

// ConvertRCEFinding converts FindingRCE to UnifiedFinding
func ConvertRCEFinding(f FindingRCE) UnifiedFinding {
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

// ConvertTraversalFinding converts FindingTraversal to UnifiedFinding
func ConvertTraversalFinding(f FindingTraversal) UnifiedFinding {
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

// ConvertXXEFinding converts FindingXXE to UnifiedFinding
func ConvertXXEFinding(f FindingXXE) UnifiedFinding {
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

// ConvertRedirectFinding converts FindingRedirect to UnifiedFinding
func ConvertRedirectFinding(f FindingRedirect) UnifiedFinding {
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
