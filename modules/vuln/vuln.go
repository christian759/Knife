package vuln

import (
	"fmt"
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

// RunAdvancedScan runs a customized vulnerability scan using the Coordinator
func RunAdvancedScan(config ScanConfig) (*ScanResult, error) {
	coordinator := NewScannerCoordinator(config)
	return coordinator.RunAllScans()
}

// RunAllVulnScanners remains for backward compatibility but uses the new logic
func RunAllVulnScanners(target string, headers map[string]string, cookies string) error {
	config := ScanConfig{
		Target:          target,
		Headers:         headers,
		Cookies:         cookies,
		Workers:         10,
		MaxPages:        50,
		MaxDepth:        2,
		Throttle:        200 * time.Millisecond,
		Intensity:       3,
		EnabledScanners: []ScannerType{
			ScannerXSS, ScannerCSRF, ScannerLFI, ScannerSSRF, 
			ScannerCommandInjection, ScannerRCE, ScannerDirectoryTraversal, 
			ScannerXXE, ScannerOpenRedirect, ScannerSQL, ScannerHeaders, ScannerFiles,
			ScannerNetwork,
		},
	}

	result, err := RunAdvancedScan(config)
	if err != nil {
		return err
	}

	// Write unified report
	err = WriteUnifiedReport(result.Findings, "", target)
	if err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}
