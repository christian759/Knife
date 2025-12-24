package vuln

import (
	"fmt"
	"sync"
	"time"
)

// ScanConfig holds configuration for a vulnerability scan
type ScanConfig struct {
	Target          string
	Headers         map[string]string
	Cookies         string
	EnabledScanners []ScannerType
	Workers         int
	MaxPages        int
	MaxDepth        int
	Throttle        time.Duration
}

// ScanResult holds the results of a complete vulnerability scan
type ScanResult struct {
	Target         string
	Findings       []UnifiedFinding
	ScannerResults map[ScannerType]*ScanProgress
	StartTime      time.Time
	EndTime        time.Time
	Duration       time.Duration
}

// ScannerCoordinator orchestrates multiple vulnerability scanners
type ScannerCoordinator struct {
	config         ScanConfig
	findings       []UnifiedFinding
	findingsMu     sync.Mutex
	progressChan   chan ScanProgress
	scannerResults map[ScannerType]*ScanProgress
	resultsMu      sync.Mutex
}

// NewScannerCoordinator creates a new scanner coordinator
func NewScannerCoordinator(config ScanConfig) *ScannerCoordinator {
	return &ScannerCoordinator{
		config:         config,
		findings:       []UnifiedFinding{},
		progressChan:   make(chan ScanProgress, 100),
		scannerResults: make(map[ScannerType]*ScanProgress),
	}
}

// RunAllScans executes all enabled scanners and aggregates results
func (sc *ScannerCoordinator) RunAllScans() (*ScanResult, error) {
	startTime := time.Now()
	
	fmt.Printf("[+] Starting vulnerability scan on: %s\n", sc.config.Target)
	fmt.Printf("[+] Enabled scanners: %d\n", len(sc.config.EnabledScanners))
	
	// Run each scanner
	for _, scannerType := range sc.config.EnabledScanners {
		if err := sc.runScanner(scannerType); err != nil {
			fmt.Printf("[-] Scanner %s failed: %v\n", scannerType, err)
			sc.updateProgress(scannerType, "failed", 0, err)
		} else {
			sc.updateProgress(scannerType, "completed", 0, nil)
		}
	}
	
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	
	fmt.Printf("\n[+] Scan complete! Found %d vulnerabilities in %v\n", len(sc.findings), duration)
	
	return &ScanResult{
		Target:         sc.config.Target,
		Findings:       sc.findings,
		ScannerResults: sc.scannerResults,
		StartTime:      startTime,
		EndTime:        endTime,
		Duration:       duration,
	}, nil
}

// runScanner executes a specific scanner type
func (sc *ScannerCoordinator) runScanner(scannerType ScannerType) error {
	fmt.Printf("[*] Running %s scanner...\n", scannerType)
	sc.updateProgress(scannerType, "running", 0, nil)
	
	switch scannerType {
	case ScannerXSS:
		return sc.runXSSScanner()
	case ScannerCSRF:
		return sc.runCSRFScanner()
	case ScannerLFI:
		return sc.runLFIScanner()
	case ScannerSSRF:
		return sc.runSSRFScanner()
	case ScannerCommandInjection:
		return sc.runCommandInjectionScanner()
	case ScannerRCE:
		return sc.runRCEScanner()
	case ScannerDirectoryTraversal:
		return sc.runDirectoryTraversalScanner()
	case ScannerXXE:
		return sc.runXXEScanner()
	case ScannerOpenRedirect:
		return sc.runOpenRedirectScanner()
	default:
		return fmt.Errorf("unknown scanner type: %s", scannerType)
	}
}

// XSS Scanner
func (sc *ScannerCoordinator) runXSSScanner() error {
	scanner, err := newScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, 
		sc.config.MaxDepth, "normal", false, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertXSSFinding(f))
	}
	
	fmt.Printf("[✓] XSS Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// CSRF Scanner
func (sc *ScannerCoordinator) runCSRFScanner() error {
	scanner, err := NewCSRFScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertCSRFFinding(f))
	}
	
	fmt.Printf("[✓] CSRF Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// LFI Scanner
func (sc *ScannerCoordinator) runLFIScanner() error {
	scanner, err := NewLFIScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertLFIFinding(f))
	}
	
	fmt.Printf("[✓] LFI Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// SSRF Scanner
func (sc *ScannerCoordinator) runSSRFScanner() error {
	scanner, err := NewSSRFScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertSSRFFinding(f))
	}
	
	fmt.Printf("[✓] SSRF Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Command Injection Scanner
func (sc *ScannerCoordinator) runCommandInjectionScanner() error {
	scanner, err := NewCmdInjScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertCmdInjFinding(f))
	}
	
	fmt.Printf("[✓] Command Injection Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// RCE Scanner
func (sc *ScannerCoordinator) runRCEScanner() error {
	scanner, err := NewRCEScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertRCEFinding(f))
	}
	
	fmt.Printf("[✓] RCE Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Directory Traversal Scanner
func (sc *ScannerCoordinator) runDirectoryTraversalScanner() error {
	scanner, err := NewTraversalScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertTraversalFinding(f))
	}
	
	fmt.Printf("[✓] Directory Traversal Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// XXE Scanner
func (sc *ScannerCoordinator) runXXEScanner() error {
	scanner, err := NewXXEScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertXXEFinding(f))
	}
	
	fmt.Printf("[✓] XXE Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Open Redirect Scanner
func (sc *ScannerCoordinator) runOpenRedirectScanner() error {
	scanner, err := NewRedirectScanner(sc.config.Target, sc.config.Workers, 
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle)
	if err != nil {
		return err
	}
	
	scanner.Run()
	
	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertRedirectFinding(f))
	}
	
	fmt.Printf("[✓] Open Redirect Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Helper methods

func (sc *ScannerCoordinator) addFinding(f UnifiedFinding) {
	sc.findingsMu.Lock()
	defer sc.findingsMu.Unlock()
	sc.findings = append(sc.findings, f)
}

func (sc *ScannerCoordinator) updateProgress(scannerType ScannerType, status string, count int, err error) {
	sc.resultsMu.Lock()
	defer sc.resultsMu.Unlock()
	
	progress := &ScanProgress{
		ScannerName:   string(scannerType),
		Status:        status,
		FindingsCount: count,
		Error:         err,
	}
	
	sc.scannerResults[scannerType] = progress
	
	// Send to progress channel for TUI updates
	select {
	case sc.progressChan <- *progress:
	default:
	}
}

// GetFindings returns all findings found during the scan
func (sc *ScannerCoordinator) GetFindings() []UnifiedFinding {
	sc.findingsMu.Lock()
	defer sc.findingsMu.Unlock()
	return sc.findings
}

// GetProgressChannel returns the progress channel for TUI updates
func (sc *ScannerCoordinator) GetProgressChannel() <-chan ScanProgress {
	return sc.progressChan
}

// GetSummary returns a summary of findings by type and severity
func (sc *ScannerCoordinator) GetSummary() map[string]int {
	sc.findingsMu.Lock()
	defer sc.findingsMu.Unlock()
	
	summary := make(map[string]int)
	severityCounts := make(map[string]int)
	
	for _, f := range sc.findings {
		summary[f.Type]++
		severityCounts[f.Severity]++
	}
	
	// Add severity counts
	summary["Critical"] = severityCounts["Critical"]
	summary["High"] = severityCounts["High"]
	summary["Medium"] = severityCounts["Medium"]
	summary["Low"] = severityCounts["Low"]
	summary["Total"] = len(sc.findings)
	
	return summary
}
