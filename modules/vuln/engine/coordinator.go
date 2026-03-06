package engine

import (
	"fmt"
	"knife/modules/vuln/scanners"
	"strconv"
	"strings"
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

	// Advanced Options
	Intensity      int                 // 1-5, controls payload variety and depth
	CustomPayloads map[string][]string // ScannerType -> Payloads
	ScannerOptions map[string]string   // Arbitrary per-scanner options
	TargetedCVEs   []string            // List of CVE IDs to focus on
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
	defer close(sc.progressChan)

	fmt.Printf("[+] Starting vulnerability scan on: %s\n", sc.config.Target)
	fmt.Printf("[+] Enabled scanners: %d\n", len(sc.config.EnabledScanners))

	// Run each scanner
	for _, scannerType := range sc.config.EnabledScanners {
		if _, err := sc.runScanner(scannerType); err != nil {
			fmt.Printf("[-] Scanner %s failed: %v\n", scannerType, err)
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
func (sc *ScannerCoordinator) runScanner(scannerType ScannerType) (int, error) {
	fmt.Printf("[*] Running %s scanner...\n", scannerType)
	sc.updateProgress(scannerType, "running", 0, nil)
	before := sc.findingCount()

	var err error

	switch scannerType {
	case ScannerXSS:
		err = sc.runXSSScanner()
	case ScannerCSRF:
		err = sc.runCSRFScanner()
	case ScannerLFI:
		err = sc.runLFIScanner()
	case ScannerSSRF:
		err = sc.runSSRFScanner()
	case ScannerCommandInjection:
		err = sc.runCommandInjectionScanner()
	case ScannerRCE:
		err = sc.runRCEScanner()
	case ScannerDirectoryTraversal:
		err = sc.runDirectoryTraversalScanner()
	case ScannerXXE:
		err = sc.runXXEScanner()
	case ScannerOpenRedirect:
		err = sc.runOpenRedirectScanner()
	case ScannerSQL:
		err = sc.runSQLScanner()
	case ScannerHeaders:
		err = sc.runHeadersScanner()
	case ScannerFiles:
		err = sc.runFilesScanner()
	case ScannerNetwork:
		err = sc.runNetworkScanner()
	default:
		err = fmt.Errorf("unknown scanner type: %s", scannerType)
	}

	found := sc.findingCount() - before
	if found < 0 {
		found = 0
	}
	if err != nil {
		sc.updateProgress(scannerType, "failed", found, err)
		return found, err
	}
	sc.updateProgress(scannerType, "completed", found, nil)
	return found, nil
}

// SQL Scanner
func (sc *ScannerCoordinator) runSQLScanner() error {
	intensity := sc.modeIntensity(ScannerSQL)
	scanner, err := scanners.NewSQLScanner(sc.config.Target, sc.config.Workers,
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle,
		intensity, sc.mergePayloads(ScannerSQL, "sql"))
	if err != nil {
		return err
	}

	scanner.Run()

	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertSQLFinding(f))
	}

	fmt.Printf("[✓] SQL Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Headers Scanner
func (sc *ScannerCoordinator) runHeadersScanner() error {
	scanner := scanners.NewHeadersScanner(sc.config.Target)
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertHeaderFinding(f))
	}
	fmt.Printf("[✓] Headers Scanner: Found %d issues\n", len(scanner.Findings))
	return nil
}

// Files Scanner
func (sc *ScannerCoordinator) runFilesScanner() error {
	scanner := scanners.NewFilesScanner(sc.config.Target)
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertFileFinding(f))
	}
	fmt.Printf("[✓] Files Scanner: Found %d discoveries\n", len(scanner.Findings))
	return nil
}

// Network Scanner
func (sc *ScannerCoordinator) runNetworkScanner() error {
	opts := scanners.NetworkScanOptions{
		Profile: sc.scannerOption("network_profile", "infrastructure"),
	}
	mode := sc.scannerMode(ScannerNetwork)
	if mode == "aggressive" || mode == "deep" {
		opts.DeepScan = true
	}

	if deepRaw := strings.TrimSpace(sc.scannerOption("network_deep_scan", "")); deepRaw != "" {
		switch strings.ToLower(deepRaw) {
		case "1", "true", "yes", "on":
			opts.DeepScan = true
		}
	}

	if workersRaw := strings.TrimSpace(sc.scannerOption("network_workers", "")); workersRaw != "" {
		if workers, err := strconv.Atoi(workersRaw); err == nil && workers > 0 {
			opts.Workers = workers
		}
	}

	if timeoutRaw := strings.TrimSpace(sc.scannerOption("network_timeout_ms", "")); timeoutRaw != "" {
		if ms, err := strconv.Atoi(timeoutRaw); err == nil && ms > 0 {
			opts.Timeout = time.Duration(ms) * time.Millisecond
		}
	}

	if portsRaw := strings.TrimSpace(sc.scannerOption("network_ports", "")); portsRaw != "" {
		ports, err := scanners.ParseNetworkPorts(portsRaw)
		if err != nil {
			return fmt.Errorf("invalid network_ports value: %w", err)
		}
		opts.Ports = ports
	}

	scanner := scanners.NewNetworkScannerWithOptions(sc.config.Target, sc.config.Workers, sc.modeIntensity(ScannerNetwork), opts)
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertNetworkFinding(f, sc.config.Target))
	}
	fmt.Printf("[✓] Network Scanner (%s/%s): Found %d open ports/services\n", opts.Profile, mode, len(scanner.Findings))
	return nil
}

func (sc *ScannerCoordinator) scannerOption(key, defaultVal string) string {
	if sc.config.ScannerOptions == nil {
		return defaultVal
	}
	val, ok := sc.config.ScannerOptions[key]
	if !ok || strings.TrimSpace(val) == "" {
		return defaultVal
	}
	return val
}

func (sc *ScannerCoordinator) scannerMode(scannerType ScannerType) string {
	return strings.ToLower(strings.TrimSpace(sc.scannerOption("mode_"+string(scannerType), "balanced")))
}

func (sc *ScannerCoordinator) modeIntensity(scannerType ScannerType) int {
	intensity := sc.config.Intensity
	switch sc.scannerMode(scannerType) {
	case "stealth":
		intensity--
	case "aggressive":
		intensity++
	case "deep":
		intensity += 2
	}
	if intensity < 1 {
		intensity = 1
	}
	if intensity > 5 {
		intensity = 5
	}
	return intensity
}

func (sc *ScannerCoordinator) mergePayloads(scannerType ScannerType, legacyKey string) []string {
	var combined []string
	if sc.config.CustomPayloads != nil {
		if p := sc.config.CustomPayloads[string(scannerType)]; len(p) > 0 {
			combined = append(combined, p...)
		}
		if legacyKey != "" {
			if p := sc.config.CustomPayloads[legacyKey]; len(p) > 0 {
				combined = append(combined, p...)
			}
		}
	}

	mode := sc.scannerMode(scannerType)
	switch scannerType {
	case ScannerXSS:
		if mode == "aggressive" || mode == "deep" {
			combined = append(combined, "<svg><script>alert(1337)</script></svg>", "<img src=x onerror=confirm(document.domain)>")
		}
	case ScannerSQL:
		if mode == "aggressive" || mode == "deep" {
			combined = append(combined, "'||(SELECT pg_sleep(5))--", "' OR SLEEP(5)--")
		}
	case ScannerLFI:
		if mode == "aggressive" || mode == "deep" {
			combined = append(combined, "../../../../proc/self/environ", "../../../../etc/shadow")
		}
	case ScannerSSRF:
		if mode == "aggressive" || mode == "deep" {
			combined = append(combined, "http://127.0.0.1:2375/version", "http://169.254.169.254/metadata/instance?api-version=2021-02-01")
		}
	case ScannerCommandInjection, ScannerRCE:
		if mode == "aggressive" || mode == "deep" {
			combined = append(combined, ";cat /etc/passwd", "$(id)")
		}
	}

	if len(combined) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(combined))
	out := make([]string, 0, len(combined))
	for _, v := range combined {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// XSS Scanner
func (sc *ScannerCoordinator) runXSSScanner() error {
	intensity := sc.modeIntensity(ScannerXSS)
	scanner, err := scanners.NewScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages,
		sc.config.MaxDepth, intensity, false, sc.config.Throttle,
		sc.mergePayloads(ScannerXSS, "xss"))
	if err != nil {
		return err
	}

	scanner.Run()

	// Convert findings
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertXSSFinding(f))
	}

	fmt.Printf("[✓] XSS Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// CSRF Scanner
func (sc *ScannerCoordinator) runCSRFScanner() error {
	intensity := sc.modeIntensity(ScannerCSRF)
	scanner, err := scanners.NewCSRFScanner(sc.config.Target, sc.config.Workers,
		sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, intensity, sc.config.TargetedCVEs)
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
	scanner, err := scanners.NewLFIScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, sc.modeIntensity(ScannerLFI), sc.config.TargetedCVEs, sc.mergePayloads(ScannerLFI, "lfi"))
	if err != nil {
		return err
	}
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertLFIFinding(f))
	}
	fmt.Printf("[✓] LFI Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// SSRF Scanner
func (sc *ScannerCoordinator) runSSRFScanner() error {
	scanner, err := scanners.NewSSRFScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, sc.modeIntensity(ScannerSSRF), sc.config.TargetedCVEs, sc.mergePayloads(ScannerSSRF, "ssrf"))
	if err != nil {
		return err
	}
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertSSRFFinding(f))
	}
	fmt.Printf("[✓] SSRF Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Command Injection Scanner
func (sc *ScannerCoordinator) runCommandInjectionScanner() error {
	scanner, err := scanners.NewCmdInjScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, sc.modeIntensity(ScannerCommandInjection), sc.config.TargetedCVEs, sc.mergePayloads(ScannerCommandInjection, "command_injection"))
	if err != nil {
		return err
	}
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertCmdInjFinding(f))
	}
	fmt.Printf("[✓] Command Injection Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// RCE Scanner
func (sc *ScannerCoordinator) runRCEScanner() error {
	scanner, err := scanners.NewRCEScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, sc.modeIntensity(ScannerRCE), sc.config.TargetedCVEs, sc.mergePayloads(ScannerRCE, "rce"))
	if err != nil {
		return err
	}
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertRCEFinding(f))
	}
	fmt.Printf("[✓] RCE Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Directory Traversal Scanner
func (sc *ScannerCoordinator) runDirectoryTraversalScanner() error {
	scanner, err := scanners.NewTraversalScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, sc.modeIntensity(ScannerDirectoryTraversal), sc.config.TargetedCVEs, sc.mergePayloads(ScannerDirectoryTraversal, "directory_traversal"))
	if err != nil {
		return err
	}
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertTraversalFinding(f))
	}
	fmt.Printf("[✓] Directory Traversal Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// XXE Scanner
func (sc *ScannerCoordinator) runXXEScanner() error {
	scanner, err := scanners.NewXXEScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, sc.modeIntensity(ScannerXXE), sc.config.TargetedCVEs, sc.mergePayloads(ScannerXXE, "xxe"))
	if err != nil {
		return err
	}
	scanner.Run()
	for _, f := range scanner.Findings {
		sc.addFinding(ConvertXXEFinding(f))
	}
	fmt.Printf("[✓] XXE Scanner: Found %d vulnerabilities\n", len(scanner.Findings))
	return nil
}

// Open Redirect Scanner
func (sc *ScannerCoordinator) runOpenRedirectScanner() error {
	scanner, err := scanners.NewRedirectScanner(sc.config.Target, sc.config.Workers, sc.config.MaxPages, sc.config.MaxDepth, sc.config.Throttle, sc.modeIntensity(ScannerOpenRedirect), sc.config.TargetedCVEs, sc.mergePayloads(ScannerOpenRedirect, "open_redirect"))
	if err != nil {
		return err
	}
	scanner.Run()
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

func (sc *ScannerCoordinator) findingCount() int {
	sc.findingsMu.Lock()
	defer sc.findingsMu.Unlock()
	return len(sc.findings)
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
