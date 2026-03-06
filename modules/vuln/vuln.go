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

// RunAllVulnScanners runs ALL vulnerability scanners and collects findings
func RunAllVulnScanners(target string, headers map[string]string, cookies string) error {
	// Reset global findings
	allUnifiedFindings = []UnifiedFinding{}

	fmt.Println("[+] Starting comprehensive vulnerability scan")
	fmt.Println("[+] Target:", target)
	fmt.Println()

	// Standard config for all scanners
	workers := 10
	maxPages := 50
	maxDepth := 2
	throttle := 200 * time.Millisecond

	// 1. XSS Scanner
	fmt.Println("[*] Running XSS Scanner...")
	xssScanner, err := newScanner(target, workers, maxPages, maxDepth, "normal", false, throttle)
	if err == nil {
		xssScanner.run()
		for _, f := range xssScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertXSSFinding(f))
		}
		fmt.Printf("[✓] XSS Scanner complete: %d findings\n", len(xssScanner.Findings))
	} else {
		fmt.Printf("[!] XSS Scanner error: %v\n", err)
	}

	// 2. CSRF Scanner
	fmt.Println("[*] Running CSRF Scanner...")
	csrfScanner, err := NewCSRFScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		csrfScanner.Run()
		for _, f := range csrfScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertCSRFFinding(f))
		}
		fmt.Printf("[✓] CSRF Scanner complete: %d findings\n", len(csrfScanner.Findings))
	} else {
		fmt.Printf("[!] CSRF Scanner error: %v\n", err)
	}

	// 3. LFI Scanner
	fmt.Println("[*] Running LFI Scanner...")
	lfiScanner, err := NewLFIScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		lfiScanner.Run()
		for _, f := range lfiScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertLFIFinding(f))
		}
		fmt.Printf("[✓] LFI Scanner complete: %d findings\n", len(lfiScanner.Findings))
	} else {
		fmt.Printf("[!] LFI Scanner error: %v\n", err)
	}

	// 4. SSRF Scanner
	fmt.Println("[*] Running SSRF Scanner...")
	ssrfScanner, err := NewSSRFScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		ssrfScanner.Run()
		for _, f := range ssrfScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertSSRFFinding(f))
		}
		fmt.Printf("[✓] SSRF Scanner complete: %d findings\n", len(ssrfScanner.Findings))
	} else {
		fmt.Printf("[!] SSRF Scanner error: %v\n", err)
	}

	// 5. Command Injection Scanner
	fmt.Println("[*] Running Command Injection Scanner...")
	cmdInjScanner, err := NewCmdInjScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		cmdInjScanner.Run()
		for _, f := range cmdInjScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertCmdInjFinding(f))
		}
		fmt.Printf("[✓] Command Injection Scanner complete: %d findings\n", len(cmdInjScanner.Findings))
	} else {
		fmt.Printf("[!] Command Injection Scanner error: %v\n", err)
	}

	// 6. RCE Scanner
	fmt.Println("[*] Running RCE Scanner...")
	rceScanner, err := NewRCEScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		rceScanner.Run()
		for _, f := range rceScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertRCEFinding(f))
		}
		fmt.Printf("[✓] RCE Scanner complete: %d findings\n", len(rceScanner.Findings))
	} else {
		fmt.Printf("[!] RCE Scanner error: %v\n", err)
	}

	// 7. Directory Traversal Scanner
	fmt.Println("[*] Running Directory Traversal Scanner...")
	traversalScanner, err := NewTraversalScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		traversalScanner.Run()
		for _, f := range traversalScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertTraversalFinding(f))
		}
		fmt.Printf("[✓] Directory Traversal Scanner complete: %d findings\n", len(traversalScanner.Findings))
	} else {
		fmt.Printf("[!] Directory Traversal Scanner error: %v\n", err)
	}

	// 8. XXE Scanner
	fmt.Println("[*] Running XXE Scanner...")
	xxeScanner, err := NewXXEScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		xxeScanner.Run()
		for _, f := range xxeScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertXXEFinding(f))
		}
		fmt.Printf("[✓] XXE Scanner complete: %d findings\n", len(xxeScanner.Findings))
	} else {
		fmt.Printf("[!] XXE Scanner error: %v\n", err)
	}

	// 9. Open Redirect Scanner
	fmt.Println("[*] Running Open Redirect Scanner...")
	redirectScanner, err := NewRedirectScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		redirectScanner.Run()
		for _, f := range redirectScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertRedirectFinding(f))
		}
		fmt.Printf("[✓] Open Redirect Scanner complete: %d findings\n", len(redirectScanner.Findings))
	} else {
		fmt.Printf("[!] Open Redirect Scanner error: %v\n", err)
	}

	// 10. SQL Scanner
	fmt.Println("[*] Running SQL Scanner...")
	sqlScanner, err := NewSQLScanner(target, workers, maxPages, maxDepth, throttle)
	if err == nil {
		sqlScanner.Run()
		for _, f := range sqlScanner.Findings {
			allUnifiedFindings = append(allUnifiedFindings, ConvertSQLFinding(f))
		}
		fmt.Printf("[✓] SQL Scanner complete: %d findings\n", len(sqlScanner.Findings))
	} else {
		fmt.Printf("[!] SQL Scanner error: %v\n", err)
	}

	// 11. Security Headers Scanner
	fmt.Println("[*] Running Headers Scanner...")
	headersScanner := NewHeadersScanner(target)
	headersScanner.Run()
	for _, f := range headersScanner.Findings {
		allUnifiedFindings = append(allUnifiedFindings, ConvertHeaderFinding(f))
	}
	fmt.Printf("[✓] Headers Scanner complete: %d findings\n", len(headersScanner.Findings))

	// 12. Sensitive Files Scanner
	fmt.Println("[*] Running Files Scanner...")
	filesScanner := NewFilesScanner(target)
	filesScanner.Run()
	for _, f := range filesScanner.Findings {
		allUnifiedFindings = append(allUnifiedFindings, ConvertFileFinding(f))
	}
	fmt.Printf("[✓] Files Scanner complete: %d findings\n", len(filesScanner.Findings))

	fmt.Println()
	fmt.Printf("[+] Scan complete! Total findings: %d\n", len(allUnifiedFindings))

	// Write unified report
	err = WriteUnifiedReport(allUnifiedFindings, "", target)
	if err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}
