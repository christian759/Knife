package vuln

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// --- helpers ---
func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func findRegexSnippet(re *regexp.Regexp, s string, maxLen int) string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return snippet(s, maxLen)
	}
	start := loc[0] - maxLen/2
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(s) {
		end = len(s)
	}
	sn := s[start:end]
	if start > 0 {
		sn = "…" + sn
	}
	if end < len(s) {
		sn = sn + "…"
	}
	return sn
}

// --- vulnerability details ---
type VulnInfo struct {
	Severity      string
	Description   string
	Fix           string
	Exploitation  string
	Investigation string
}

func vulnDetails(name string) VulnInfo {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "xss"):
		return VulnInfo{
			Severity:      "High",
			Description:   "Cross-Site Scripting (XSS) occurs when untrusted input is embedded into web pages without proper escaping or sanitization. It lets attackers execute arbitrary JavaScript in the victim’s browser.",
			Fix:           "Sanitize and encode user input before rendering. Use frameworks or template engines that auto-escape HTML.",
			Exploitation:  "An attacker can trick users into clicking a malicious link containing the injected script, stealing cookies, session tokens, or performing actions on their behalf.",
			Investigation: "Try different payloads like <script>alert(1)</script>, <img src=x onerror=alert(1)>, or use Burp Intruder to identify reflected parameters.",
		}

	case strings.Contains(n, "sql"):
		return VulnInfo{
			Severity:      "High",
			Description:   "SQL Injection happens when unsanitized input is directly inserted into SQL queries. Attackers can manipulate the query logic to read or modify database data.",
			Fix:           "Always use prepared statements or ORM libraries that safely bind parameters. Avoid concatenating input into queries.",
			Exploitation:  "Attackers could extract usernames, passwords, or entire tables using payloads like ' OR '1'='1 -- or UNION-based injections.",
			Investigation: "Test with payloads such as ' OR '1'='1, or ' UNION SELECT NULL,NULL -- to see if errors or unusual behavior occur. Tools like sqlmap can automate deeper analysis.",
		}

	case strings.Contains(n, "lfi"):
		return VulnInfo{
			Severity:      "High",
			Description:   "Local File Inclusion (LFI) allows an attacker to include local server files by manipulating file path parameters.",
			Fix:           "Use whitelisting for file paths, and never concatenate user input into filesystem calls.",
			Exploitation:  "An attacker could read sensitive files (like /etc/passwd) or access configuration secrets.",
			Investigation: "Try different traversal patterns like ../../../../etc/passwd or PHP wrappers like php://filter/convert.base64-encode/resource=index.php to test deeper inclusion possibilities.",
		}

	case strings.Contains(n, "redirect"):
		return VulnInfo{
			Severity:      "Medium",
			Description:   "Open Redirect vulnerabilities occur when user-controlled data determines a redirect location.",
			Fix:           "Restrict redirects to internal paths or use a predefined whitelist of safe URLs.",
			Exploitation:  "Attackers can use a trusted website’s redirect feature to lead victims to phishing or malware sites.",
			Investigation: "Modify redirect parameters manually (e.g., ?next=http://evil.com) and observe if the response Location header changes.",
		}

	case strings.Contains(n, "command"):
		return VulnInfo{
			Severity:      "Critical",
			Description:   "Command Injection allows attackers to execute system commands on the server by injecting shell operators into vulnerable inputs.",
			Fix:           "Never pass user input to system commands. Use parameterized APIs or strict whitelists.",
			Exploitation:  "Attackers could run arbitrary shell commands (e.g., cat /etc/passwd) to read or modify system data.",
			Investigation: "Inject symbols like ;, &&, |, or backticks (`) and monitor responses. Look for command outputs or delays in responses (indicating execution).",
		}

	case strings.Contains(n, "ssrf"):
		return VulnInfo{
			Severity:      "High",
			Description:   "Server-Side Request Forgery (SSRF) lets an attacker force the server to make HTTP requests to internal systems or external targets.",
			Fix:           "Block requests to private IP ranges and enforce URL allowlists. Disable redirects in server-to-server calls.",
			Exploitation:  "Attackers can probe internal services (e.g., 127.0.0.1, AWS metadata endpoints) to extract secrets.",
			Investigation: "Replace URLs with internal targets like http://127.0.0.1:80 or http://169.254.169.254/latest/meta-data and observe if the response leaks info.",
		}

	case strings.Contains(n, "csrf"):
		return VulnInfo{
			Severity:      "Medium",
			Description:   "Cross-Site Request Forgery (CSRF) tricks authenticated users into making unintended requests on trusted sites.",
			Fix:           "Use anti-CSRF tokens and same-site cookie attributes.",
			Exploitation:  "Attackers could craft malicious links that trigger state-changing actions like deleting an account or transferring funds.",
			Investigation: "Inspect HTML forms for hidden CSRF tokens. If missing, attempt to replay authenticated POST requests from external origins.",
		}

	case strings.Contains(n, "rce"):
		return VulnInfo{
			Severity:      "Critical",
			Description:   "Remote Code Execution (RCE) lets attackers execute arbitrary code on the server, leading to full compromise.",
			Fix:           "Never process user input through functions that execute code or shell commands. Apply strict input validation.",
			Exploitation:  "An attacker can inject payloads that directly execute OS commands, upload shells, or pivot into internal networks.",
			Investigation: "Use payloads like `echo hacked` or blind RCE detection with timing payloads (e.g., sleep 5) to see if response delays indicate execution.",
		}

	case strings.Contains(n, "xxe"):
		return VulnInfo{
			Severity:      "High",
			Description:   "XML External Entity (XXE) vulnerabilities occur when XML parsers process external entities, allowing file disclosure or SSRF attacks.",
			Fix:           "Disable external entity resolution in XML parsers. Avoid parsing untrusted XML input.",
			Exploitation:  "Attackers can read local files or make network requests from the server by embedding external entities.",
			Investigation: "Send XML payloads that reference local files (e.g., file:///etc/passwd) or remote servers to detect leaks in the parser response.",
		}

	default:
		return VulnInfo{
			Severity:      "Low",
			Description:   "A potential issue requiring manual review.",
			Fix:           "Review manually and verify with additional tools or fuzzing.",
			Exploitation:  "Unknown or low impact.",
			Investigation: "Manually inspect input/output behavior.",
		}
	}
}

func WriteReport(filename string) error {
	now := time.Now().Format("02 Jan 2006 15:04:05 MST")

	// Extract target folder from filename if possible
	target := "default"
	if strings.Contains(filename, "/") {
		parts := strings.Split(filename, "/")
		target = parts[len(parts)-2] // second to last segment if path given
	} else {
		// try to infer domain name from filename
		re := regexp.MustCompile(`[a-zA-Z0-9.-]+`)
		m := re.FindString(filename)
		if m != "" {
			target = m
		}
	}

	// Create per-target directory: ~/targetname/
	homeDir, _ := os.UserHomeDir()
	targetDir := filepath.Join(homeDir, target)
	os.MkdirAll(targetDir, 0755)

	// If filename is empty, generate a timestamped one
	if filename == "" {
		filename = fmt.Sprintf("_report_%d.html", time.Now().Unix())
	} else {
		// Strip any full paths; just keep the base name
		filename = fmt.Sprintf("_report_%d.html", time.Now().Unix())
	}

	fullPath := filepath.Join(targetDir, filename)

	f, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	fmt.Printf("[+] Report will be saved at: %s\n", fullPath)

	const tpl = `
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Detailed Vulnerability Report</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f8fc; color: #1a1d2e; }
			h1 { font-size: 1.8em; color: #222; }
			.card { background: #fff; border-radius: 12px; box-shadow: 0 3px 8px rgba(0,0,0,0.08); padding: 20px; margin-bottom: 25px; }
			h2 { margin-bottom: 8px; }
			.evidence { background: #eef1f6; border-radius: 6px; padding: 10px; font-family: monospace; white-space: pre-wrap; overflow-x: auto; }
			.severity-Critical { border-left: 6px solid #d63031; }
			.severity-High { border-left: 6px solid #e67e22; }
			.severity-Medium { border-left: 6px solid #f1c40f; }
			.severity-Low { border-left: 6px solid #3498db; }
			footer { text-align: center; margin-top: 40px; font-size: 0.85em; color: #666; }
		</style>
	</head>
	<body>
		<h1>Vulnerability Scan Report</h1>
		<p>Generated: {{ .GeneratedAt }}</p>
		<p>Total Findings: {{ len .Findings }}</p>
		<hr>

		{{ range $i, $f := .Findings }}
		{{ $info := vulnExplain $f.Name }}
		<div class="card severity-{{ $info.Severity }}">
		  <h2>{{ add $i 1 }}. {{ $f.Name }} ({{ $info.Severity }})</h2>
		  <p><strong>Target:</strong> <a href="{{ $f.TestURL }}">{{ $f.TestURL }}</a></p>
		  <p><strong>Parameter:</strong> {{ $f.Param }} | <strong>Method:</strong> {{ $f.Method }} | <strong>Status:</strong> {{ $f.StatusCode }}</p>
		  <p><strong>Payload:</strong> <code>{{ $f.Payload }}</code></p>

		  <h3>What This Means</h3>
		  <p>{{ $info.Description }}</p>

		  <h3>How Attackers Could Exploit It</h3>
		  <p>{{ $info.Exploitation }}</p>

		  <h3>How to Investigate Further</h3>
		  <p>{{ $info.Investigation }}</p>

		  <h3>How to Fix</h3>
		  <p>{{ $info.Fix }}</p>

		  {{ if $f.Evidence }}
		  <h3>Evidence</h3>
		  <div class="evidence">{{ $f.Evidence }}</div>
		  {{ end }}
		</div>
		{{ end }}

		<footer>
		  Generated by <strong>vulnscan</strong> — for ethical and educational use only.<br>
		  Learn. Investigate. Protect.
		</footer>
	</body>
</html>`

	funcMap := template.FuncMap{
		"add":         func(a, b int) int { return a + b },
		"vulnExplain": vulnDetails,
	}

	t := template.New("report").Funcs(funcMap)
	t, err = t.Parse(tpl)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}

	data := struct {
		GeneratedAt string
		Findings    []FindingC
	}{
		GeneratedAt: now,
		Findings:    findings,
	}

	if err := t.Execute(f, data); err != nil {
		return fmt.Errorf("template execution failed: %w", err)
	}

	fmt.Printf("[+] Deep educational report saved to: %s\n", filename)
	return nil
}

// WriteUnifiedReport generates a comprehensive HTML report from all scanner findings
func WriteUnifiedReport(findings []UnifiedFinding, filename string, target string) error {
	now := time.Now().Format("02 Jan 2006 15:04:05 MST")
	
	// Extract target name from URL or use fallback
	targetName := "scan"
	if target != "" {
		targetName = strings.ReplaceAll(strings.ReplaceAll(target, "http://", ""), "https://", "")
		targetName = strings.ReplaceAll(strings.ReplaceAll(targetName, "/", "_"), ":", "_")
	}
	
	// Create per-target directory: ~/targetname/
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine user home directory: %w", err)
	}
	targetDir := filepath.Join(homeDir, targetName)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory %s: %w", targetDir, err)
	}
	
	// If filename is empty, generate a timestamped one
	if filename == "" {
		filename = fmt.Sprintf("unified_report_%d.html", time.Now().Unix())
	} else {
		// Keep the user-provided base name but ensure it's safe
		filename = filepath.Base(filename)
	}
	
	fullPath := filepath.Join(targetDir, filename)
	
	f, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()
	
	fmt.Printf("[+] Report will be saved at: %s\n", fullPath)
	
	// Calculate summary statistics
	summary := calculateSummary(findings)
	
	const tpl = `
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<title>Comprehensive Vulnerability Scan Report</title>
		<style>
			* { margin: 0; padding: 0; box-sizing: border-box; }
			body { 
				font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
				background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
				padding: 20px;
				min-height: 100vh;
			}
			.container {
				max-width: 1200px;
				margin: 0 auto;
				background: #fff;
				border-radius: 16px;
				box-shadow: 0 20px 60px rgba(0,0,0,0.3);
				overflow: hidden;
			}
			.header {
				background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
				color: #fff;
				padding: 40px;
				text-align: center;
			}
			.header h1 { font-size: 2.5em; margin-bottom: 10px; }
			.header p { opacity: 0.9; font-size: 1.1em; }
			.summary {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
				gap: 20px;
				padding: 30px 40px;
				background: #f8f9fa;
				border-bottom: 3px solid #e9ecef;
			}
			.summary-card {
				background: #fff;
				padding: 20px;
				border-radius: 12px;
				box-shadow: 0 2px 8px rgba(0,0,0,0.1);
				text-align: center;
				transition: transform 0.2s;
			}
			.summary-card:hover { transform: translateY(-5px); }
			.summary-card h3 { font-size: 2em; margin-bottom: 5px; }
			.summary-card p { color: #666; font-size: 0.9em; }
			.critical { color: #d63031; border-left: 4px solid #d63031; }
			.high { color: #e67e22; border-left: 4px solid #e67e22; }
			.medium { color: #f1c40f; border-left: 4px solid #f1c40f; }
			.low { color: #3498db; border-left: 4px solid #3498db; }
			.findings {
				padding: 40px;
			}
			.finding-card {
				background: #fff;
				border-radius: 12px;
				padding: 25px;
				margin-bottom: 25px;
				border-left: 6px solid #ccc;
				box-shadow: 0 3px 10px rgba(0,0,0,0.08);
			}
			.finding-card.severity-Critical { border-left-color: #d63031; }
			.finding-card.severity-High { border-left-color: #e67e22; }
			.finding-card.severity-Medium { border-left-color: #f1c40f; }
			.finding-card.severity-Low { border-left-color: #3498db; }
			.finding-header {
				display: flex;
				justify-content: space-between;
				align-items: center;
				margin-bottom: 15px;
			}
			.finding-title { font-size: 1.5em; color: #2c3e50; }
			.severity-badge {
				padding: 6px 16px;
				border-radius: 20px;
				font-weight: bold;
				font-size: 0.9em;
				color: #fff;
			}
			.severity-badge.Critical { background: #d63031; }
			.severity-badge.High { background: #e67e22; }
			.severity-badge.Medium { background: #f1c40f; color: #333; }
			.severity-badge.Low { background: #3498db; }
			.finding-details { margin: 15px 0; }
			.detail-row {
				display: grid;
				grid-template-columns: 150px 1fr;
				padding: 8px 0;
				border-bottom: 1px solid #ecf0f1;
			}
			.detail-label { font-weight: bold; color: #7f8c8d; }
			.detail-value { color: #2c3e50; word-break: break-all; }
			.evidence {
				background: #eef1f6;
				border-radius: 8px;
				padding: 15px;
				font-family: 'Courier New', monospace;
				white-space: pre-wrap;
				overflow-x: auto;
				margin-top: 15px;
				font-size: 0.9em;
			}
			.section-title {
				font-size: 1.3em;
				color: #2c3e50;
				margin-bottom: 10px;
				padding-bottom: 10px;
				border-bottom: 2px solid #3498db;
			}
			footer {
				text-align: center;
				padding: 30px;
				background: #f8f9fa;
				color: #666;
				font-size: 0.9em;
			}
			.timestamp { color: #95a5a6; font-size: 0.85em; margin-top: 10px; }
		</style>
	</head>
	<body>
		<div class="container">
			<div class="header">
				<h1>🔐 Vulnerability Scan Report</h1>
				<p>Target: {{ .Target }}</p>
				<p>Generated: {{ .GeneratedAt }}</p>
			</div>
			
			<div class="summary">
				<div class="summary-card">
					<h3>{{ .Summary.Total }}</h3>
					<p>Total Findings</p>
				</div>
				<div class="summary-card critical">
					<h3>{{ .Summary.Critical }}</h3>
					<p>Critical</p>
				</div>
				<div class="summary-card high">
					<h3>{{ .Summary.High }}</h3>
					<p>High</p>
				</div>
				<div class="summary-card medium">
					<h3>{{ .Summary.Medium }}</h3>
					<p>Medium</p>
				</div>
				<div class="summary-card low">
					<h3>{{ .Summary.Low }}</h3>
					<p>Low</p>
				</div>
			</div>
			
			<div class="findings">
				{{ if .Findings }}
				{{ range $i, $f := .Findings }}
				{{ $info := vulnExplain $f.Type }}
				<div class="finding-card severity-{{ $f.Severity }}">
					<div class="finding-header">
						<div class="finding-title">{{ add $i 1 }}. {{ $f.Name }}</div>
						<span class="severity-badge {{ $f.Severity }}">{{ $f.Severity }}</span>
					</div>
					
					<div class="finding-details">
						<div class="detail-row">
							<div class="detail-label">Type:</div>
							<div class="detail-value">{{ $f.Type }}</div>
						</div>
						<div class="detail-row">
							<div class="detail-label">URL:</div>
							<div class="detail-value"><a href="{{ $f.URL }}">{{ $f.URL }}</a></div>
						</div>
						{{ if $f.Param }}
						<div class="detail-row">
							<div class="detail-label">Parameter:</div>
							<div class="detail-value">{{ $f.Param }}</div>
						</div>
						{{ end }}
						{{ if $f.Method }}
						<div class="detail-row">
							<div class="detail-label">Method:</div>
							<div class="detail-value">{{ $f.Method }}</div>
						</div>
						{{ end }}
						{{ if $f.Payload }}
						<div class="detail-row">
							<div class="detail-label">Payload:</div>
							<div class="detail-value"><code>{{ $f.Payload }}</code></div>
						</div>
						{{ end }}
						{{ if $f.Location }}
						<div class="detail-row">
							<div class="detail-label">Redirect Location:</div>
							<div class="detail-value">{{ $f.Location }}</div>
						</div>
						{{ end }}
						<div class="detail-row">
							<div class="detail-label">Discovered:</div>
							<div class="detail-value">{{ $f.Timestamp.Format "2006-01-02 15:04:05" }}</div>
						</div>
					</div>
					
					<div class="section-title">What This Means</div>
					<p>{{ $info.Description }}</p>
					
					<div class="section-title" style="margin-top: 20px;">How Attackers Could Exploit It</div>
					<p>{{ $info.Exploitation }}</p>
					
					<div class="section-title" style="margin-top: 20px;">How to Investigate Further</div>
					<p>{{ $info.Investigation }}</p>
					
					<div class="section-title" style="margin-top: 20px;">How to Fix</div>
					<p>{{ $info.Fix }}</p>
					
					{{ if $f.Evidence }}
					<div class="section-title" style="margin-top: 20px;">Evidence</div>
					<div class="evidence">{{ $f.Evidence }}</div>
					{{ end }}
				</div>
				{{ end }}
				{{ else }}
				<p style="text-align: center; color: #27ae60; font-size: 1.2em; padding: 40px;">
					✓ No vulnerabilities detected! The target appears secure.
				</p>
				{{ end }}
			</div>
			
			<footer>
				Generated by <strong>Knife Vulnerability Scanner</strong> — for ethical and educational use only.<br>
				Learn. Investigate. Protect.
			</footer>
		</div>
	</body>
</html>`

	funcMap := template.FuncMap{
		"add":         func(a, b int) int { return a + b },
		"vulnExplain": vulnDetails,
	}
	
	t := template.New("unified_report").Funcs(funcMap)
	t, err = t.Parse(tpl)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}
	
	data := struct {
		GeneratedAt string
		Target      string
		Findings    []UnifiedFinding
		Summary     map[string]int
	}{
		GeneratedAt: now,
		Target:      target,
		Findings:    findings,
		Summary:     summary,
	}
	
	if err := t.Execute(f, data); err != nil {
		return fmt.Errorf("template execution failed: %w", err)
	}
	
	fmt.Printf("[+] Unified report saved to: %s\n", fullPath)
	return nil
}

// calculateSummary generates statistics from findings
func calculateSummary(findings []UnifiedFinding) map[string]int {
	summary := map[string]int{
		"Total":    len(findings),
		"Critical": 0,
		"High":     0,
		"Medium":   0,
		"Low":      0,
	}
	
	for _, f := range findings {
		switch f.Severity {
		case "Critical":
			summary["Critical"]++
		case "High":
			summary["High"]++
		case "Medium":
			summary["Medium"]++
		case "Low":
			summary["Low"]++
		}
	}
	
	return summary
}
