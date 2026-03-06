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

func snippetAround(s, match string, maxLen int) string {
	loc := strings.Index(s, match)
	if loc == -1 {
		return snippet(s, maxLen)
	}
	start := loc - maxLen/2
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
	
	case strings.Contains(n, "header"):
		return VulnInfo{
			Severity:      "Low",
			Description:   "HTTP Security Headers (like CSP, HSTS, XFO) are missing or misconfigured, weakening the browser's ability to protect the user.",
			Fix:           "Configure the web server to send appropriate security headers in all responses.",
			Exploitation:  "Lack of headers makes it easier to perform Clickjacking, XSS, or downgrade attacks.",
			Investigation: "Use browser developer tools or 'curl -I' to inspect server response headers.",
		}

	case strings.Contains(n, "file") || strings.Contains(n, "discovery"):
		return VulnInfo{
			Severity:      "High",
			Description:   "Sensitive files (like .env, .git/config, backups) are publicly accessible, potentially leaking credentials or source code.",
			Fix:           "Restrict access to sensitive files using server configuration or move them outside the web root.",
			Exploitation:  "Attackers can extract database passwords, API keys, or intellectual property.",
			Investigation: "Attempt to access common sensitive paths directly via the browser.",
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
				font-family: 'Courier New', Courier, monospace; 
				background: #0d0208;
				color: #00ff41;
				padding: 20px;
				min-height: 100vh;
			}
			.container {
				max-width: 1200px;
				margin: 0 auto;
				background: #000;
				border: 1px solid #00ff41;
				border-radius: 4px;
				box-shadow: 0 0 20px #00ff4155;
				overflow: hidden;
			}
			.header {
				background: #000;
				border-bottom: 2px solid #ff0000;
				color: #ff0000;
				padding: 40px;
				text-align: center;
				text-transform: uppercase;
				letter-spacing: 4px;
			}
			.header h1 { font-size: 3em; margin-bottom: 10px; text-shadow: 0 0 10px #ff000055; }
			.header p { opacity: 0.9; font-size: 1.1em; color: #00ff41; }
			.summary {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
				gap: 20px;
				padding: 30px 40px;
				background: #050505;
				border-bottom: 1px solid #00ff41;
			}
			.summary-card {
				background: #000;
				padding: 20px;
				border: 1px solid #00ff41;
				border-radius: 4px;
				text-align: center;
				transition: all 0.2s;
			}
			.summary-card:hover { border-color: #ff0000; box-shadow: 0 0 10px #ff000055; }
			.summary-card h3 { font-size: 2.5em; margin-bottom: 5px; }
			.summary-card p { color: #00ff41; font-size: 0.9em; text-transform: uppercase; }
			.critical { color: #ff0000; border-color: #ff0000 !important; }
			.high { color: #e67e22; }
			.medium { color: #f1c40f; }
			.low { color: #3498db; }
			.findings {
				padding: 40px;
			}
			.finding-card {
				background: #050505;
				border: 1px solid #00ff41;
				padding: 25px;
				margin-bottom: 30px;
				box-shadow: 5px 5px 0px #00ff4122;
			}
			.finding-card.severity-Critical { border-color: #ff0000; box-shadow: 5px 5px 0px #ff000022; }
			.finding-card.severity-High { border-color: #e67e22; }
			.finding-card.severity-Medium { border-color: #f1c40f; }
			.finding-card.severity-Low { border-color: #3498db; }
			.finding-header {
				display: flex;
				justify-content: space-between;
				align-items: center;
				margin-bottom: 20px;
				border-bottom: 1px solid #333;
				padding-bottom: 10px;
			}
			.finding-title { font-size: 1.6em; color: #ff0000; font-weight: bold; }
			.severity-badge {
				padding: 4px 12px;
				border-radius: 2px;
				font-weight: bold;
				font-size: 0.8em;
				text-transform: uppercase;
				border: 1px solid;
			}
			.severity-badge.Critical { color: #ff0000; border-color: #ff0000; }
			.severity-badge.High { color: #e67e22; border-color: #e67e22; }
			.severity-badge.Medium { color: #f1c40f; border-color: #f1c40f; }
			.severity-badge.Low { color: #3498db; border-color: #3498db; }
			.finding-details { margin: 15px 0; font-size: 0.95em; }
			.detail-row {
				display: grid;
				grid-template-columns: 200px 1fr;
				padding: 10px 0;
				border-bottom: 1px solid #111;
			}
			.detail-label { font-weight: bold; color: #00ff41; opacity: 0.7; text-transform: uppercase; }
			.detail-value { color: #00ff41; word-break: break-all; }
			.evidence {
				background: #000;
				border: 1px dashed #00ff41;
				padding: 15px;
				font-family: 'Courier New', monospace;
				white-space: pre-wrap;
				overflow-x: auto;
				margin-top: 15px;
				font-size: 0.9em;
				color: #00ff41;
			}
			.section-title {
				font-size: 1.1em;
				color: #ff0000;
				margin-bottom: 8px;
				text-transform: uppercase;
				letter-spacing: 1px;
			}
			footer {
				text-align: center;
				padding: 40px;
				background: #050505;
				color: #444;
				font-size: 0.8em;
				border-top: 1px solid #111;
			}
			.timestamp { color: #333; }
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
