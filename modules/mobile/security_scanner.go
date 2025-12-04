package mobile

import (
	"fmt"
	"os/exec"
	"strings"
)

// SecurityIssue represents a security finding
type SecurityIssue struct {
	Severity    string // "High", "Medium", "Low", "Info"
	Category    string
	Description string
	Remediation string
}

// SecurityScanResult holds all security findings
type SecurityScanResult struct {
	APKPath string
	Issues  []SecurityIssue
}

// ScanAPKSecurity performs comprehensive security scanning of APK
func ScanAPKSecurity(apkPath string) (*SecurityScanResult, error) {
	result := &SecurityScanResult{
		APKPath: apkPath,
		Issues:  []SecurityIssue{},
	}

	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║          MOBILE SECURITY SCANNER                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Printf("Scanning: %s\n", apkPath)
	fmt.Println(strings.Repeat("─", 60))

	// Get APK info for analysis
	analysis, err := DeepAnalyzeAPK(apkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze APK: %v", err)
	}

	// Check 1: Debuggable flag
	checkDebuggable(apkPath, result)

	// Check 2: Backup allowance
	checkBackupAllowed(apkPath, result)

	// Check 3: Clear text traffic
	checkClearTextTraffic(apkPath, result)

	// Check 4: Exported components without permissions
	checkExportedComponents(analysis, result)

	// Check 5: Dangerous permissions
	checkDangerousPermissions(analysis, result)

	// Check 6: Min SDK version
	checkMinSDK(analysis, result)

	// Check 7: Code obfuscation
	checkObfuscation(apkPath, result)

	return result, nil
}

func checkDebuggable(apkPath string, result *SecurityScanResult) {
	cmd := exec.Command("aapt", "dump", "badging", apkPath)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	if strings.Contains(string(output), "application-debuggable") {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:    "High",
			Category:    "Configuration",
			Description: "Application is debuggable - allows runtime inspection and code injection",
			Remediation: "Remove android:debuggable=\"true\" from AndroidManifest.xml",
		})
	}
}

func checkBackupAllowed(apkPath string, result *SecurityScanResult) {
	cmd := exec.Command("aapt", "dump", "xmltree", apkPath, "AndroidManifest.xml")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	// Check if backup is explicitly allowed
	if strings.Contains(string(output), "android:allowBackup") {
		if strings.Contains(string(output), "0xffffffff") || strings.Contains(string(output), "true") {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:    "Medium",
				Category:    "Data Protection",
				Description: "Application allows backup - sensitive data may be extracted via ADB",
				Remediation: "Set android:allowBackup=\"false\" in AndroidManifest.xml",
			})
		}
	}
}

func checkClearTextTraffic(apkPath string, result *SecurityScanResult) {
	cmd := exec.Command("aapt", "dump", "xmltree", apkPath, "AndroidManifest.xml")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	if strings.Contains(string(output), "usesCleartextTraffic") {
		if strings.Contains(string(output), "0xffffffff") || strings.Contains(string(output), "true") {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:    "Medium",
				Category:    "Network Security",
				Description: "Application allows clear text (HTTP) traffic - vulnerable to MITM attacks",
				Remediation: "Remove usesCleartextTraffic or set to false, use HTTPS only",
			})
		}
	}
}

func checkExportedComponents(analysis *APKAnalysis, result *SecurityScanResult) {
	exportedCount := 0
	vulnerableComponents := []string{}

	for _, activity := range analysis.Activities {
		if activity.Exported {
			exportedCount++
			vulnerableComponents = append(vulnerableComponents, "Activity: "+activity.Name)
		}
	}

	for _, service := range analysis.Services {
		if service.Exported {
			exportedCount++
			vulnerableComponents = append(vulnerableComponents, "Service: "+service.Name)
		}
	}

	for _, receiver := range analysis.Receivers {
		if receiver.Exported {
			exportedCount++
			vulnerableComponents = append(vulnerableComponents, "Receiver: "+receiver.Name)
		}
	}

	for _, provider := range analysis.Providers {
		if provider.Exported {
			exportedCount++
			vulnerableComponents = append(vulnerableComponents, "Provider: "+provider.Name)
		}
	}

	if exportedCount > 0 {
		severity := "Low"
		if exportedCount > 5 {
			severity = "Medium"
		}

		desc := fmt.Sprintf("%d exported components without permission protection - potential attack surface", exportedCount)
		if exportedCount <= 3 {
			desc += "\n  Components:\n  • " + strings.Join(vulnerableComponents, "\n  • ")
		}

		result.Issues = append(result.Issues, SecurityIssue{
			Severity:    severity,
			Category:    "Access Control",
			Description: desc,
			Remediation: "Review exported components and add permission protection or set android:exported=\"false\"",
		})
	}
}

func checkDangerousPermissions(analysis *APKAnalysis, result *SecurityScanResult) {
	dangerousPerms := []string{}

	dangerousPatterns := []string{
		"READ_CONTACTS", "WRITE_CONTACTS",
		"READ_SMS", "SEND_SMS", "RECEIVE_SMS",
		"READ_CALENDAR", "WRITE_CALENDAR",
		"CAMERA",
		"RECORD_AUDIO",
		"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
		"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
		"READ_PHONE_STATE", "CALL_PHONE",
		"BODY_SENSORS",
	}

	for _, perm := range analysis.Permissions {
		for _, pattern := range dangerousPatterns {
			if strings.Contains(perm.Name, pattern) {
				dangerousPerms = append(dangerousPerms, perm.Name)
				break
			}
		}
	}

	if len(dangerousPerms) > 5 {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:    "Medium",
			Category:    "Privacy",
			Description: fmt.Sprintf("High number of dangerous permissions requested (%d) - may indicate privacy concerns", len(dangerousPerms)),
			Remediation: "Review if all permissions are necessary, follow principle of least privilege",
		})
	}
}

func checkMinSDK(analysis *APKAnalysis, result *SecurityScanResult) {
	// Parse SDK version
	if analysis.MinSDK != "" {
		// Try to convert to int
		var minSDK int
		fmt.Sscanf(analysis.MinSDK, "%d", &minSDK)
		
		if minSDK > 0 && minSDK < 23 {
			result.Issues = append(result.Issues, SecurityIssue{
				Severity:    "Low",
				Category:    "Platform Security",
				Description: fmt.Sprintf("Low minimum SDK version (%s) - missing modern security features", analysis.MinSDK),
				Remediation: "Consider increasing minSdkVersion to 23+ for runtime permissions and enhanced security",
			})
		}
	}
}

func checkObfuscation(apkPath string, result *SecurityScanResult) {
	// Check for common obfuscation indicators
	cmd := exec.Command("aapt", "list", apkPath)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	files := string(output)
	
	// Look for ProGuard/R8 mapping file
	hasMapping := strings.Contains(files, "mapping.txt")
	
	// Check for short class names (typical of obfuscation)
	hasShortNames := strings.Contains(files, "/a.class") || 
		strings.Contains(files, "/b.class") ||
		strings.Contains(files, "/c.class")

	if !hasMapping && !hasShortNames {
		result.Issues = append(result.Issues, SecurityIssue{
			Severity:    "Info",
			Category:    "Code Protection",
			Description: "No code obfuscation detected - easier for attackers to reverse engineer",
			Remediation: "Enable ProGuard or R8 code obfuscation in build configuration",
		})
	}
}

// FormatSecurityReport returns the security scan results as a formatted string
func FormatSecurityReport(result *SecurityScanResult) string {
	var s strings.Builder

	s.WriteString("\n╔════════════════════════════════════════════════════════════╗\n")
	s.WriteString("║              SECURITY SCAN RESULTS                         ║\n")
	s.WriteString("╚════════════════════════════════════════════════════════════╝\n")

	// Count by severity
	high, medium, low, info := 0, 0, 0, 0
	for _, issue := range result.Issues {
		switch issue.Severity {
		case "High":
			high++
		case "Medium":
			medium++
		case "Low":
			low++
		case "Info":
			info++
		}
	}

	s.WriteString(fmt.Sprintf("\n📊 Summary:\n"))
	s.WriteString(fmt.Sprintf("   Total Issues: %d\n", len(result.Issues)))
	if high > 0 {
		s.WriteString(fmt.Sprintf("   🔴 High:   %d\n", high))
	}
	if medium > 0 {
		s.WriteString(fmt.Sprintf("   🟠 Medium: %d\n", medium))
	}
	if low > 0 {
		s.WriteString(fmt.Sprintf("   🟡 Low:    %d\n", low))
	}
	if info > 0 {
		s.WriteString(fmt.Sprintf("   🔵 Info:   %d\n", info))
	}

	if len(result.Issues) == 0 {
		s.WriteString("\n✅ No security issues detected!\n")
		s.WriteString("   (This doesn't guarantee the app is secure - manual review recommended)\n")
		return s.String()
	}

	s.WriteString("\n🔍 Detailed Findings:\n")
	s.WriteString(strings.Repeat("─", 60) + "\n")

	for i, issue := range result.Issues {
		// Icon based on severity
		icon := "•"
		switch issue.Severity {
		case "High":
			icon = "🔴"
		case "Medium":
			icon = "🟠"
		case "Low":
			icon = "🟡"
		case "Info":
			icon = "🔵"
		}

		s.WriteString(fmt.Sprintf("\n%s [%s] %s\n", icon, issue.Severity, issue.Category))
		s.WriteString(fmt.Sprintf("   Issue: %s\n", issue.Description))
		s.WriteString(fmt.Sprintf("   Fix:   %s\n", issue.Remediation))
		
		if i < len(result.Issues)-1 {
			s.WriteString(strings.Repeat("─", 60) + "\n")
		}
	}

	s.WriteString("\n" + strings.Repeat("─", 60) + "\n")
	s.WriteString("💡 Recommendations:\n")
	s.WriteString("   • Address High severity issues immediately\n")
	s.WriteString("   • Review Medium issues based on app context\n")
	s.WriteString("   • Perform dynamic analysis with debugger/proxy\n")
	s.WriteString("   • Conduct code review for hardcoded secrets\n")
	s.WriteString("   • Test for SQL injection and XSS vulnerabilities\n")
	s.WriteString("\n✓ Security scan complete\n")
	
	return s.String()
}
