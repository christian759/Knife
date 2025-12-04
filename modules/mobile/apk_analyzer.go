package mobile

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// APKAnalysis holds detailed APK information
type APKAnalysis struct {
	PackageName    string
	VersionName    string
	VersionCode    string
	MinSDK         string
	TargetSDK      string
	Permissions    []Permission
	Activities     []Component
	Services       []Component
	Receivers      []Component
	Providers      []Component
}

// Permission represents an Android permission
type Permission struct {
	Name           string
	ProtectionLevel string
}

// Component represents an Android component (Activity, Service, etc.)
type Component struct {
	Name     string
	Exported bool
}

// DeepAnalyzeAPK performs comprehensive APK analysis
func DeepAnalyzeAPK(apkPath string) (*APKAnalysis, error) {
	analysis := &APKAnalysis{
		Permissions: []Permission{},
		Activities:  []Component{},
		Services:    []Component{},
		Receivers:   []Component{},
		Providers:   []Component{},
	}

	// Get badging info (package, version, SDK)
	cmd := exec.Command("aapt", "dump", "badging", apkPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try aapt2 if aapt fails
		cmd = exec.Command("aapt2", "dump", "badging", apkPath)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to run aapt/aapt2: %v\nOutput: %s", err, output)
		}
	}

	parseBadging(string(output), analysis)

	// Get permissions
	cmd = exec.Command("aapt", "dump", "permissions", apkPath)
	output, err = cmd.CombinedOutput()
	if err == nil {
		parsePermissions(string(output), analysis)
	}

	// Get XML tree for manifest
	cmd = exec.Command("aapt", "dump", "xmltree", apkPath, "AndroidManifest.xml")
	output, err = cmd.CombinedOutput()
	if err == nil {
		parseManifest(string(output), analysis)
	}

	return analysis, nil
}

func parseBadging(output string, analysis *APKAnalysis) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		
		if strings.HasPrefix(line, "package:") {
			// Extract package name
			if idx := strings.Index(line, "name='"); idx != -1 {
				start := idx + 6
				if end := strings.Index(line[start:], "'"); end != -1 {
					analysis.PackageName = line[start : start+end]
				}
			}
			// Extract version code
			if idx := strings.Index(line, "versionCode='"); idx != -1 {
				start := idx + 13
				if end := strings.Index(line[start:], "'"); end != -1 {
					analysis.VersionCode = line[start : start+end]
				}
			}
			// Extract version name
			if idx := strings.Index(line, "versionName='"); idx != -1 {
				start := idx + 13
				if end := strings.Index(line[start:], "'"); end != -1 {
					analysis.VersionName = line[start : start+end]
				}
			}
		} else if strings.HasPrefix(line, "sdkVersion:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				analysis.MinSDK = strings.Trim(parts[1], " '\"")
			}
		} else if strings.HasPrefix(line, "targetSdkVersion:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				analysis.TargetSDK = strings.Trim(parts[1], " '\"")
			}
		}
	}
}

func parsePermissions(output string, analysis *APKAnalysis) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "uses-permission:") || strings.HasPrefix(line, "permission:") {
			// Extract permission name
			if idx := strings.Index(line, "name='"); idx != -1 {
				start := idx + 6
				if end := strings.Index(line[start:], "'"); end != -1 {
					permName := line[start : start+end]
					perm := Permission{Name: permName}
					analysis.Permissions = append(analysis.Permissions, perm)
				}
			}
		}
	}
}

func parseManifest(output string, analysis *APKAnalysis) {
	lines := strings.Split(output, "\n")
	var currentElement string
	var currentExported bool

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Detect element type
		if strings.Contains(trimmed, "E: activity") {
			currentElement = "activity"
			currentExported = false
		} else if strings.Contains(trimmed, "E: service") {
			currentElement = "service"
			currentExported = false
		} else if strings.Contains(trimmed, "E: receiver") {
			currentElement = "receiver"
			currentExported = false
		} else if strings.Contains(trimmed, "E: provider") {
			currentElement = "provider"
			currentExported = false
		}

		// Extract name attribute
		if strings.Contains(trimmed, "A: android:name(") {
			if idx := strings.Index(trimmed, "=\""); idx != -1 {
				start := idx + 2
				if end := strings.Index(trimmed[start:], "\""); end != -1 {
					name := trimmed[start : start+end]
					
					// Check if exported
					if strings.Contains(trimmed, "android:exported") {
						currentExported = strings.Contains(trimmed, "true")
					}

					component := Component{
						Name:     name,
						Exported: currentExported,
					}

					switch currentElement {
					case "activity":
						analysis.Activities = append(analysis.Activities, component)
					case "service":
						analysis.Services = append(analysis.Services, component)
					case "receiver":
						analysis.Receivers = append(analysis.Receivers, component)
					case "provider":
						analysis.Providers = append(analysis.Providers, component)
					}
				}
			}
		}

		// Check for exported attribute
		if strings.Contains(trimmed, "A: android:exported") {
			currentExported = strings.Contains(trimmed, "0xffffffff")
		}
	}
}

// FormatAnalysis returns the analysis results as a formatted string
func FormatAnalysis(analysis *APKAnalysis) string {
	var s strings.Builder
	
	s.WriteString("\n╔════════════════════════════════════════════════════════════╗\n")
	s.WriteString("║             APK DEEP ANALYSIS REPORT                       ║\n")
	s.WriteString("╚════════════════════════════════════════════════════════════╝\n")

	s.WriteString(fmt.Sprintf("\n📦 Package Information:\n"))
	s.WriteString(fmt.Sprintf("   Package Name:  %s\n", analysis.PackageName))
	s.WriteString(fmt.Sprintf("   Version:       %s (%s)\n", analysis.VersionName, analysis.VersionCode))
	s.WriteString(fmt.Sprintf("   Min SDK:       %s\n", analysis.MinSDK))
	s.WriteString(fmt.Sprintf("   Target SDK:    %s\n", analysis.TargetSDK))

	s.WriteString(fmt.Sprintf("\n🔐 Permissions (%d):\n", len(analysis.Permissions)))
	for _, perm := range analysis.Permissions {
		// Highlight dangerous permissions
		isDangerous := strings.Contains(perm.Name, "CAMERA") ||
			strings.Contains(perm.Name, "LOCATION") ||
			strings.Contains(perm.Name, "CONTACTS") ||
			strings.Contains(perm.Name, "SMS") ||
			strings.Contains(perm.Name, "STORAGE") ||
			strings.Contains(perm.Name, "MICROPHONE")
		
		if isDangerous {
			s.WriteString(fmt.Sprintf("   ⚠️  %s\n", perm.Name))
		} else {
			s.WriteString(fmt.Sprintf("   •  %s\n", perm.Name))
		}
	}

	s.WriteString(fmt.Sprintf("\n📱 Activities (%d):\n", len(analysis.Activities)))
	for _, act := range analysis.Activities {
		if act.Exported {
			s.WriteString(fmt.Sprintf("   🔓 [EXPORTED] %s\n", act.Name))
		} else {
			s.WriteString(fmt.Sprintf("   •  %s\n", act.Name))
		}
	}

	s.WriteString(fmt.Sprintf("\n⚙️  Services (%d):\n", len(analysis.Services)))
	for _, svc := range analysis.Services {
		if svc.Exported {
			s.WriteString(fmt.Sprintf("   🔓 [EXPORTED] %s\n", svc.Name))
		} else {
			s.WriteString(fmt.Sprintf("   •  %s\n", svc.Name))
		}
	}

	s.WriteString(fmt.Sprintf("\n📡 Broadcast Receivers (%d):\n", len(analysis.Receivers)))
	for _, rcv := range analysis.Receivers {
		if rcv.Exported {
			s.WriteString(fmt.Sprintf("   🔓 [EXPORTED] %s\n", rcv.Name))
		} else {
			s.WriteString(fmt.Sprintf("   •  %s\n", rcv.Name))
		}
	}

	if len(analysis.Providers) > 0 {
		s.WriteString(fmt.Sprintf("\n🗄️  Content Providers (%d):\n", len(analysis.Providers)))
		for _, prov := range analysis.Providers {
			if prov.Exported {
				s.WriteString(fmt.Sprintf("   🔓 [EXPORTED] %s\n", prov.Name))
			} else {
				s.WriteString(fmt.Sprintf("   •  %s\n", prov.Name))
			}
		}
	}

	// Security warnings
	s.WriteString("\n⚠️  Security Considerations:\n")
	exportedCount := 0
	for _, act := range analysis.Activities {
		if act.Exported {
			exportedCount++
		}
	}
	for _, svc := range analysis.Services {
		if svc.Exported {
			exportedCount++
		}
	}
	for _, rcv := range analysis.Receivers {
		if rcv.Exported {
			exportedCount++
		}
	}

	if exportedCount > 0 {
		s.WriteString(fmt.Sprintf("   • %d exported components (potential attack surface)\n", exportedCount))
	}
	if len(analysis.Permissions) > 10 {
		s.WriteString(fmt.Sprintf("   • High number of permissions requested (%d)\n", len(analysis.Permissions)))
	}

	s.WriteString("\n" + strings.Repeat("─", 60) + "\n")
	
	return s.String()
}

