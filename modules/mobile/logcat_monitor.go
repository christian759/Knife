package mobile

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// LogLevel represents Android log levels
type LogLevel string

const (
	LogVerbose LogLevel = "V"
	LogDebug   LogLevel = "D"
	LogInfo    LogLevel = "I"
	LogWarn    LogLevel = "W"
	LogError   LogLevel = "E"
	LogFatal   LogLevel = "F"
)

// LogcatConfig holds configuration for logcat monitoring
type LogcatConfig struct {
	Level       LogLevel
	PackageFilter string
	TagFilter   string
	ClearFirst  bool
}

// MonitorLogcat monitors Android logcat in real-time
func MonitorLogcat(config LogcatConfig) error {
	// Clear logcat if requested
	if config.ClearFirst {
		clearCmd := exec.Command("adb", "logcat", "-c")
		if err := clearCmd.Run(); err != nil {
			fmt.Printf("Warning: Could not clear logcat: %v\n", err)
		} else {
			fmt.Println("✓ Logcat buffer cleared")
		}
	}

	// Build logcat command
	args := []string{"logcat"}
	
	// Add log level filter
	if config.Level != "" {
		args = append(args, fmt.Sprintf("*:%s", config.Level))
	}

	// Add tag filter if specified
	if config.TagFilter != "" {
		args = append(args, "-s", config.TagFilter)
	}

	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           ANDROID LOGCAT MONITOR                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Printf("Log Level: %s\n", config.Level)
	if config.PackageFilter != "" {
		fmt.Printf("Package Filter: %s\n", config.PackageFilter)
	}
	if config.TagFilter != "" {
		fmt.Printf("Tag Filter: %s\n", config.TagFilter)
	}
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println("Press Ctrl+C to stop monitoring...\n")

	// Start logcat
	cmd := exec.Command("adb", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start adb logcat: %v", err)
	}

	// Read and display logs
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		
		// Apply package filter if specified
		if config.PackageFilter != "" && !strings.Contains(line, config.PackageFilter) {
			continue
		}

		// Colorize output based on log level
		colorizedLine := colorizeLogLine(line)
		fmt.Println(colorizedLine)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading logcat: %v", err)
	}

	return cmd.Wait()
}

// colorizeLogLine adds color codes based on log level
func colorizeLogLine(line string) string {
	// ANSI color codes
	const (
		colorReset  = "\033[0m"
		colorRed    = "\033[31m"
		colorYellow = "\033[33m"
		colorBlue   = "\033[34m"
		colorGray   = "\033[90m"
		colorWhite  = "\033[97m"
	)

	// Detect log level and colorize
	if strings.Contains(line, " E ") || strings.Contains(line, "/E(") {
		return colorRed + line + colorReset
	} else if strings.Contains(line, " W ") || strings.Contains(line, "/W(") {
		return colorYellow + line + colorReset
	} else if strings.Contains(line, " I ") || strings.Contains(line, "/I(") {
		return colorWhite + line + colorReset
	} else if strings.Contains(line, " D ") || strings.Contains(line, "/D(") {
		return colorBlue + line + colorReset
	} else if strings.Contains(line, " V ") || strings.Contains(line, "/V(") {
		return colorGray + line + colorReset
	}

	return line
}

// SaveLogcat saves logcat output to a file
func SaveLogcat(filename string, config LogcatConfig) error {
	args := []string{"logcat", "-d"} // -d = dump and exit
	
	if config.Level != "" {
		args = append(args, fmt.Sprintf("*:%s", config.Level))
	}

	cmd := exec.Command("adb", args...)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get logcat: %v", err)
	}

	// Filter by package if specified
	lines := strings.Split(string(output), "\n")
	filteredLines := []string{}
	
	for _, line := range lines {
		if config.PackageFilter == "" || strings.Contains(line, config.PackageFilter) {
			filteredLines = append(filteredLines, line)
		}
	}

	// Write to file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(strings.Join(filteredLines, "\n"))
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	fmt.Printf("✓ Logcat saved to: %s\n", filename)
	fmt.Printf("  Lines captured: %d\n", len(filteredLines))
	
	return nil
}

// GetConnectedDevices returns list of connected Android devices
func GetConnectedDevices() ([]string, error) {
	cmd := exec.Command("adb", "devices")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run adb devices: %v", err)
	}

	devices := []string{}
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") || strings.HasPrefix(line, "*") {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == "device" {
			devices = append(devices, parts[0])
		}
	}

	return devices, nil
}
