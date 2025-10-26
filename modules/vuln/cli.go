package vuln

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func Interact() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("==== Website Vulnerability Scanner ====")
	fmt.Println("This tool checks for common web vulnerabilities like XSS, SQLi, LFI, etc.")
	fmt.Println("Please provide the required inputs.")

	fmt.Print("Enter target URL (e.g., http://example.com/page): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	// --- Headers ---
	fmt.Print("Add custom headers? (Y/N): ")
	hdrAns, _ := reader.ReadString('\n')
	hdrAns = strings.TrimSpace(hdrAns)

	headers := make(map[string]string)
	if strings.EqualFold(hdrAns, "Y") {
		fmt.Println("Enter each header in 'Key: Value' format. Leave blank to finish.")
		for {
			fmt.Print("Header: ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			} else {
				fmt.Println("⚠️  Invalid format. Please use 'Key: Value'.")
			}
		}
	}

	// --- Cookies ---
	fmt.Print("Add cookies? (Y/N): ")
	cookieAns, _ := reader.ReadString('\n')
	cookieAns = strings.TrimSpace(cookieAns)

	cookies := ""
	if strings.EqualFold(cookieAns, "Y") {
		fmt.Print("Enter cookies (key1=val1; key2=val2): ")
		cookieInput, _ := reader.ReadString('\n')
		cookies = strings.TrimSpace(cookieInput)
	}

	// --- Start Scan ---
	fmt.Println("\n[+] Starting vulnerability scan on:", target)
	fmt.Println("[*] This may take a few seconds depending on server response time...")

	// Output path
	homeDir, _ := os.UserHomeDir()
	reportFile := fmt.Sprintf("%s/%s_report_%d.html", homeDir, strings.ReplaceAll(strings.ReplaceAll(target, "http://", ""), "https://", ""), time.Now().Unix())

	err := ScanURL(target, headers, cookies, reportFile)
	if err != nil {
		fmt.Println("❌ Scan failed:", err)
		return
	}

	fmt.Printf("\n✅ Scan complete!\nHTML Report saved at: %s\n", reportFile)
	fmt.Println("📄 You can open it in your browser to view detailed results.")
}
