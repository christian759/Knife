package vuln

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func Interact() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("==== Website Vulnerability Scanner ====")
	fmt.Print("Enter target URL (e.g., http://example.com/page): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	fmt.Print("Add custom headers? (Y/N): ")
	hdrAns, _ := reader.ReadString('\n')
	hdrAns = strings.TrimSpace(hdrAns)

	headers := make(map[string]string)
	if strings.EqualFold(hdrAns, "Y") {
		for {
			fmt.Print("Header (key:value) or blank to finish: ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				break
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			} else {
				fmt.Println("Invalid header format.")
			}
		}
	}

	fmt.Print("Add cookies? (Y/N): ")
	cookieAns, _ := reader.ReadString('\n')
	cookieAns = strings.TrimSpace(cookieAns)

	cookies := ""
	if strings.EqualFold(cookieAns, "Y") {
		fmt.Print("Enter cookies (key1=val1; key2=val2): ")
		cookieInput, _ := reader.ReadString('\n')
		cookies = strings.TrimSpace(cookieInput)
	}

	fmt.Println("Scanning", target, "...")
	// Here you would call the scanning functions, passing in the target, headers, and cookies as needed.

	fmt.Println("Headers:", headers)
	fmt.Println("Cookies:", cookies)
	ScanURL(target, headers, cookies)
	fmt.Println("Scan complete.")
}
