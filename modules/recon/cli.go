package recon

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// global input reader
var reader = bufio.NewReader(os.Stdin)

func Interact(selectedOption int) {
	switch selectedOption {
	case 1:
		userName := readInput("Enter the username to search for:")
		sitesInput := readInput("Enter sites to search (comma separated, e.g. https://github.com,https://twitter.com):")
		sites := parseCSVInput(sitesInput)
		if len(sites) == 0 {
			fmt.Println("No sites provided.")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		results, err := SearchUser(ctx, userName, sites)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		if len(results) == 0 {
			fmt.Println("No profiles found.")
		} else {
			fmt.Println("Found profiles:")
			for _, url := range results {
				fmt.Println(" -", url)
			}
		}

	case 2:
		dorkName := readInput("Enter the dork or search phrase:")
		dorkEngine := readInput("Enter the search engine (google/duckduck):")
		maxResults := readIntInput("Max results (number):", 10)
		results, err := DorkSearch(dorkName, dorkEngine, maxResults)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		if len(results) == 0 {
			fmt.Println("No results found.")
		} else {
			fmt.Println("Results:")
			for i, value := range results {
				fmt.Printf("%d. %s\n", i+1, value)
			}
		}

	case 3:
		whoisWeb := readInput("Enter the website or domain for WHOIS lookup:")
		result, err := WhoisLookup(whoisWeb)
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Println(result)
		}

	case 4:
		dnsDomain := readInput("Enter the domain name for DNS recon:")
		res := DNSRecon(dnsDomain)
		fmt.Println("A records:", res.A)
		fmt.Println("AAAA records:", res.AAAA)
		fmt.Println("MX records:", res.MX)
		fmt.Println("NS records:", res.NS)
		fmt.Println("TXT records:", res.TXT)
		fmt.Println("CNAME:", res.CNAME)
		fmt.Println("Wildcard DNS detected:", res.HasWildcard)

	case 5:
		emailName := readInput("Enter the domain to hunt for emails (e.g. example.com):")
		emailDepth := readIntInput("Enter the search depth (number):", 2)
		emailStrict := readBoolInput("Strict search (only emails ending with @domain)? (Y/N):")
		emails, err := EmailHunter(emailName, emailDepth, emailStrict)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		if len(emails) == 0 {
			fmt.Println("No emails found.")
		} else {
			fmt.Println("Emails found:")
			for _, email := range emails {
				fmt.Println(" -", email)
			}
		}

	case 6:
		target := readInput("Enter target for port scan (IP or domain):")
		portsInput := readInput("Enter ports to scan (comma separated, e.g. 80,443,8080):")
		ports := parsePortsInput(portsInput)
		if len(ports) == 0 {
			fmt.Println("No valid ports provided.")
			return
		}
		udp := readBoolInput("Scan UDP? (Y/N):")
		timeout := readIntInput("Timeout per port (seconds):", 2)
		results := PortScan(target, ports, time.Duration(timeout)*time.Second, udp)
		if len(results) == 0 {
			fmt.Println("No open ports found.")
		} else {
			fmt.Println("Open ports:")
			for _, r := range results {
				fmt.Printf("%s/%d: %s\n", r.Proto, r.Port, r.Banner)
			}
		}

	case 7:
		webAnalyzer := readInput("Enter website to analyze headers (e.g. https://example.com):")
		headers, err := HeaderAnalyze(webAnalyzer)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Println("Interesting headers:")
		for k, v := range headers {
			fmt.Printf("%s: %s\n", k, v)
		}
	default:
		fmt.Println("Unknown option.")
	}
}

// Helper function to read and trim input
func readInput(prompt string) string {
	fmt.Println(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// Helper function to read integer input with a default value
func readIntInput(prompt string, defaultValue int) int {
	input := readInput(prompt)
	value, err := strconv.Atoi(input)
	if err != nil || value < 1 {
		return defaultValue
	}
	return value
}

// Helper function to read boolean (Y/N) input
func readBoolInput(prompt string) bool {
	input := readInput(prompt)
	return input == "Y" || input == "y"
}

// Helper function to parse CSV input
func parseCSVInput(input string) []string {
	var result []string
	for _, s := range strings.Split(input, ",") {
		site := strings.TrimSpace(s)
		if site != "" {
			result = append(result, site)
		}
	}
	return result
}

// Helper function to parse ports input
func parsePortsInput(input string) []int {
	var ports []int
	for _, p := range strings.Split(input, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(p))
		if err == nil && port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	return ports
}
