package recon

import (
	"bufio"
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
		SearchUser(userName, sites)

	case 2:
		dorkName := readInput("Enter the dork or search phrase:")
		dorkEngine := readInput("Enter the search engine (google/duckduck):")
		maxResults := readIntInput("Max results (number):", 10)

		results := DorkSearching(dorkName, dorkEngine, maxResults)
		fmt.Println("Results:")
		for i, value := range results {
			fmt.Printf("%d. %s\n", i+1, value)
		}

	case 3:
		whoisWeb := readInput("Enter the website or domain for WHOIS lookup:")
		LookupWhois(whoisWeb)

	case 4:
		dnsDomain := readInput("Enter the domain name for DNS recon:")
		DNSRecon(dnsDomain)

	case 5:
		emailName := readInput("Enter the domain to hunt for emails (e.g. example.com):")
		emailDepth := readIntInput("Enter the search depth (number):", 2)
		emailStrict := readBoolInput("Strict search (only emails ending with @domain)? (Y/N):")
		EmailHunter(emailName, emailDepth, emailStrict)

	case 6:
		webAnalyzer := readInput("Enter website to analyze headers (e.g. https://example.com):")
		HeaderAnalyzer(webAnalyzer)

	case 7:
		target := readInput("Enter target for port scan (IP or domain):")
		portsInput := readInput("Enter ports to scan (comma separated, e.g. 80,443,8080):")
		ports := parsePortsInput(portsInput)
		if len(ports) == 0 {
			fmt.Println("No valid ports provided.")
			return
		}

		udp := readBoolInput("Scan UDP? (Y/N):")
		timeout := readIntInput("Timeout per port (seconds):", 2)
		PortScanner(target, ports, time.Duration(timeout)*time.Second, udp)
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
