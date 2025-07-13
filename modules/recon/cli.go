package recon

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// global input reader
var reader = bufio.NewReader(os.Stdin)

// user search
var userName string

// dork searching
var dorkName string
var dorkStrict string
var dorkEngine string
var dorkResult map[string]string

// whois
var whoisWeb string

// dns recon
var dnsDomain string

// email hunter
var emailName string
var emailDepth int
var emailStrict string

// web analyzer
var webAnalyzer string

func Interact(selectedOption int) {
	switch selectedOption {
	case 1:
		fmt.Println("Enter the name of the Person:")
		input, _ := reader.ReadString('\n')
		userName = strings.TrimSpace(input)
		search_user(userName)

	case 2:
		fmt.Println("Enter the Word or Phrase you want to search for:")
		input, _ := reader.ReadString('\n')
		dorkName = strings.TrimSpace(input)

		fmt.Println("Enter the search engine (google/duckduck):")
		input, _ = reader.ReadString('\n')
		dorkEngine = strings.TrimSpace(input)

		fmt.Println("Strict Searching? (Y/N):")
		input, _ = reader.ReadString('\n')
		dorkStrict = strings.TrimSpace(input)

		if dorkStrict == "Y" || dorkStrict == "y" {
			dorkResult = dork_searching(dorkName, true, dorkEngine)
		} else {
			dorkResult = dork_searching(dorkName, false, dorkEngine)
		}
		for index, value := range dorkResult {
			fmt.Println(index, value)
		}

	case 3:
		fmt.Println("Enter the website name or domain:")
		input, _ := reader.ReadString('\n')
		whoisWeb = strings.TrimSpace(input)
		LookupWhois(whoisWeb)

	case 4:
		fmt.Println("Enter the domain name:")
		input, _ := reader.ReadString('\n')
		dnsDomain = strings.TrimSpace(input)
		DNSRecon(dnsDomain)

	case 5:
		fmt.Println("Enter email to search for: ")
		input, _ := reader.ReadString('\n')
		emailName = strings.TrimSpace(input)

		fmt.Println("Enter the search depth (number): ")
		input, _ = reader.ReadString('\n')
		emailDepth, _ = strconv.Atoi(strings.TrimSpace(input))

		fmt.Println("Deep search? (Y/N): ")
		input, _ = reader.ReadString('\n')
		emailStrict = strings.TrimSpace(input)

		if emailStrict == "Y" || emailStrict == "y" {
			EmailHunter(emailName, emailDepth, true)
		} else {
			EmailHunter(emailName, emailDepth, false)
		}

	case 6:
		fmt.Println("Enter website to analyze:")
		input, _ := reader.ReadString('\n')
		webAnalyzer = strings.TrimSpace(input)
		HeaderAnalyzer(webAnalyzer)
	}
}
