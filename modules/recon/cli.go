package recon

import (
	"fmt"
)

// user search
var userName string

// dork searching
var dorkName string
var dorkStrict string
var engine string
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
		fmt.Println("Enter the name of the Person: ")
		fmt.Scan(&userName)
		search_user(userName)

	case 2:
		fmt.Println("Enter the Word or Phrase you want to search for")
		fmt.Scan(&dorkName)
		fmt.Println("Enter the search engine (google/duckduck):")
		fmt.Scan(&engine)
		fmt.Println("Strict Searching ? (Y/N):")
		fmt.Scan(&dorkStrict)
		if dorkStrict == "Y" || dorkStrict == "y" {
			dorkResult = dork_searching(dorkName, true, engine)
			for index, value := range dorkResult {
				fmt.Println(index, value)
			}
		} else {
			dorkResult = dork_searching(dorkName, false, engine)
			for index, value := range dorkResult {
				fmt.Println(index, value)
			}
		}

	case 3:
		fmt.Println("enter the website name or domain: ")
		fmt.Scan(&whoisWeb)
		LookupWhois(whoisWeb)

	case 4:
		fmt.Println("enter the domain name: ")
		fmt.Scan(&dnsDomain)
		DNSRecon(dnsDomain)

	case 5:
		fmt.Println("enter email to search for: ")
		fmt.Scan(&emailName)
		fmt.Println("enter the search depth(number): ")
		fmt.Scan(&emailDepth)
		fmt.Println("deep search (Y or N): ")

		if emailStrict == "Y" || emailStrict == "y" {
			EmailHunter(emailName, emailDepth, true)
		} else {
			EmailHunter(emailName, emailDepth, false)
		}

	case 6:
		fmt.Println("enter website to analyze: ")
		fmt.Scan(&webAnalyzer)
		HeaderAnalyzer(webAnalyzer)
	}

}
