package main

import (
	"fmt"
)

var Modules = []string{
	"Mobile attack",
	"Phishing",
	"Reconnaissance",
	"Web vulnerability",
	"Wifi attack",
}

var TrickMobile = []string{
	"Injector",
	"Recon",
}

var TrickPhishTemp = []string{
	"Facebook",
	"Gmail",
	"Instagram",
	"Netflix",
	"Outlook",
}

var TrickRecon = []string{
	"Search users",
	"Dork searching",
	"Whois",
	"Dns reconnaissance",
	"Email hunter",
	"Port scanner",
	"Header analyzer",
}

var TrickWifi = []string{
	"Deauth",
	"Evil Twin",
	"Geo-locate",
	"HandShake",
	"Injector",
	"Interface",
	"Mac Spoofer",
	"PmKid",
	"Sniffer",
	"Scanner",
}

var SelectedModule string

func MobileModule() string {
	for index, module := range TrickMobile {
		fmt.Printf("[%d] %s\n", index+1, module)
	}

	// Take input
	var moduleIntNo int
	fmt.Print("Select the number: ")
	fmt.Scan(&moduleIntNo)

	// Validate input
	if moduleIntNo < 1 || moduleIntNo > len(TrickMobile) {
		fmt.Println("Choice out of range")
		return ""
	}

	// Set selected module
	SelectedModule = Modules[moduleIntNo-1]
	return SelectedModule
}

func PhishModule() string {
	for index, module := range TrickPhishTemp {
		fmt.Printf("[%d] %s\n", index+1, module)
	}

	// Take input
	var moduleIntNo int
	fmt.Print("Select the number: ")
	fmt.Scan(&moduleIntNo)

	// Validate input
	if moduleIntNo < 1 || moduleIntNo > len(TrickPhishTemp) {
		fmt.Println("Choice out of range")
		return ""
	}

	// Set selected module
	SelectedModule = Modules[moduleIntNo-1]
	return SelectedModule
}

func ReconModule() string {
	for index, module := range TrickRecon {
		fmt.Printf("[%d] %s\n", index+1, module)
	}

	// Take input
	var moduleIntNo int
	fmt.Print("Select the number: ")
	fmt.Scan(&moduleIntNo)

	// Validate input
	if moduleIntNo < 1 || moduleIntNo > len(TrickRecon) {
		fmt.Println("Choice out of range")
		return ""
	}

	// Set selected module
	SelectedModule = Modules[moduleIntNo-1]
	return SelectedModule
}

func VulnModule() string {
	return ""
}

func WifiModule() string {
	for index, module := range TrickWifi {
		fmt.Printf("[%d] %s\n", index+1, module)
	}

	// Take input
	var moduleIntNo int
	fmt.Print("Select the number: ")
	fmt.Scan(&moduleIntNo)

	// Validate input
	if moduleIntNo < 1 || moduleIntNo > len(TrickWifi) {
		fmt.Println("Choice out of range")
		return ""
	}

	// Set selected module
	SelectedModule = Modules[moduleIntNo-1]
	return SelectedModule
}

func DisplayModules() string {
	for index, module := range Modules {
		fmt.Printf("[%d] %s\n", index+1, module)
	}

	// Take input
	var moduleIntNo int
	fmt.Print("Select the number: ")
	fmt.Scan(&moduleIntNo)

	// Validate input
	if moduleIntNo < 1 || moduleIntNo > len(Modules) {
		fmt.Println("Choice out of range")
		return ""
	}

	// Set selected module
	SelectedModule = Modules[moduleIntNo-1]
	return SelectedModule
}
