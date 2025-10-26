package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"knife/modules/mobile"
	"knife/modules/phish"
	"knife/modules/vuln"
	"knife/modules/wifi"
)

var width int

var Modules = []string{
	"Mobile attack",
	"Phishing",
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

// getting terminal size
func getTerminalSize() (int, int, error) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}

	size := strings.Split(string(out), " ")
	width, err := strconv.Atoi(strings.TrimSpace(size[1]))
	if err != nil {
		return 0, 0, err
	}

	height, err := strconv.Atoi(strings.TrimSpace(size[0]))
	if err != nil {
		return 0, 0, err
	}

	return width, height, nil
}

// printing the bold title(knife)
func printAsciiArtAlign(sentences []string, textFile []string, position string, w int) {
	for i, word := range sentences {
		if word == "" {
			if i != 0 {
				fmt.Println()
			}
			continue
		}
		wordCount := 1
		for _, char := range word {
			if char == ' ' {
				wordCount++
			}
		}
		wordLen := 0
		for i := 0; i < len(word); i++ {
			for lineIndex, line := range textFile {
				if lineIndex == (int(word[i])-32)*9+2 {
					wordLen += len(line)
					break
				}
			}
		}
		var spacesForJustify int
		if wordCount == 1 && position == "justify" {
			position = "center"
		} else if wordCount == 1 {
			spacesForJustify = (w - wordLen) / wordCount
		} else {
			spacesForJustify = (w - wordLen) / (wordCount - 1)
		}
		spaces := w/2 - wordLen/2
		for h := 1; h < 9; h++ {
			switch position {
			case "center":
				for i := 1; i <= spaces; i++ {
					fmt.Print(" ")
				}
			case "right":
				for i := 1; i <= spaces*2; i++ {
					fmt.Print(" ")
				}
			}
			for i := 0; i < len(word); i++ {
				for lineIndex, line := range textFile {
					if lineIndex == (int(word[i])-32)*9+h {
						if position == "justify" && i != len(word)-1 && word[i] == ' ' {
							fmt.Print(line)
							for i := 1; i <= spacesForJustify; i++ {
								fmt.Print(" ")
							}
						} else {
							fmt.Print(line)
						}
						break
					}
				}
			}
			switch position {
			case "center":
				for i := 1; i <= spaces; i++ {
					fmt.Print(" ")
				}
			case "left":
				for i := 1; i <= spaces*2; i++ {
					fmt.Print(" ")
				}
			}

			fmt.Println()
		}
	}
}

func MobileModule() {
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
		return
	}

	switch moduleIntNo {
	case 1:
		mobile.InteractInject()
	case 2:
		mobile.InteractApkMeat()
	}

}

func PhishModule() {
	for index, module := range TrickPhishTemp {
		fmt.Printf("[%d] %s\n", index+1, module)
	}

	// Take input
	var moduleIntNo int
	fmt.Print("Select a template: ")
	fmt.Scan(&moduleIntNo)

	// Validate input
	if moduleIntNo < 1 || moduleIntNo > len(TrickPhishTemp) {
		fmt.Println("Choice out of range")
		return
	}

	phish.Interact(moduleIntNo)
}

func VulnModule() {
	vuln.Interact()
}

func WifiModule() {
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
		return
	}

	// Set selected module
	SelectedModule = TrickWifi[moduleIntNo-1]
	wifi.Interact(SelectedModule)
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
func main() {
	argStr := "Go-Knife"
	sepArgs := strings.Split(argStr, "\\n")

	width, _, _ = getTerminalSize()

	file, err := os.ReadFile("letters.txt")
	if err != nil {
		fmt.Println(err)
	}

	lines := strings.Split(string(file), "\n")
	printAsciiArtAlign(sepArgs, lines, "left", width)

	SelectedModule = DisplayModules()
	fmt.Println(SelectedModule)

	switch SelectedModule {

	case "Mobile attack":
		MobileModule()

	case "Phishing":
		PhishModule()

	case "Web vulnerability":
		VulnModule()

	case "Wifi attack":
		WifiModule()

	default:
		os.Exit(1)
	}

}
