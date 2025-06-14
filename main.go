package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var width int

var modules = []string{
	"mobile attack",
	"phishing",
	"reconnaissance",
	"web vulnerability",
	"wifi attack",
}

var moduleNo string

var selectedModule string

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
			if position == "center" {
				for i := 1; i <= spaces; i++ {
					fmt.Print(" ")
				}
			} else if position == "right" {
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
			if position == "center" {
				for i := 1; i <= spaces; i++ {
					fmt.Print(" ")
				}
			} else if position == "left" {
				for i := 1; i <= spaces*2; i++ {
					fmt.Print(" ")
				}
			}

			fmt.Println()
		}
	}
}

func displayModule() string {
	for index, module := range modules {
		fmt.Printf("[%d] %s \n", index+1, module)
	}
	// taking input
	fmt.Print("Select the number: ")
	fmt.Scan(&moduleNo)

	moduleIntNo, err := strconv.Atoi(moduleNo)
	if err != nil {
		fmt.Printf("could not convert '%s' to type string \n", moduleNo)
		return ""
	}

	for index, value := range modules {
		if index == moduleIntNo-1 {
			selectedModule = modules[moduleIntNo]
			return value
		} else {
			return "number is not in range"
		}
	}
	return "/n"
}

func main() {
	argStr := "Go-Knife"
	sepArgs := strings.Split(argStr, "\\n")

	width, _, _ = getTerminalSize()

	file, err := os.ReadFile("standard.txt")
	if err != nil {
		fmt.Println(err)
	}

	lines := strings.Split(string(file), "\n")
	printAsciiArtAlign(sepArgs, lines, "left", width)

	selectedModule = displayModule()
	println(selectedModule)
	// testing the phishing module
	/*
		if len(os.Args) >= 4 && os.Args[1] == "phish" {
			template := os.Args[2]
			port, _ := strconv.Atoi(os.Args[3])
			phish.Launch(template, port)
		}
	*/

	// testing the vuln scanner movule (doesnt seem to be to through)
	/*
		vuln.ScanURL("https://unilorin.edu.ng")
	*/

	//testing the apk module
	/*
		mobile.ParseAPKMeat("/home/christian/archive/codemine/codemine.apk")
	*/
}
