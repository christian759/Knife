package main

import "fmt"

func printAsciiArt(sentences []string, textFile []string) {
	for i, word := range sentences {
		if word == "" {
			if i != 0 {
				fmt.Println()
			}
			continue
		}
		for h := 1; h < 9; h++ {
			for i := 0; i < len(word); i++ {
				for lineIndex, line := range textFile {
					if lineIndex == (int(word[i])-32)*9+h {
						fmt.Print(line)
					}
				}
			}
			fmt.Println()
		}
	}
}

func main() {
}
