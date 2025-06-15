package recon

import (
	"fmt"
)

// user search
var userName string

// dork searching
var dorkName string
var strict bool

func Interact(selectedOption int) {
	switch selectedOption {
	case 1:
		fmt.Println("Enter the name of the Person: ")
		fmt.Scan(&userName)
		search_user(userName)

	case 2:
		fmt.Println("Enter the Word or Phrase you want to search for")
		fmt.Scan(&dorkName)
		fmt.Println("Strict Searching ? (Y/N):")
		fmt.Scan(&strict)

	}

}
