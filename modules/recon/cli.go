package recon

import (
	"fmt"
)

// user search
var userName string

// dork searching
var dorkName string
var strict string
var engine string
var dorkResult map[string]string

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
		fmt.Scan(&strict)
		if strict == "Y" || strict == "y" {
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
	}

}
