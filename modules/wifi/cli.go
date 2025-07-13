package wifi

import "fmt"

var wifiFunc = []string{
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

func Interact(choice string) {
	switch choice {
	case "Deauth":
		DeauthHandle()
	case "Evil Twin":
		EvilTwinHandle()
	case "Geo-Locate":
		GeoloacateHandle()
	case "HandShake":
		HandShakeHandle()
	case "Injector":
		InjectorHandle()
	case "Mac Spoofer":
		MacSpooferHandle()
	case "Pmkid":
		PmkidHandle()
	case "Sniffer":
		SnifferHandle()
	case "Scanner":
		ScannerHandle()
	}
}

// TODO: ADD MAIN FUNCTIONALITY
func DeauthHandle() {
	fmt.Println("i am deauth")
}

func EvilTwinHandle() {
	fmt.Println("i am evil handle")
}

func GeoloacateHandle() {
	fmt.Println("i am geoloacte")
}

func HandShakeHandle() {
	fmt.Println("i am handshake")
}

func InjectorHandle() {
	fmt.Println("i am injector")
}

func MacSpooferHandle() {
	fmt.Println("i am mac spoofer")
}

func PmkidHandle() {
	fmt.Println("i am pmkid")
}

func SnifferHandle() {
	fmt.Println("i am sniffer")
}

func ScannerHandle() {
	fmt.Println("i am scanner")
}
