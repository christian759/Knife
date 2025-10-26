package wifi

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var reader = bufio.NewReader(os.Stdin)

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
	case "Interface":
		InterfaceHandle()
	case "Mac Spoofer":
		MacSpooferHandle()
	case "Pmkid":
		PmkidHandle()
	case "Sniffer":
		SnifferHandle()
	case "Scanner":
		ScannerHandle()
	default:
		fmt.Println("Unknown option:", choice)
	}
}

// Deauth attack handler
func DeauthHandle() {
	fmt.Print("Interface: ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	fmt.Print("BSSID (AP MAC): ")
	bssid, _ := reader.ReadString('\n')
	bssid = strings.TrimSpace(bssid)
	fmt.Print("Target MAC (or ff:ff:ff:ff:ff:ff for broadcast): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	fmt.Print("Count: ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count, _ := strconv.Atoi(countStr)
	err := DeauthAttack(iface, bssid, target, count)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Deauth sent.")
	}
}

func EvilTwinHandle() {
	fmt.Print("Interface: ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	fmt.Print("SSID to fake: ")
	ssid, _ := reader.ReadString('\n')
	ssid = strings.TrimSpace(ssid)
	StartEvilTwin(iface, ssid)
	fmt.Println("Press Enter to stop Evil Twin...")
	reader.ReadString('\n')
	StopEvilTwin()
}

func GeoloacateHandle() {
	fmt.Print("MAC address (BSSID): ")
	mac, _ := reader.ReadString('\n')
	mac = strings.TrimSpace(mac)
	fmt.Print("Signal strength (dBm): ")
	signalStr, _ := reader.ReadString('\n')
	signalStr = strings.TrimSpace(signalStr)
	signal, _ := strconv.Atoi(signalStr)
	fmt.Print("Google API Key: ")
	apiKey, _ := reader.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)
	resp, err := Geolocate([]WiFiAccessPoint{{MacAddress: mac, SignalStrength: signal}}, apiKey)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Lat: %.6f, Lng: %.6f (Accuracy: %.2fm)\n", resp.Location.Lat, resp.Location.Lng, resp.Accuracy)
	}
}

func HandShakeHandle() {
	fmt.Print("Interface: ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	fmt.Print("Output file: ")
	file, _ := reader.ReadString('\n')
	file = strings.TrimSpace(file)
	fmt.Print("Timeout (seconds): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout, _ := strconv.Atoi(timeoutStr)
	err := CaptureHandshake(iface, file, time.Duration(timeout)*time.Second)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Handshake capture complete.")
	}
}

func InjectorHandle() {
	fmt.Print("Interface: ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	fmt.Print("SSID to flood: ")
	ssid, _ := reader.ReadString('\n')
	ssid = strings.TrimSpace(ssid)
	fmt.Print("Count: ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count, _ := strconv.Atoi(countStr)
	InjectBeaconFlood(iface, ssid, count)
	fmt.Println("Beacon flood sent.")
}

func InterfaceHandle() {
	fmt.Println("Available actions:")
	for i, v := range interfaceWifi {
		fmt.Printf("%d. %s\n", i+1, v)
	}
	fmt.Print("Select action: ")
	actionIdxStr, _ := reader.ReadString('\n')
	actionIdxStr = strings.TrimSpace(actionIdxStr)
	actionIdx, _ := strconv.Atoi(actionIdxStr)
	if actionIdx < 1 || actionIdx > len(interfaceWifi) {
		fmt.Println("Invalid selection.")
		return
	}
	action := interfaceWifi[actionIdx-1]
	var iface string
	if action != "List Interface" {
		fmt.Print("Interface: ")
		iface, _ = reader.ReadString('\n')
		iface = strings.TrimSpace(iface)
	}
	err := HandleWifiAction(action, iface)
	if err != nil {
		fmt.Println("Error:", err)
	}
}

func MacSpooferHandle() {
	fmt.Print("Interface: ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	fmt.Print("Randomize MAC? (Y/N): ")
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(ans)
	if ans == "Y" || ans == "y" {
		mac, err := RandomMAC(iface)
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Println("New MAC:", mac)
		}
	} else {
		mac, err := GetCurrentMAC(iface)
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Println("Current MAC:", mac)
		}
	}
}

func PmkidHandle() {
	fmt.Print("Interface: ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	fmt.Print("Output file: ")
	file, _ := reader.ReadString('\n')
	file = strings.TrimSpace(file)
	fmt.Print("Timeout (seconds): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout, _ := strconv.Atoi(timeoutStr)
	err := CapturePMKID(iface, file, time.Duration(timeout)*time.Second)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("PMKID capture complete.")
	}
}

func SnifferHandle() {
	fmt.Print("Interface: ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	fmt.Print("Sniff probe requests only? (Y/N): ")
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(ans)
	if ans == "Y" || ans == "y" {
		fmt.Print("Timeout (seconds): ")
		timeoutStr, _ := reader.ReadString('\n')
		timeoutStr = strings.TrimSpace(timeoutStr)
		timeout, _ := strconv.Atoi(timeoutStr)
		SniffProbes(iface, time.Duration(timeout)*time.Second)
	} else {
		StartPacketSniffer(iface)
	}
}

func ScannerHandle() {
	ifaces, err := GetWirelessInterfaces()
	if err != nil {
		fmt.Println("Error detecting wireless interfaces:", err)
		return
	}
	if len(ifaces) == 0 {
		fmt.Println("No wireless interfaces detected.")
		return
	}

	fmt.Println("Detected interfaces:", strings.Join(ifaces, ", "))
	ScanAndPrintAll(ifaces)

	// Ask user if they want continuous scanning + optional channel hopping.
	ans := Prompt("\nContinuous scan with channel hopping across all interfaces? (Y/N): ")
	if strings.EqualFold(ans, "y") {
		delayStr := Prompt("Hop delay in ms (e.g. 500): ")
		delayMs, err := strconv.Atoi(delayStr)
		if err != nil || delayMs <= 0 {
			fmt.Println("Invalid delay; using 500ms.")
			delayMs = 500
		}
		delay := time.Duration(delayMs) * time.Millisecond

		// channels to hop — you can change or extend this slice
		channels := []int{1, 6, 11, 3, 9, 13, 2, 10, 7, 4, 5, 8, 12, 14}
		fmt.Println("Starting continuous scan. Press Ctrl+C to stop.")
		for {
			// hop each interface sequentially (simple approach)
			for _, ch := range channels {
				for _, iface := range ifaces {
					_ = ChannelHopSingle(iface, ch) // ignore hop errors here
				}
				ScanAndPrintAll(ifaces)
				time.Sleep(delay)
			}
		}
	}
}
