package wifi

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
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
	case "PmKid":
		PmkidHandle()
	case "Sniffer":
		SnifferHandle()
	case "Scanner":
		ScannerHandleConcurrent()
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
	// detect wireless interfaces (assumes GetWirelessInterfaces() exists)
	ifaces, err := GetWirelessInterfaces()
	if err != nil {
		fmt.Println("Error detecting wireless interfaces:", err)
		return
	}
	if len(ifaces) == 0 {
		fmt.Println("No wireless interfaces detected.")
		return
	}

	// use the first wireless interface by default
	iface := strings.TrimSpace(ifaces[0])
	fmt.Println("Using interface:", iface)

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Choose action — Randomize MAC (R) / Show current MAC (S) / Quit (Q): ")
		raw, _ := reader.ReadString('\n')
		choice := strings.ToLower(strings.TrimSpace(raw))

		switch choice {
		case "r", "random", "randomize":
			fmt.Println("Randomizing MAC... (requires root)")
			newMac, err := RandomMAC(iface)
			if err != nil {
				fmt.Println("Error randomizing MAC:", err)
			} else {
				// verify readback
				curr, cerr := GetCurrentMAC(iface)
				if cerr != nil {
					fmt.Printf("New MAC (reported): %s — but verification failed: %v\n", newMac, cerr)
				} else {
					fmt.Printf("New MAC: %s (verified: %s)\n", newMac, curr)
				}
			}
			return

		case "s", "show", "current":
			mac, err := GetCurrentMAC(iface)
			if err != nil {
				fmt.Println("Error reading current MAC:", err)
			} else {
				fmt.Println("Current MAC:", mac)
			}
			return

		case "q", "quit", "exit":
			fmt.Println("Cancelled.")
			return

		default:
			fmt.Println("Unrecognized choice. Please enter R, S, or Q.")
			// loop and prompt again
		}
	}
}

func PmkidHandle() {
	ifaces, err := GetWirelessInterfaces()
	if err != nil {
		fmt.Println("Error detecting wireless interfaces:", err)
		return
	}
	if len(ifaces) == 0 {
		fmt.Println("No wireless interfaces detected.")
		return
	}

	// Show available interfaces
	fmt.Println("Detected interfaces:")
	for i, ifn := range ifaces {
		fmt.Printf("  [%d] %s\n", i+1, ifn)
	}
	fmt.Printf("Select interface number (press Enter for %s): ", ifaces[0])

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	// Choose one interface
	selected := ifaces[0]
	if choice != "" {
		if idx, err := strconv.Atoi(choice); err == nil && idx >= 1 && idx <= len(ifaces) {
			selected = ifaces[idx-1]
		} else {
			fmt.Println("Invalid selection, using default:", selected)
		}
	}

	fmt.Printf("Using interface: %s\n", selected)

	fmt.Print("Output file: ")
	file, _ := reader.ReadString('\n')
	file = strings.TrimSpace(file)
	fmt.Print("Timeout (seconds): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout, _ := strconv.Atoi(timeoutStr)
	err = CapturePMKID(selected, file, time.Duration(timeout)*time.Second)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("PMKID capture complete.")
	}
}

func SnifferHandle() {
	ifaces, err := GetWirelessInterfaces()
	if err != nil {
		fmt.Println("Error detecting wireless interfaces:", err)
		return
	}
	if len(ifaces) == 0 {
		fmt.Println("No wireless interfaces detected.")
		return
	}

	// Show available interfaces
	fmt.Println("Detected interfaces:")
	for i, ifn := range ifaces {
		fmt.Printf("  [%d] %s\n", i+1, ifn)
	}
	fmt.Printf("Select interface number (press Enter for %s): ", ifaces[0])

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	// Choose one interface
	selected := ifaces[0]
	if choice != "" {
		if idx, err := strconv.Atoi(choice); err == nil && idx >= 1 && idx <= len(ifaces) {
			selected = ifaces[idx-1]
		} else {
			fmt.Println("Invalid selection, using default:", selected)
		}
	}

	fmt.Printf("Using interface: %s\n", selected)

	// Ask for mode
	fmt.Print("Sniff probe requests only? (Y/N): ")
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(ans)

	// Timeout input if probe-only mode
	if strings.EqualFold(ans, "y") {
		fmt.Print("Timeout (seconds): ")
		timeoutStr, _ := reader.ReadString('\n')
		timeoutStr = strings.TrimSpace(timeoutStr)
		timeout, err := strconv.Atoi(timeoutStr)
		if err != nil || timeout <= 0 {
			fmt.Println("Invalid timeout, defaulting to 10 seconds.")
			timeout = 10
		}
		fmt.Printf("Sniffing probe requests on %s for %d seconds...\n", selected, timeout)
		SniffProbes(selected, time.Duration(timeout)*time.Second)
	} else {
		fmt.Printf("Starting full packet sniffer on %s (Ctrl+C to stop)...\n", selected)
		StartPacketSniffer(selected)
	}
}

func ScannerHandleConcurrent() {
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

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		go func(ifn string) {
			defer wg.Done()
			fmt.Printf("\n--- Interface: %s ---\n", ifn)
			ssids, err := ScanNetworks(ifn)
			if err != nil {
				fmt.Println("Scan error:", err)
				return
			}
			if len(ssids) == 0 {
				fmt.Println("No SSIDs found.")
				return
			}
			fmt.Println("Found SSIDs:")
			for _, s := range ssids {
				fmt.Println("-", s)
			}
		}(iface)
	}
	wg.Wait()
	fmt.Println("\nFinished concurrent single-pass scan.")
}
