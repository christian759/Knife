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

// DeauthHandle - auto-scans for BSSID and then prompts for target + count
func DeauthHandle() {
	// detect wireless interfaces
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

	// Run a scan and pick the strongest AP
	fmt.Printf("Scanning for nearby APs on interface %s (this may require sudo)...\n", iface)
	aps, err := scanAPs(iface)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		return
	}
	if len(aps) == 0 {
		fmt.Println("No APs found during scan. Make sure your interface is up and you have permission to scan.")
		return
	}

	// choose the AP with the best (largest) signal value (remember -30 > -80)
	best := aps[0]
	for _, a := range aps[1:] {
		if a.Signal > best.Signal {
			best = a
		}
	}

	chosenBSSID := strings.ToLower(strings.TrimSpace(best.BSSID))
	displaySSID := best.SSID
	if displaySSID == "" {
		displaySSID = "<hidden>"
	}
	fmt.Printf("Auto-selected BSSID: %s  (SSID: %s, signal: %.1f dBm)\n", chosenBSSID, displaySSID, best.Signal)

	// Prompt for remaining inputs (target + count)
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Target MAC (or ff:ff:ff:ff:ff:ff for broadcast): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	fmt.Print("Count: ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count, _ := strconv.Atoi(countStr)

	// Call your DeauthAttack (should be the harmless simulator)
	err = DeauthAttack(iface, chosenBSSID, target, count)
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
	// detect wireless interfaces
	ifaces, err := GetWirelessInterfaces()
	if err != nil {
		fmt.Println("Error detecting wireless interfaces:", err)
		return
	}
	if len(ifaces) == 0 {
		fmt.Println("No wireless interfaces detected.")
		return
	}
	iface := strings.TrimSpace(ifaces[0])

	fmt.Printf("Scanning for nearby APs on %s (this may require sudo)...\n", iface)
	aps, err := scanAPs(iface)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		// fallback to manual input like your original flow
		fallbackManualGeolocate()
		return
	}
	if len(aps) == 0 {
		fmt.Println("No APs found during scan. Falling back to manual input.")
		fallbackManualGeolocate()
		return
	}

	// show the list
	fmt.Println("Found APs:")
	for i, a := range aps {
		ssid := a.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		fmt.Printf("%2d) BSSID: %s  SSID: %s  Signal: %.1f dBm\n", i+1, a.BSSID, ssid, a.Signal)
	}

	// prompt selection
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Select AP by number (1-%d) or enter 'm' for manual MAC: ", len(aps))
	choiceRaw, _ := reader.ReadString('\n')
	choiceRaw = strings.TrimSpace(choiceRaw)

	var mac string
	if strings.EqualFold(choiceRaw, "m") || choiceRaw == "" {
		// manual entry
		fmt.Print("MAC address (BSSID): ")
		mac, _ = reader.ReadString('\n')
		mac = strings.TrimSpace(mac)
	} else {
		idx, err := strconv.Atoi(choiceRaw)
		if err != nil || idx < 1 || idx > len(aps) {
			fmt.Println("Invalid selection. Falling back to manual entry.")
			fmt.Print("MAC address (BSSID): ")
			mac, _ = reader.ReadString('\n')
			mac = strings.TrimSpace(mac)
		} else {
			mac = aps[idx-1].BSSID
			fmt.Printf("Selected BSSID: %s (SSID: %s)\n", mac, func() string {
				if aps[idx-1].SSID == "" {
					return "<hidden>"
				}
				return aps[idx-1].SSID
			}())
		}
	}

	// ask for signal strength
	fmt.Print("Signal strength (dBm): ")
	signalStr, _ := reader.ReadString('\n')
	signalStr = strings.TrimSpace(signalStr)
	signal, err := strconv.Atoi(signalStr)
	if err != nil {
		// if user left blank, try to match to detected AP signal (best effort)
		found := false
		for _, a := range aps {
			if strings.EqualFold(a.BSSID, mac) {
				signal = int(a.Signal)
				found = true
				break
			}
		}
		if !found {
			fmt.Println("Invalid or missing signal value; aborting.")
			return
		} else {
			fmt.Printf("Using detected signal: %d dBm\n", signal)
		}
	}

	// API key
	fmt.Print("Google API Key: ")
	apiKey, _ := reader.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)

	// Build request and call Geolocate. This uses your existing WiFiAccessPoint type.
	req := []WiFiAccessPoint{{MacAddress: mac, SignalStrength: signal}}
	resp, err := Geolocate(req, apiKey)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Lat: %.6f, Lng: %.6f (Accuracy: %.2fm)\n", resp.Location.Lat, resp.Location.Lng, resp.Accuracy)
}

// fallbackManualGeolocate keeps original behavior if scanning isn't available
func fallbackManualGeolocate() {
	reader := bufio.NewReader(os.Stdin)
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
	// detect wireless interfaces
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
