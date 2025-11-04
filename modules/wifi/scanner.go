package wifi

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ScanNetworks runs the scan for a single interface and returns SSIDs.
func ScanNetworks(iface string) ([]string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("iw dev %s scan | grep SSID", iface))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var ssids []string
	for _, line := range lines {
		// some lines may be empty, skip them
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		ssid := strings.TrimSpace(strings.Replace(l, "SSID:", "", 1))
		if ssid != "" && ssid != "* SSID List" {
			ssids = append(ssids, ssid)
		}
	}
	return ssids, nil
}

// ChannelHopSingle performs channel hopping on one interface (non-blocking Run).
func ChannelHopSingle(iface string, ch int) error {
	return exec.Command("bash", "-c", fmt.Sprintf("iwconfig %s channel %d", iface, ch)).Run()
}

// ScanAndPrintAll scans all provided interfaces and prints found SSIDs.
func ScanAndPrintAll(ifaces []string) {
	if len(ifaces) == 0 {
		fmt.Println("No wireless interfaces found.")
		return
	}
	for _, iface := range ifaces {
		fmt.Printf("\n--- Interface: %s ---\n", iface)
		ssids, err := ScanNetworks(iface)
		if err != nil {
			fmt.Println("Scan error:", err)
			continue
		}
		if len(ssids) == 0 {
			fmt.Println("No SSIDs found.")
			continue
		}
		fmt.Println("Found SSIDs:")
		for _, s := range ssids {
			fmt.Println("-", s)
		}
	}
}

// Prompt returns trimmed input from stdin after showing prompt text.
func Prompt(promptText string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(promptText)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}
