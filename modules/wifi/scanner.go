package wifi

import (
	"fmt"
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


