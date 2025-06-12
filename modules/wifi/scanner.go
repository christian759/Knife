// knife/modules/wifi/scanner.go
package wifi

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func ScanNetworks(iface string) ([]string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("iw dev %s scan | grep SSID", iface))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var ssids []string
	for _, line := range lines {
		ssids = append(ssids, strings.TrimSpace(strings.Replace(line, "SSID:", "", 1)))
	}
	return ssids, nil
}

func ChannelHop(iface string, delay time.Duration) {
	channels := []int{1, 6, 11, 3, 9, 13, 2, 10, 7, 4, 5, 8, 12, 14}
	for {
		for _, ch := range channels {
			exec.Command("bash", "-c", fmt.Sprintf("iwconfig %s channel %d", iface, ch)).Run()
			time.Sleep(delay)
		}
	}
}
