package wifi

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// GetWirelessInterfaces returns a slice of wireless interface names (wlan0, wlp2s0, etc).
func GetWirelessInterfaces() ([]string, error) {
	cmd := exec.Command("bash", "-c", "iw dev | grep Interface | awk '{print $2}'")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	lines := strings.Split(raw, "\n")
	var ifaces []string
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" {
			ifaces = append(ifaces, t)
		}
	}
	return ifaces, nil
}

// AP holds parsed scan info
type AP struct {
	BSSID  string
	SSID   string
	Signal float64 // dBm (negative numbers; closer to 0 is stronger)
}

// scanAPs runs `iw dev <iface> scan` and returns parsed APs
func scanAPs(iface string) ([]AP, error) {
	reBSS := regexp.MustCompile(`^BSS\s+([0-9a-f:]{17})\b`)
	reSSID := regexp.MustCompile(`^\s*SSID:\s*(.*)$`)
	reSignal := regexp.MustCompile(`^\s*signal:\s*([-\d\.]+)\s*dBm`)

	cmd := exec.Command("iw", "dev", iface, "scan")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("iw scan failed: %v; output:\n%s", err, out.String())
	}

	var results []AP
	var cur *AP
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		if m := reBSS.FindStringSubmatch(line); m != nil {
			if cur != nil {
				results = append(results, *cur)
			}
			cur = &AP{BSSID: strings.ToLower(m[1])}
			continue
		}
		if cur == nil {
			continue
		}
		if m := reSSID.FindStringSubmatch(line); m != nil {
			cur.SSID = m[1]
			continue
		}
		if m := reSignal.FindStringSubmatch(line); m != nil {
			// parse float
			if v, err := strconv.ParseFloat(m[1], 64); err == nil {
				cur.Signal = v
			}
			continue
		}
	}
	if cur != nil {
		results = append(results, *cur)
	}
	return results, nil
}
