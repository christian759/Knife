package wifi

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const privilegedFlag = "--run-pmkid-privileged"

func IsRootOrSudoRelaunch() bool {
	// 1. If we are already running as root, return true.
	if os.Getuid() == 0 {
		return true
	}

	// 2. Check if the magic flag is already present.
	// If it is, this means we've already tried to relaunch and failed, or the user manually used sudo.
	// We treat it as a non-privileged process that should exit cleanly.
	for _, arg := range os.Args {
		if arg == privilegedFlag {
			// If the flag is present but we are NOT root (os.Getuid() != 0),
			// it means the sudo attempt failed or was canceled.
			return false // Stop execution of the task.
		}
	}

	// 3. If not root and no magic flag, attempt to relaunch with sudo.
	fmt.Println("This operation requires root privileges. Requesting sudo...")

	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to find executable path: %v\n", err)
		os.Exit(1)
	}

	// Append the magic flag to the arguments being passed to sudo.
	args := append(os.Args[1:], privilegedFlag)
	cmd := exec.Command("sudo", append([]string{executable}, args...)...)

	// Connect streams for password prompt
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to re-run with sudo: %v\n", err)
		os.Exit(1)
	}

	// 4. Exit the non-privileged process (MANDATORY STEP).
	os.Exit(0)
	return false // Unreachable, but satisfies compiler
}

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
