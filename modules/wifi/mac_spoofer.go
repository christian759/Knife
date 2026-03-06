package wifi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RandomMAC generates a locally-administered unicast MAC and applies it to iface.
// It attempts to use `ip` and falls back to `ifconfig`. Returns the new MAC or an error.
func RandomMAC(iface string) (string, error) {
	if iface = strings.TrimSpace(iface); iface == "" {
		return "", errors.New("interface name is empty")
	}

	mac, err := generateLocallyAdministeredMAC()
	if err != nil {
		return "", fmt.Errorf("generate MAC: %w", err)
	}

	// Bring interface down, change MAC, bring up. Prefer `ip` tool.
	if hasCmd("ip") {
		if err := runCmd("ip", "link", "set", "dev", iface, "down"); err != nil {
			return "", fmt.Errorf("bring down iface: %w", err)
		}
		if err := runCmd("ip", "link", "set", "dev", iface, "address", mac); err != nil {
			return "", fmt.Errorf("set mac (ip): %w", err)
		}
		if err := runCmd("ip", "link", "set", "dev", iface, "up"); err != nil {
			return "", fmt.Errorf("bring up iface: %w", err)
		}
	} else if hasCmd("ifconfig") {
		if err := runCmd("ifconfig", iface, "down"); err != nil {
			return "", fmt.Errorf("bring down iface (ifconfig): %w", err)
		}
		if err := runCmd("ifconfig", iface, "hw", "ether", mac); err != nil {
			return "", fmt.Errorf("set mac (ifconfig): %w", err)
		}
		if err := runCmd("ifconfig", iface, "up"); err != nil {
			return "", fmt.Errorf("bring up iface (ifconfig): %w", err)
		}
	} else {
		return "", errors.New("neither `ip` nor `ifconfig` available on PATH")
	}

	return mac, nil
}

// GetCurrentMAC reads the interface MAC from /sys/class/net/<iface>/address.
// Returns the MAC string (lowercase) or an error.
func GetCurrentMAC(iface string) (string, error) {
	if iface = strings.TrimSpace(iface); iface == "" {
		return "", errors.New("interface name is empty")
	}
	path := filepath.Join("/sys/class/net", iface, "address")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	mac := strings.TrimSpace(string(data))
	if !isValidMAC(mac) {
		return "", fmt.Errorf("invalid MAC read from %s: %q", path, mac)
	}
	return strings.ToLower(mac), nil
}

// --- helpers ---

// generateLocallyAdministeredMAC returns a MAC string like "02:xx:xx:xx:xx:xx".
// It sets the locally-administered bit (bit 1) and clears the multicast bit (bit 0).
func generateLocallyAdministeredMAC() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// Set locally administered bit, clear multicast bit on first octet:
	// b00000010 = locally administered (bit 1)
	// ensure unicast by clearing bit 0 (multicast)
	buf[0] &= 0xFC // clear lower two bits
	buf[0] |= 0x02 // set locally administered bit

	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = fmt.Sprintf("%02x", buf[i])
	}
	return strings.Join(parts, ":"), nil
}

func isValidMAC(mac string) bool {
	// simple validation: 6 octets hex separated by ':'
	parts := strings.Split(strings.ToLower(strings.TrimSpace(mac)), ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		if _, err := hex.DecodeString(p); err != nil {
			return false
		}
	}
	return true
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w -- output: %s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
