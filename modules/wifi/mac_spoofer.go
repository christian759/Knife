// knife/modules/wifi/mac_spoofer.go
package wifi

import (
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
)

func RandomMAC(iface string) (string, error) {
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		rand.Intn(256), rand.Intn(256), rand.Intn(256),
		rand.Intn(256), rand.Intn(256), rand.Intn(256))

	exec.Command("ifconfig", iface, "down").Run()
	exec.Command("ifconfig", iface, "hw", "ether", mac).Run()
	exec.Command("ifconfig", iface, "up").Run()

	return mac, nil
}

func GetCurrentMAC(iface string) (string, error) {
	out, err := exec.Command("cat", fmt.Sprintf("/sys/class/net/%s/address", iface)).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
