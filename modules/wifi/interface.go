// knife/modules/wifi/interface.go
package wifi

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// ListInterfaces returns all wireless interfaces available
func ListInterfaces() ([]string, error) {
	out, err := exec.Command("bash", "-c", "iw dev | grep Interface | awk '{print $2}'").Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines, nil
}

func EnableMonitorMode(iface string) error {
	commands := []string{
		"ip link set " + iface + " down",
		"iw dev " + iface + " set type monitor",
		"ip link set " + iface + " up",
	}
	for _, cmd := range commands {
		if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
			return fmt.Errorf("[!] Failed to run: %s", cmd)
		}
	}
	return nil
}

func RestoreManagedMode(iface string) error {
	commands := []string{
		"ip link set " + iface + " down",
		"iw dev " + iface + " set type managed",
		"ip link set " + iface + " up",
	}
	for _, cmd := range commands {
		if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
			return err
		}
	}
	return nil
}

// StartPacketSniffer opens the interface in promiscuous mode and listens
func StartPacketSniffer(iface string) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}
