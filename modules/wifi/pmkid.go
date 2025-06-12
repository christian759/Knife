// knife/modules/wifi/pmkid.go
package wifi

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func CapturePMKID(iface, filepath string, timeout time.Duration) error {
	handle, err := pcap.OpenLive(iface, 2048, true, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(2048, handle.LinkType())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("[*] Waiting for PMKID packets...")
	start := time.Now()

	for packet := range packetSource.Packets() {
		if time.Since(start) > timeout {
			break
		}
		if isPMKID(packet) {
			writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
	fmt.Println("[*] PMKID capture complete.")
	return nil
}

func isPMKID(packet gopacket.Packet) bool {
	// Check for EAPOL key frames with RSN capabilities
	// This is a placeholder: proper parsing required
	return strings.Contains(packet.String(), "PMKID")
}
