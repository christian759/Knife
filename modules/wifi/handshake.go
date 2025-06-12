// knife/modules/wifi/handshake.go
package wifi

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func CaptureHandshake(iface, filepath string, timeout time.Duration) error {
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
	fmt.Println("[*] Waiting for WPA2 4-way handshake...")

	start := time.Now()
	for packet := range packetSource.Packets() {
		if time.Since(start) > timeout {
			break
		}
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		// Add logic to detect EAPOL here if needed
	}
	fmt.Println("[*] Capture saved to", filepath)
	return nil
}
