// knife/modules/wifi/probe_sniffer.go
package wifi

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func SniffProbes(iface string, timeout time.Duration, outChan chan<- string) error {
	handle, err := pcap.OpenLive(iface, 2048, true, timeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	start := time.Now()
	
	if outChan != nil {
		outChan <- fmt.Sprintf("[*] Sniffing for probe requests on %s...", iface)
	}

	for packet := range packetSource.Packets() {
		if time.Since(start) > timeout {
			break
		}
		if probeReqLayer := packet.Layer(layers.LayerTypeDot11MgmtProbeReq); probeReqLayer != nil {
			if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
				dot11 := dot11Layer.(*layers.Dot11)
				if outChan != nil {
					outChan <- fmt.Sprintf("[+] Probe from: %s", dot11.Address2)
				}
			}
		}
	}
	return nil
}
