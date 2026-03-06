package mobile

import (
	"fmt"
	"os/exec"
	"strings"
)

// NetworkCaptureGuide provides instructions for mobile traffic interception
type NetworkCaptureGuide struct {
	ProxyType string // "mitmproxy" or "burp"
	ProxyIP   string
	ProxyPort string
}

// FormatNetworkCaptureInstructions returns the setup guide as a formatted string
func FormatNetworkCaptureInstructions(guide NetworkCaptureGuide) string {
	var s strings.Builder

	s.WriteString("\n╔════════════════════════════════════════════════════════════╗\n")
	s.WriteString("║      MOBILE NETWORK TRAFFIC CAPTURE SETUP GUIDE            ║\n")
	s.WriteString("╚════════════════════════════════════════════════════════════╝\n")

	s.WriteString("\n📱 Step 1: Setup Proxy Tool\n")
	s.WriteString(strings.Repeat("─", 60) + "\n")
	
	if guide.ProxyType == "mitmproxy" {
		s.WriteString("Using mitmproxy:\n")
		s.WriteString("  1. Install: pip install mitmproxy\n")
		s.WriteString("  2. Start proxy: mitmproxy -p 8080\n")
		s.WriteString("  3. Or web interface: mitmweb -p 8080\n")
	} else {
		s.WriteString("Using Burp Suite:\n")
		s.WriteString("  1. Open Burp Suite\n")
		s.WriteString("  2. Go to Proxy → Options\n")
		s.WriteString("  3. Ensure proxy listener is on 0.0.0.0:8080\n")
		s.WriteString("  4. Enable invisible proxying (optional)\n")
	}

	s.WriteString("\n🔧 Step 2: Configure Android Device Proxy\n")
	s.WriteString(strings.Repeat("─", 60) + "\n")
	s.WriteString("Manual Configuration:\n")
	s.WriteString("  1. Settings → Wi-Fi → Long press network → Modify\n")
	s.WriteString("  2. Advanced options → Proxy: Manual\n")
	s.WriteString(fmt.Sprintf("  3. Proxy hostname: %s\n", guide.ProxyIP))
	s.WriteString(fmt.Sprintf("  4. Proxy port: %s\n", guide.ProxyPort))
	s.WriteString("  5. Save\n")

	s.WriteString("\nADB Configuration (Alternative):\n")
	devices, _ := GetConnectedDevices()
	if len(devices) > 0 {
		s.WriteString(fmt.Sprintf("  Device detected: %s\n", devices[0]))
		s.WriteString(fmt.Sprintf("  Run: adb shell settings put global http_proxy %s:%s\n", 
			guide.ProxyIP, guide.ProxyPort))
		s.WriteString("  To remove: adb shell settings put global http_proxy :0\n")
	} else {
		s.WriteString("  ⚠️  No ADB device detected. Connect device and enable USB debugging.\n")
	}

	s.WriteString("\n🔐 Step 3: Install CA Certificate\n")
	s.WriteString(strings.Repeat("─", 60) + "\n")
	
	if guide.ProxyType == "mitmproxy" {
		s.WriteString("  1. On Android, open browser to: http://mitm.it\n")
		s.WriteString("  2. Download Android certificate\n")
		s.WriteString("  3. Settings → Security → Install from storage\n")
		s.WriteString("  4. Select downloaded certificate\n")
		s.WriteString("  5. Name it 'mitmproxy' and select VPN and apps\n")
	} else {
		s.WriteString("  1. Export Burp CA cert: Proxy → Options → Import/Export CA cert\n")
		s.WriteString("  2. Save as DER format\n")
		s.WriteString("  3. Push to device: adb push burp-cert.der /sdcard/\n")
		s.WriteString("  4. Settings → Security → Install from storage\n")
		s.WriteString("  5. Select burp-cert.der, name it 'Burp Suite'\n")
	}

	s.WriteString("\n⚠️  For Android 7+ (Nougat and above):\n")
	s.WriteString("  Apps ignore user certificates by default.\n")
	s.WriteString("  Solutions:\n")
	s.WriteString("    • Modify APK network security config (see APK Injector)\n")
	s.WriteString("    • Use rooted device to install as system cert\n")
	s.WriteString("    • Add to /system/etc/security/cacerts/\n")

	s.WriteString("\n🔍 Step 4: Test Traffic Capture\n")
	s.WriteString(strings.Repeat("─", 60) + "\n")
	s.WriteString("  1. Open app on device\n")
	s.WriteString("  2. Check proxy tool for intercepted traffic\n")
	s.WriteString("  3. If HTTPS fails, app may use SSL pinning\n")

	s.WriteString("\n🛡️  SSL Pinning Detection:\n")
	s.WriteString(strings.Repeat("─", 60) + "\n")
	s.WriteString("  If app refuses HTTPS connections after proxy setup:\n")
	s.WriteString("    • App likely uses certificate pinning\n")
	s.WriteString("    • Bypass options:\n")
	s.WriteString("      - Frida with SSL pinning bypass script\n")
	s.WriteString("      - Objection: objection --gadget <package> explore\n")
	s.WriteString("      - Xposed modules (rooted device)\n")
	s.WriteString("      - Patch APK to disable pinning\n")

	s.WriteString("\n💡 Useful ADB Commands:\n")
	s.WriteString(strings.Repeat("─", 60) + "\n")
	s.WriteString("  • List packages: adb shell pm list packages\n")
	s.WriteString("  • Get app path: adb shell pm path <package>\n")
	s.WriteString("  • Pull APK: adb pull /data/app/<package>/base.apk\n")
	s.WriteString("  • Check proxy: adb shell settings get global http_proxy\n")
	
	s.WriteString("\n" + strings.Repeat("─", 60) + "\n")
	s.WriteString("✓ Network capture setup guide complete!\n")
	s.WriteString("  For more help, refer to OWASP Mobile Security Testing Guide\n")
	
	return s.String()
}

// SetupADBProxy configures Android device to use proxy via ADB
func SetupADBProxy(proxyIP, proxyPort string) error {
	devices, err := GetConnectedDevices()
	if err != nil {
		return fmt.Errorf("failed to get devices: %v", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("no Android devices connected via ADB")
	}

	fmt.Printf("Setting proxy on device: %s\n", devices[0])
	
	cmd := exec.Command("adb", "shell", "settings", "put", "global", "http_proxy", 
		fmt.Sprintf("%s:%s", proxyIP, proxyPort))
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set proxy: %v", err)
	}

	fmt.Println("✓ Proxy configured successfully")
	fmt.Printf("  Proxy: %s:%s\n", proxyIP, proxyPort)
	fmt.Println("\nTo remove proxy, run:")
	fmt.Println("  adb shell settings put global http_proxy :0")
	
	return nil
}

// RemoveADBProxy removes proxy configuration from Android device
func RemoveADBProxy() error {
	cmd := exec.Command("adb", "shell", "settings", "put", "global", "http_proxy", ":0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove proxy: %v", err)
	}

	fmt.Println("✓ Proxy configuration removed")
	return nil
}

// CheckSSLPinning tests if app uses SSL pinning
func CheckSSLPinning(packageName string) {
	fmt.Printf("\n🔍 Checking SSL Pinning for: %s\n", packageName)
	fmt.Println(strings.Repeat("─", 60))
	
	fmt.Println("Manual Test Steps:")
	fmt.Println("  1. Ensure proxy is configured (see network capture guide)")
	fmt.Println("  2. Open the app")
	fmt.Println("  3. Try to perform HTTPS requests")
	fmt.Println("\nResults:")
	fmt.Println("  ✓ Traffic visible in proxy → No pinning or bypassed")
	fmt.Println("  ✗ Network error/connection failed → SSL pinning detected")
	
	fmt.Println("\nAutomated Detection (requires Frida):")
	fmt.Println("  frida -U -f " + packageName + " -l ssl-pinning-bypass.js")
	fmt.Println("\nOr use Objection:")
	fmt.Println("  objection -g " + packageName + " explore")
	fmt.Println("  > android sslpinning disable")
}
