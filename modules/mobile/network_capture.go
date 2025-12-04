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

// DisplayNetworkCaptureInstructions shows setup guide for MITM proxy
func DisplayNetworkCaptureInstructions(guide NetworkCaptureGuide) {
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║      MOBILE NETWORK TRAFFIC CAPTURE SETUP GUIDE            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")

	fmt.Println("\n📱 Step 1: Setup Proxy Tool")
	fmt.Println(strings.Repeat("─", 60))
	
	if guide.ProxyType == "mitmproxy" {
		fmt.Println("Using mitmproxy:")
		fmt.Println("  1. Install: pip install mitmproxy")
		fmt.Println("  2. Start proxy: mitmproxy -p 8080")
		fmt.Println("  3. Or web interface: mitmweb -p 8080")
	} else {
		fmt.Println("Using Burp Suite:")
		fmt.Println("  1. Open Burp Suite")
		fmt.Println("  2. Go to Proxy → Options")
		fmt.Println("  3. Ensure proxy listener is on 0.0.0.0:8080")
		fmt.Println("  4. Enable invisible proxying (optional)")
	}

	fmt.Println("\n🔧 Step 2: Configure Android Device Proxy")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Manual Configuration:\n")
	fmt.Println("  1. Settings → Wi-Fi → Long press network → Modify")
	fmt.Println("  2. Advanced options → Proxy: Manual")
	fmt.Printf("  3. Proxy hostname: %s\n", guide.ProxyIP)
	fmt.Printf("  4. Proxy port: %s\n", guide.ProxyPort)
	fmt.Println("  5. Save")

	fmt.Println("\nADB Configuration (Alternative):")
	devices, _ := GetConnectedDevices()
	if len(devices) > 0 {
		fmt.Printf("  Device detected: %s\n", devices[0])
		fmt.Printf("  Run: adb shell settings put global http_proxy %s:%s\n", 
			guide.ProxyIP, guide.ProxyPort)
		fmt.Println("  To remove: adb shell settings put global http_proxy :0")
	} else {
		fmt.Println("  ⚠️  No ADB device detected. Connect device and enable USB debugging.")
	}

	fmt.Println("\n🔐 Step 3: Install CA Certificate")
	fmt.Println(strings.Repeat("─", 60))
	
	if guide.ProxyType == "mitmproxy" {
		fmt.Println("  1. On Android, open browser to: http://mitm.it")
		fmt.Println("  2. Download Android certificate")
		fmt.Println("  3. Settings → Security → Install from storage")
		fmt.Println("  4. Select downloaded certificate")
		fmt.Println("  5. Name it 'mitmproxy' and select VPN and apps")
	} else {
		fmt.Println("  1. Export Burp CA cert: Proxy → Options → Import/Export CA cert")
		fmt.Println("  2. Save as DER format")
		fmt.Println("  3. Push to device: adb push burp-cert.der /sdcard/")
		fmt.Println("  4. Settings → Security → Install from storage")
		fmt.Println("  5. Select burp-cert.der, name it 'Burp Suite'")
	}

	fmt.Println("\n⚠️  For Android 7+ (Nougat and above):")
	fmt.Println("  Apps ignore user certificates by default.")
	fmt.Println("  Solutions:")
	fmt.Println("    • Modify APK network security config (see APK Injector)")
	fmt.Println("    • Use rooted device to install as system cert")
	fmt.Println("    • Add to /system/etc/security/cacerts/")

	fmt.Println("\n🔍 Step 4: Test Traffic Capture")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println("  1. Open app on device")
	fmt.Println("  2. Check proxy tool for intercepted traffic")
	fmt.Println("  3. If HTTPS fails, app may use SSL pinning")

	fmt.Println("\n🛡️  SSL Pinning Detection:")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println("  If app refuses HTTPS connections after proxy setup:")
	fmt.Println("    • App likely uses certificate pinning")
	fmt.Println("    • Bypass options:")
	fmt.Println("      - Frida with SSL pinning bypass script")
	fmt.Println("      - Objection: objection --gadget <package> explore")
	fmt.Println("      - Xposed modules (rooted device)")
	fmt.Println("      - Patch APK to disable pinning")

	fmt.Println("\n💡 Useful ADB Commands:")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println("  • List packages: adb shell pm list packages")
	fmt.Println("  • Get app path: adb shell pm path <package>")
	fmt.Println("  • Pull APK: adb pull /data/app/<package>/base.apk")
	fmt.Println("  • Check proxy: adb shell settings get global http_proxy")
	
	fmt.Println("\n" + strings.Repeat("─", 60))
	fmt.Println("✓ Network capture setup guide complete!")
	fmt.Println("  For more help, refer to OWASP Mobile Security Testing Guide")
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
