# 🔪 Knife - Penetration Testing Toolkit

A modern, terminal-based penetration testing toolkit built with Go and [Bubble Tea](https://github.com/charmbracelet/bubbletea). Knife provides an intuitive TUI for various security testing operations across mobile, web, WiFi, and social engineering domains.

![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-Educational-red?style=flat)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux)

## ✨ Features

### 📱 Mobile Attack
- **APK Injector**: Inject payloads into Android APK files with interactive file picker
- **APK Reconnaissance**: Analyze APK metadata, permissions, and structure
- **Process Monitor**: Monitor Android device processes via ADB

### 🎣 Phishing
- **Multi-Template Server**: Pre-built phishing templates for popular services:
  - Facebook
  - Gmail
  - Instagram
  - Netflix
  - Outlook
- **Credential Logging**: Automatic credential capture with geolocation enrichment
- **One-Click Launch**: Select template and launch HTTP server instantly

### 🌐 Web Vulnerability Scanner
- **Automated Testing**: Scan for common vulnerabilities:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
  - Open Redirect
  - Command Injection
- **Custom Headers & Cookies**: Support for authenticated testing
- **HTML Reports**: Detailed vulnerability reports with severity ratings

### 📡 WiFi Attack Suite
- **Deauthentication Attack**: Disconnect clients from access points
- **Evil Twin**: Create rogue access points
- **Handshake Capture**: Capture WPA/WPA2 handshakes for offline cracking
- **PMKID Capture**: Extract PMKIDs for hashcat cracking
- **Beacon Flooding**: Flood area with fake SSIDs
- **Packet Sniffer**: Capture and analyze WiFi packets
- **Probe Request Sniffer**: Monitor device probe requests
- **MAC Spoofing**: Randomize MAC addresses
- **Interface Management**: Monitor mode control and interface configuration
- **Geolocation**: Locate access points using Google Geolocation API
- **Network Scanner**: Discover nearby WiFi networks

## 🎨 Modern TUI

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lipgloss](https://github.com/charmbracelet/lipgloss), Knife features:

- ✅ Keyboard-driven navigation
- ✅ Responsive layouts that adapt to terminal size
- ✅ Adaptive color themes (light/dark mode)
- ✅ Interactive file picker for APK selection
- ✅ Multi-field forms with tab navigation
- ✅ List selection with filtering
- ✅ Real-time AP scanning and selection
- ✅ Consistent styling across all modules

## 📦 Installation

### Prerequisites

```bash
# Install Go 1.23 or later
# Install system dependencies
sudo apt install libpcap-dev iw  # Debian/Ubuntu
sudo dnf install libpcap-devel iw  # Fedora

# Optional: For APK signing
# Download uber-apk-signer from https://github.com/patrickfav/uber-apk-signer
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/knife.git
cd knife

# Download dependencies
go mod download

# Build
go build -v

# Run
./knife
```

## 🚀 Usage

### Quick Start

```bash
# Launch Knife
./knife

# Navigate with arrow keys
# Press Enter to select a module
# Use Tab to navigate between form fields
# Press q or Esc to go back
# Press Ctrl+C to quit
```

### Module-Specific Usage

#### Mobile Attack

```bash
# APK Injector
1. Select "Mobile attack" → "Injector"
2. Use file picker or type path to select APK
3. Select payload (.dex file)
4. Enter output path inside APK (e.g., assets/payload.dex)
5. Knife will inject and sign the APK

# Note: Requires uber-apk-signer in PATH
```

#### Phishing

```bash
# Launch Phishing Server
1. Select "Phishing"
2. Choose template (Facebook, Gmail, etc.)
3. Server starts on http://localhost:8080
4. Credentials logged to phishing_creds.txt with geolocation
```

#### Web Vulnerability Scanner

```bash
# Scan Website
1. Select "Web vulnerability"
2. Enter target URL
3. Optionally add custom headers (for authentication)
4. Optionally add cookies
5. Report saved to ~/target_report_timestamp.html
```

#### WiFi Attacks

```bash
# Most WiFi operations require root/sudo privileges

# Deauth Attack
sudo ./knife
1. Select "Wifi attack" → "Deauth"
2. Auto-scan and select target AP
3. Enter target MAC or broadcast address
4. Set packet count

# Evil Twin
sudo ./knife
1. Select "Wifi attack" → "Evil Twin"
2. Enter interface and SSID to fake
3. Press Enter when done to stop

# Handshake Capture
sudo ./knife
1. Select "Wifi attack" → "Handshake"
2. Enter interface and output file
3. Set timeout (seconds)
4. Use captured .pcap with hashcat or aircrack-ng
```

## 🏗️ Architecture

```
knife/
├── main.go              # Entry point with main menu
├── tui/
│   └── styles.go       # Centralized styling (colors, fonts, components)
├── modules/
│   ├── mobile/
│   │   ├── tui.go      # File picker + forms
│   │   ├── injector.go # APK injection logic
│   │   ├── recon.go    # APK analysis
│   │   └── monitor_process.go
│   ├── phish/
│   │   ├── tui.go      # Template selection
│   │   ├── phishing.go # HTTP server + logging
│   │   └── templates/  # HTML templates
│   ├── vuln/
│   │   ├── tui.go      # Multi-step forms
│   │   ├── vuln.go     # Scanner engine
│   │   └── report.go   # HTML report generator
│   └── wifi/
│       ├── tui.go      # Comprehensive TUI with AP picker
│       ├── cli.go      # Core handlers
│       └── *.go        # Attack implementations
└── util/
    └── helper.go       # Utilities
```

## 🎯 Roadmap

- [ ] Add tests for all modules
- [ ] Bluetooth attack module
- [ ] Network scanning module (Nmap integration)
- [ ] Password cracking module
- [ ] Metasploit integration
- [ ] Report export (PDF, JSON)
- [ ] Configuration file support
- [ ] Plugin system for custom modules

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- ✅ Penetration testing with proper authorization
- ✅ Security research in controlled environments
- ✅ Educational purposes and learning
- ✅ Personal network security auditing

**UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL**

You must:
- Obtain written permission before testing any network/system
- Comply with all applicable laws and regulations
- Use this tool ethically and responsibly
- Respect privacy and data protection laws

The authors are not responsible for misuse or damage caused by this tool.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow existing code style and TUI patterns
4. Use shared styles from `tui/styles.go`
5. Implement Bubble Tea models for new TUI components
6. Test thoroughly
7. Submit a Pull Request

## 📚 Resources

- [Bubble Tea Documentation](https://github.com/charmbracelet/bubbletea)
- [Lipgloss Styling](https://github.com/charmbracelet/lipgloss)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [WiFi Security Testing](https://www.aircrack-ng.org/)

## 📄 License

This project is for educational purposes only. Use at your own risk.

## 🙏 Acknowledgments

- [Bubble Tea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [Lipgloss](https://github.com/charmbracelet/lipgloss) - Style definitions
- [gopacket](https://github.com/google/gopacket) - Packet processing
- The security research community

---

Made with ❤️ and Go | Stay ethical, stay legal
