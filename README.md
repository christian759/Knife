# 🔪 Knife - Penetration Testing Toolkit

A modern, terminal-based penetration testing toolkit built with Go and [Bubble Tea](https://github.com/charmbracelet/bubbletea). Knife provides an intuitive TUI for various security testing operations across mobile, web, WiFi, and social engineering domains.


![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-Educational-red?style=flat)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux)


## ✨ Features

### 📱 Mobile Attack
- **APK Injector**: Inject payloads into Android APK files with interactive file picker
- **APK Reconnaissance**: Analyze APK metadata, permissions, and structure
- **Process Monitor**: Monitor Android device processes via ADB

### 🎣 Phishing
- **Dual Phishing Modes**: 
  - **Web Page Phishing**: Clone login pages with live credential capture
  - **Email Phishing**: SMTP-based email campaigns
- **Pre-Built Templates**: 5 professional phishing page templates:
  - Facebook
  - Gmail
  - Instagram
  - Netflix
  - Outlook
- **Geolocation Tracking**: Automatic IP-based location detection (City, Region, Country, ISP)
- **Device Fingerprinting**: Capture User-Agent and browser information
- **Real-Time Logging**: Instant credential capture with timestamp and full context
- **One-Click Launch**: TUI-based template selection and instant HTTP server deployment

### 🌐 Web Vulnerability Scanner
- **Unified Scanning System**: Orchestrated vulnerability scanner with TUI-based scanner selection
- **9 Vulnerability Scanners**: Comprehensive automated testing for:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
  - Open Redirect
  - Command Injection
  - Server-Side Request Forgery (SSRF)
  - Cross-Site Request Forgery (CSRF)
  - Directory Traversal
  - XML External Entity (XXE)
- **Interactive Scanner Selection**: TUI for choosing which scanners to run
- **Custom Headers & Cookies**: Support for authenticated testing
- **Unified HTML Reports**: Consolidated vulnerability reports from all scanners with severity ratings
- **Real-Time Progress**: Live scan progress monitoring in terminal

### 📡 WiFi Attack Suite
- **10 Attack Modes**: Complete wireless security testing toolkit
  - **Deauthentication Attack**: Disconnect clients from access points
  - **Evil Twin**: Create rogue access points for credential harvesting
  - **Handshake Capture**: Capture WPA/WPA2 handshakes for offline cracking
  - **PMKID Capture**: Extract PMKIDs for hashcat cracking (clientless attack)
  - **Packet Injector**: Inject custom WiFi frames
  - **Packet Sniffer**: Capture and analyze WiFi traffic
  - **MAC Spoofing**: Randomize or spoof MAC addresses
  - **Interface Management**: Monitor mode control and interface configuration
  - **Geolocation**: Locate access points using Google Geolocation API
  - **Network Scanner**: Discover and enumerate nearby WiFi networks
- **Interactive AP Selection**: TUI-based access point picker with signal strength
- **Auto-Detection**: Automatic wireless interface discovery
- **Real-Time Monitoring**: Live network scanning with SSID/BSSID/Channel display

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
# Install Go 1.24 or later
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
# Web Page Phishing
1. Select "Phishing" → "Web Page Phishing"
2. Choose template (Facebook, Gmail, Instagram, Netflix, Outlook)
3. Server starts on http://0.0.0.0:8080
4. Victims captured with IP, location, user-agent, and credentials
5. Data logged to phishing_creds.txt with detailed geolocation

# Email Phishing
1. Select "Phishing" → "Email Phishing"
2. Configure SMTP settings and email template
3. Launch campaign
```

#### Web Vulnerability Scanner

```bash
# Scan Website
1. Select "Web vulnerability"
2. Choose which scanners to run (or select "All")
3. Enter target URL
4. Optionally add custom headers (for authentication)
5. Optionally add cookies
6. View real-time scan progress
7. Unified report saved to ~/target_report_timestamp.html
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
│   │   ├── tui.go          # TUI with file picker + forms
│   │   ├── injector.go     # APK injection logic
│   │   ├── recon.go        # APK analysis
│   │   └── monitor_process.go # Process monitoring
│   ├── phish/
│   │   ├── tui.go          # Phishing mode selection
│   │   ├── web/
│   │   │   ├── tui.go      # Web template selection
│   │   │   ├── phishing.go # HTTP server + credential logging
│   │   │   └── templates/  # HTML templates (Facebook, Gmail, Instagram, Netflix, Outlook)
│   │   └── mail/
│   │       ├── tui.go      # Email phishing TUI
│   │       └── email.go    # SMTP email logic
│   ├── vuln/
│   │   ├── tui.go              # Scanner selection TUI
│   │   ├── coordinator.go      # Unified scanner orchestration
│   │   ├── scanner_interface.go # Scanner interface definition
│   │   ├── vuln.go             # Main entry point
│   │   ├── xss.go              # XSS scanner
│   │   ├── sql.go              # SQL injection scanner
│   │   ├── lfi.go              # LFI scanner
│   │   ├── rce.go              # RCE scanner
│   │   ├── open_redirect.go    # Open redirect scanner
│   │   ├── command_injection.go # Command injection scanner
│   │   ├── ssrf.go             # SSRF scanner
│   │   ├── csrf.go             # CSRF scanner
│   │   ├── directory_traversal.go # Directory traversal scanner
│   │   ├── xxe.go              # XXE scanner
│   │   └── report.go           # Unified HTML report generator
│   └── wifi/
│       ├── tui.go          # Comprehensive TUI with AP picker
│       ├── deauth.go       # Deauth attack implementation
│       ├── evil_twin.go    # Evil twin AP
│       ├── handshake.go    # Handshake capture
│       ├── pmkid.go        # PMKID extraction
│       ├── injector.go     # Packet injection
│       ├── probSniff.go    # Packet sniffer
│       ├── mac_spoofer.go  # MAC address spoofing
│       ├── interface.go    # Interface management
│       ├── geolocate.go    # AP geolocation
│       ├── scanner.go      # Network scanner
│       └── general.go      # Common WiFi utilities
└── util/
    └── helper.go       # Utilities
```

## 🔄 Recent Improvements

### Major TUI Modernization (November-December 2024)

#### Vulnerability Scanner Unification (December 2024)
- ✅ **Unified Scanning System**: Comprehensive orchestration layer coordinating all 9 vulnerability scanners
- ✅ **Scanner Interface**: Standardized `Scanner` interface for consistent behavior across all scanners
- ✅ **Interactive TUI**: Scanner selection interface allowing users to choose specific scanners or run all
- ✅ **Consolidated Reporting**: Unified HTML report generator combining findings from all scanners with severity ratings
- ✅ **Channel Synchronization**: Fixed "panic: send on closed channel" errors across all scanners
- ✅ **Worker Management**: Implemented `Active` counter for proper goroutine lifecycle management
- ✅ **9 Complete Scanners**: XSS, SQLi, LFI, RCE, Open Redirect, Command Injection, SSRF, CSRF, Directory Traversal, XXE
- ✅ **Real-time Progress**: Live scan progress monitoring in terminal

#### Phishing Module Enhancement (December 2024)
- ✅ **Dual Mode Architecture**: Separated web page phishing and email phishing campaigns
- ✅ **5 Professional Templates**: Facebook, Gmail, Instagram, Netflix, Outlook login pages
- ✅ **Enhanced Logging**: Geolocation tracking with city, region, country, ISP details
- ✅ **Device Fingerprinting**: User-Agent and browser information capture
- ✅ **IP Geolocation API**: Integration with ip-api.com for real-time location lookup

#### Mobile Module Refinements
- ✅ **Interactive File Picker**: Visual APK and payload selection with Ctrl+T toggle
- ✅ **3-Step Wizard**: Guided injection process with clear state management
- ✅ **Path Flexibility**: Support for both file picker and manual path entry
- ✅ **Real-time Feedback**: Status updates at each injection step

#### WiFi Module Expansion
- ✅ **10 Attack Modes**: Complete wireless penetration testing suite
- ✅ **Interactive AP Selection**: Real-time access point scanning with signal strength display
- ✅ **Auto-Detection**: Automatic wireless interface discovery
- ✅ **PMKID Support**: Clientless WPA/WPA2 cracking capability
- ✅ **Form-Based TUI**: Clean interfaces for all attack configurations

#### Core TUI Framework (November 2024)
- ✅ **Bubble Tea Integration**: Modern terminal UI framework (v1.3.10)
- ✅ **Centralized Styling**: Shared `tui/styles.go` with adaptive light/dark themes
- ✅ **Keyboard Navigation**: Consistent shortcuts across all modules
- ✅ **Responsive Layouts**: Automatic adaptation to terminal size
- ✅ **Lipgloss Styling**: Beautiful, consistent visual design


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
