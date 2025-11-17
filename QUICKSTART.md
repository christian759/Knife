# ⚡ Knife Quick Start Guide

Get up and running with Knife in under 5 minutes!

## 🎯 Prerequisites

```bash
# Required
- Go 1.23 or later
- libpcap-dev (for packet operations)
- iw (for WiFi operations)

# Optional
- uber-apk-signer (for APK signing)
- ADB (for Android monitoring)
```

## 📦 Installation

```bash
# 1. Clone and enter directory
git clone https://github.com/yourusername/knife.git
cd knife

# 2. Install dependencies (Debian/Ubuntu)
sudo apt install libpcap-dev iw

# 3. Build
go build -v

# 4. Run!
./knife
```

## 🚀 First Run

### Launch Knife
```bash
./knife
```

You'll see the beautiful main menu:
```
🔪 KNIFE - Penetration Testing Toolkit
Select a module to begin

📋 Available Modules

  ➤ Mobile attack
  • Phishing
  • Web vulnerability
  • Wifi attack
```

### Navigation Basics
- **↑/↓**: Navigate between options
- **Enter**: Select current option
- **q or Esc**: Go back / quit
- **Ctrl+C**: Force quit

## 🎓 Try Your First Module

### Example 1: Web Vulnerability Scanner

1. Launch Knife: `./knife`
2. Select "Web vulnerability" (arrow down, press Enter)
3. Enter target URL: `http://testphp.vulnweb.com`
4. Enter "N" for custom headers
5. Enter "N" for cookies
6. Press Enter to start scan
7. Report saved to your home directory!

### Example 2: Phishing Server

1. Launch Knife: `./knife`
2. Select "Phishing"
3. Choose "Facebook" template
4. Server starts on port 8080
5. Visit http://localhost:8080 in browser
6. Credentials logged to `phishing_creds.txt`
7. Press Ctrl+C to stop server

### Example 3: WiFi Scanner

```bash
# WiFi operations need root
sudo ./knife
```

1. Select "Wifi attack"
2. Select "Scanner"
3. Wait for scan to complete
4. View discovered networks!

## 🎨 Interface Tips

### Lists
- Use `/` to filter/search
- Arrow keys to navigate
- Enter to select

### Forms
- Tab to move to next field
- Shift+Tab to move to previous field
- Enter on last field submits form

### File Picker (APK Injector)
- Arrow keys to browse
- Enter to select file/folder
- Ctrl+T to toggle text input mode

## 🔒 Security Notes

⚠️ **IMPORTANT**: This is a penetration testing tool!

- ✅ Only use on systems you own or have permission to test
- ✅ Many WiFi features require root/sudo privileges
- ✅ Some operations may be illegal without authorization
- ✅ Always follow your local laws and regulations

## 📚 Learn More

### Documentation
- **README.md** - Complete feature list and installation
- **SCREENSHOTS.md** - Visual guide with examples
- **WARP.md** - Architecture and developer guide
- **CHANGELOG.md** - Version history

### Key Features by Module

**📱 Mobile Attack**
- APK payload injection
- APK analysis and reconnaissance
- Android process monitoring

**🎣 Phishing**
- 5 pre-built templates (Facebook, Gmail, Instagram, Netflix, Outlook)
- Automatic credential logging
- Geolocation enrichment

**🌐 Web Vulnerability**
- XSS, SQLi, LFI, RCE detection
- Custom headers and cookies
- HTML vulnerability reports

**📡 WiFi Attack**
- Deauth attacks
- Evil twin AP creation
- Handshake/PMKID capture
- MAC spoofing
- Network scanning
- And much more!

## 🐛 Troubleshooting

### Build Issues

**Problem**: `missing go.sum entry`
```bash
Solution: go mod download
```

**Problem**: `libpcap not found`
```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# Fedora
sudo dnf install libpcap-devel
```

### Runtime Issues

**Problem**: WiFi module doesn't detect interfaces
```bash
# Run with sudo
sudo ./knife

# Check if wireless interface exists
iw dev
```

**Problem**: APK signing fails
```bash
# Install uber-apk-signer
# Download from: https://github.com/patrickfav/uber-apk-signer
# Add to PATH
```

## 🎯 Next Steps

1. ✅ Try all four modules
2. ✅ Read the full README for detailed features
3. ✅ Check SCREENSHOTS.md for advanced usage
4. ✅ Contribute or report issues on GitHub
5. ✅ Stay ethical and legal!

## 💡 Pro Tips

1. **Use Filtering**: Press `/` in any list to quickly find items
2. **Tab Navigation**: Keep hands on keyboard with Tab key navigation
3. **File Picker Toggle**: Ctrl+T switches between picker and text input
4. **Terminal Size**: Resize terminal anytime - UI adapts automatically
5. **Color Themes**: UI adapts to your terminal's light/dark theme

## 🆘 Getting Help

- Check documentation files in this directory
- Review examples in SCREENSHOTS.md
- Read error messages - they're helpful!
- Check system logs for WiFi/network issues

## 🎉 Have Fun!

Knife is designed to make penetration testing accessible and enjoyable. The modern TUI makes complex operations simple and intuitive.

**Remember**: With great power comes great responsibility. Always use ethically and legally!

---

**Quick Links**
- [Full Documentation](README.md)
- [Visual Guide](SCREENSHOTS.md)
- [Architecture](WARP.md)
- [Changelog](CHANGELOG.md)

**Get Started Now**: `./knife` 🚀
