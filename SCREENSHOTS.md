# 📸 Knife TUI Screenshots & Navigation Guide

This document provides a visual walkthrough of the Knife TUI interface and its features.

## 🏠 Main Menu

```
🔪 KNIFE - Penetration Testing Toolkit
Select a module to begin

📋 Available Modules

  ➤ Mobile attack
    APK injection, reconnaissance, and monitoring
    
    Phishing
    Multi-template phishing server (Facebook, Gmail, Instagram, Netflix, Outlook)
    
    Web vulnerability
    Automated web vulnerability scanner (XSS, SQLi, LFI, RCE)
    
    Wifi attack
    WiFi security testing tools (Deauth, Evil Twin, Handshake, etc.)
```

**Navigation:**
- ↑/↓: Move between modules
- Enter: Select module
- q/Ctrl+C: Quit

---

## 📱 Mobile Attack Module

### Action Selection
```
🤖 Mobile Attack Tools

  ➤ Injector
    Inject payload into APK (requires uber-apk-signer)
    
    Recon
    Analyze APK metadata and structure
    
    Monitor
    Monitor Android device processes (requires ADB)
```

### APK Injector - File Picker
```
🔪 APK Injector

Step 1/3: Select APK file

✅ APK: /home/user/target.apk

📁 Current directory: /home/user
  ..
  ➤ Downloads/
    Documents/
    target.apk
    payload.dex

ctrl+t: switch to text input • q: quit
```

### APK Injector - Text Input Mode
```
🔪 APK Injector

Step 3/3: Enter output path inside APK

✅ APK: /home/user/target.apk
✅ Payload: /home/user/payload.dex

Path: ┃assets/payload.dex                                   ┃

ctrl+t: switch to file picker • enter: confirm • q: quit
```

---

## 🎣 Phishing Module

```
🎣 Phishing Templates

  ➤ Facebook
    Facebook login page phishing template
    
    Gmail
    Gmail login page phishing template
    
    Instagram
    Instagram login page phishing template
    
    Netflix
    Netflix login page phishing template
    
    Outlook
    Outlook login page phishing template
```

**After Selection:**
```
ℹ️  Starting Facebook phishing server on port 8080...
⚠️  Credentials will be logged to phishing_creds.txt

[Server Running...]
```

---

## 🌐 Web Vulnerability Scanner

### Main Form
```
🔪 Website Vulnerability Scanner

This tool checks for common web vulnerabilities like XSS, SQLi, LFI, etc.

Target URL: 
┃http://testsite.com/vulnerable.php?id=1                   ┃

Add custom headers? (Y/N): 
┃N                                                           ┃

Add cookies? (Y/N): 
┃N                                                           ┃

tab: next field • enter: submit • q/esc: quit
```

### Header Entry
```
🔪 Add Custom Headers

Enter each header in 'Key: Value' format. Leave blank to finish.

ℹ️  Current headers:
  • Authorization: Bearer token123
  • X-API-Key: abc456

Header: 
┃User-Agent: Custom UA                                      ┃

enter: add header (or finish if empty) • q/esc: cancel
```

### Cookie Entry
```
🔪 Add Cookies

Enter cookies in the format: key1=val1; key2=val2

Cookies: 
┃session=xyz789; user_id=123                                ┃

enter: submit • q/esc: cancel
```

---

## 📡 WiFi Attack Module

### Attack Selection
```
📡 WiFi Attack Tools

  ➤ Deauth
    Deauthentication attack on selected AP
    
    Evil Twin
    Create rogue access point
    
    Geo-locate
    Geolocate AP using Google API
    
    Handshake
    Capture WPA handshake
    
    Injector
    Beacon frame flooding
    
    [... more options ...]
```

### Access Point Selection
```
📡 Select AP for Deauth Attack

  ➤ HomeNetwork (-45.0 dBm)
    BSSID: aa:bb:cc:dd:ee:ff
    
    OfficeWiFi (-52.0 dBm)
    BSSID: 11:22:33:44:55:66
    
    <hidden> (-68.0 dBm)
    BSSID: ff:ee:dd:cc:bb:aa
```

### Deauth Attack Form
```
🔪 Deauth Attack

Target: HomeNetwork (aa:bb:cc:dd:ee:ff)

Target MAC (or ff:ff:ff:ff:ff:ff for broadcast): 
┃ff:ff:ff:ff:ff:ff                                          ┃

Packet Count: 
┃100                                                         ┃

tab: next field • enter: submit • q/esc: quit
```

### Evil Twin Form
```
🔪 Evil Twin Attack

Create a rogue access point

Interface: 
┃wlan0                                                       ┃

SSID to fake: 
┃FreePublicWiFi                                             ┃

tab: next field • enter: submit • q/esc: quit
```

### Handshake Capture Form
```
🔪 Handshake Capture

Capture WPA handshake for offline cracking

Interface: 
┃wlan0                                                       ┃

Output file: 
┃handshake.pcap                                             ┃

Timeout (seconds): 
┃60                                                          ┃

tab: next field • enter: submit • q/esc: quit
```

---

## 🎨 Color Themes

The TUI adapts to your terminal's color scheme:

### Light Mode
- Primary: Red (#FF0000)
- Secondary: Blue (#0000FF)
- Accent: Green (#00FF00)
- Text: Dark Gray (#1A1A1A)

### Dark Mode
- Primary: Light Red (#FF6B6B)
- Secondary: Cyan (#4ECDC4)
- Accent: Mint (#95E1D3)
- Text: White (#FAFAFA)

---

## ⌨️ Global Keyboard Shortcuts

| Key | Action |
|-----|--------|
| ↑/↓ | Navigate lists |
| ←/→ | (Future: navigate tabs) |
| Enter | Select/Submit |
| Tab | Next field in forms |
| Shift+Tab | Previous field in forms |
| Ctrl+T | Toggle file picker/text input (mobile module) |
| q | Quit/Back |
| Esc | Quit/Back |
| Ctrl+C | Force quit |
| / | Search/Filter (in lists) |

---

## 💡 Pro Tips

### Navigation
- Use `/` to quickly filter long lists (APs, templates)
- Hold Shift with Tab to navigate backwards in forms
- Press Esc to go back without confirming changes

### File Picker
- Navigate directories with arrow keys
- Press Ctrl+T to switch to text input if file browser is slow
- Use text input mode for absolute paths outside current directory

### WiFi Operations
- Scanner automatically selects strongest AP for deauth
- Use filtering in AP list to find specific networks
- Most operations auto-detect wireless interfaces

### Forms
- Tab through fields without lifting hands from keyboard
- Press Enter on last field to submit immediately
- Invalid input is validated on submission

---

## 🚀 Performance Notes

- List rendering is optimized for 1000+ items
- File picker caches directory listings
- AP scanning runs in background goroutines
- Terminal size changes trigger automatic reflow

---

## 📝 Taking Screenshots

To capture Knife in action:

```bash
# Using asciinema (recommended)
asciinema rec knife-demo.cast
./knife
# [perform actions]
# Ctrl+D to stop recording

# Using script
script -c "./knife" knife-demo.txt

# Using screenshot tools
# Take terminal screenshot with:
# - flameshot (GUI)
# - import (ImageMagick)
# - gnome-screenshot
```

---

**Note:** Actual colors and styling may vary based on your terminal emulator and theme configuration.
