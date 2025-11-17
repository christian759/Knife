# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Knife is a Go-based penetration testing toolkit with four main modules:
- **Mobile attack**: APK injection, reconnaissance, and monitoring
- **Phishing**: Multi-template phishing server (Facebook, Gmail, Instagram, Netflix, Outlook)
- **Web vulnerability**: Automated web vulnerability scanner
- **Wifi attack**: Comprehensive WiFi security testing tools

## Build & Development Commands

### Building
```bash
go build -v ./...
```

This produces an executable named `knife` in the project root.

### Running
```bash
./knife
```

The main program presents an interactive menu system for selecting modules and sub-tools.

### Testing
```bash
go test -v ./...
```

Note: Currently no test files exist in the repository.

### Dependencies
```bash
go mod download
```

Key dependencies:
- `github.com/google/gopacket` - Packet capture and processing
- `github.com/charmbracelet/bubbletea` - Modern TUI framework
- `github.com/charmbracelet/bubbles` - TUI components (list, textinput, filepicker)
- `github.com/charmbracelet/lipgloss` - Style definitions and rendering
- System requirement: `libpcap-dev` (for packet manipulation features)

### CI/CD
GitHub Actions workflow (`.github/workflows/go.yml`) automatically:
- Builds on push/PR to master
- Requires Go 1.23+
- Installs libpcap-dev before building

## Architecture

### Module System
The application follows a clean modular architecture with modern TUI:

```
main.go                          # Entry point with Bubble Tea TUI and module router
├── tui/
│   └── styles.go               # Centralized lipgloss styles and rendering utilities
├── modules/
│   ├── mobile/                  # Android APK manipulation
│   │   ├── tui.go              # Bubble Tea TUI with file picker
│   │   ├── injector.go         # APK payload injection (passive - doesn't auto-execute)
│   │   ├── recon.go            # APK reconnaissance
│   │   └── monitor_process.go # Device monitoring
│   ├── phish/                  # Phishing infrastructure
│   │   ├── tui.go              # Bubble Tea template selection
│   │   ├── phishing.go         # HTTP server + credential logging with geo-location
│   │   └── templates/          # HTML/CSS templates per service
│   ├── vuln/                   # Web vulnerability scanner
│   │   ├── tui.go              # Bubble Tea multi-form interface
│   │   ├── vuln.go             # Scanner engine (XSS, SQLi, LFI, RCE, etc.)
│   │   └── report.go           # HTML report generation
│   └── wifi/                   # WiFi attack suite
│       ├── tui.go              # Comprehensive Bubble Tea TUI with AP selection
│       ├── cli.go              # Legacy CLI handlers (still used by TUI)
│       ├── general.go          # Interface detection + AP scanning
│       ├── deauth.go           # Deauth attack (simulator)
│       ├── evil_twin.go        # Rogue AP
│       ├── geolocate.go        # Google Geolocation API integration
│       ├── handshake.go        # WPA handshake capture
│       ├── injector.go         # Beacon flooding
│       ├── interface.go        # Interface management
│       ├── mac_spoofer.go      # MAC address randomization
│       ├── pmkid.go            # PMKID capture
│       ├── probSniff.go        # Probe request sniffing
│       └── scanner.go          # Network scanning
└── util/
    └── helper.go               # Random string generation
```

### Key Architectural Patterns

**1. Module Isolation**
Each module (mobile, phish, vuln, wifi) is self-contained with its own `tui.go` for user interaction and implementation files for core logic.

**2. Modern TUI Architecture (Bubble Tea)**
- `main.go` displays styled title and top-level module menu using Bubble Tea
- Each module has dedicated TUI models implementing the `tea.Model` interface
- User interaction through keyboard navigation (arrows, enter, tab, etc.)
- Centralized styling via `tui/styles.go` with adaptive light/dark themes
- Responsive layouts that adapt to terminal size

**3. TUI Component Patterns**
- **List models**: For menu selection (modules, actions, APs)
- **Form models**: Multi-field input with tab navigation and validation
- **File picker**: Interactive file browser for APK/payload selection
- **Text input**: Single-field input with placeholders and styling
- All TUI components use consistent styling from `tui/styles.go`

**4. WiFi Module Auto-Detection**
The WiFi module automatically:
- Detects wireless interfaces via `GetWirelessInterfaces()` 
- Scans for nearby APs using `iw dev <iface> scan`
- Selects strongest AP for deauth attacks
- Parses BSSID, SSID, and signal strength from `iw` output

**5. Phishing Module Design**
- HTTP server on port 8080
- Logs credentials to `phishing_creds.txt`
- Enriches logs with IP geolocation via ip-api.com
- Templates stored in `modules/phish/templates/<service>/index.html`

**6. Vulnerability Scanner Pattern**
- Array of `VulnCheck` structs defines tests (payload + regex matcher)
- Supports both GET and POST methods
- Generates timestamped HTML reports in user's home directory
- No redirect following for open redirect detection

**7. Mobile Module Limitations**
**IMPORTANT**: The APK injector (`injector.go`) passively injects `.dex` files into APK archives but:
- Does NOT auto-execute on device
- Does NOT establish reverse shells
- Does NOT hook into app lifecycle
- Requires manual APK signing with `uber-apk-signer`

## File Dependencies

### External Tools Required
- `iw` - WiFi interface scanning (wifi module)
- `uber-apk-signer` - APK signing (mobile module)
- `libpcap` - Packet capture library

### Data Files
- `letters.txt` - ASCII art font data for banner
- `phishing_creds.txt` - Output log for captured credentials

## Code Conventions

### Error Handling
- Most functions return `error` as last return value
- CLI handlers print errors directly and return early
- Network operations use 15-second timeouts

### Concurrency
- WiFi scanner uses goroutines with `sync.WaitGroup` for parallel interface scanning
- Packet capture uses gopacket's `PacketSource` for streaming

### System Commands
Heavy reliance on `os/exec` for:
- `stty size` - Terminal dimensions
- `iw` commands - WiFi operations
- `uber-apk-signer` - APK signing

### Regex Patterns
Vulnerability scanner uses case-insensitive regex matching with `(?i)` prefix for detection.

## Development Notes

### Adding New Modules
1. Create new directory under `modules/`
2. Implement `tui.go` with Bubble Tea models
3. Add module to `main.go` module list
4. Use shared styles from `tui/styles.go`

### Adding New Phishing Templates
1. Create directory: `modules/phish/templates/<ServiceName>/`
2. Add `index.html` with form posting to `/log`
3. Form fields must be named `email` and `pass`
4. Add new `templateItem` to `RunPhishModule()` in `modules/phish/tui.go`

### Adding WiFi Attack Types
1. Implement handler function in appropriate `modules/wifi/*.go` file
2. Add `wifiActionItem` to `RunWifiModule()` in `modules/wifi/tui.go`
3. Add case to `handleWifiAction()` with corresponding `run*()` function

### Adding Vulnerability Checks
Add entry to `vulns` slice in `modules/vuln/vuln.go` with:
- Name, Param, Payload, Match (regex), Method

### Security Context
This is a penetration testing tool. Many operations require:
- Root/sudo privileges (WiFi monitoring, MAC spoofing, packet injection)
- Proper authorization before use on networks
- Ethical/legal compliance
