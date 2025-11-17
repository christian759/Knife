# Changelog

All notable changes to the Knife penetration testing toolkit will be documented in this file.

## [2.0.0] - 2025-11-17

### 🎉 Major Release: Modern TUI Architecture

This release represents a complete modernization of the Knife user interface, transitioning from basic CLI prompts to a beautiful, responsive terminal UI powered by Bubble Tea.

### ✨ New Features

#### Core TUI System
- **Centralized Styling**: New `tui/styles.go` with adaptive light/dark themes
- **Consistent Components**: Shared UI components across all modules
- **Keyboard Navigation**: Arrow keys, Enter, Tab, Esc for intuitive control
- **Responsive Design**: Layouts adapt to terminal size automatically

#### Mobile Module TUI
- **Interactive File Picker**: Browse and select APK/DEX files visually
- **Path Toggle**: Switch between file picker and text input with Ctrl+T
- **Multi-Step Wizard**: Guided 3-step process for APK injection
- **Real-time Feedback**: Visual confirmation of each selection step

#### Phishing Module TUI
- **Template Gallery**: Scrollable list of phishing templates with descriptions
- **One-Click Launch**: Select and launch servers instantly
- **Status Messages**: Clear feedback using styled messages

#### Vulnerability Scanner TUI
- **Multi-Form Interface**: Tab-navigated forms for target configuration
- **Header Builder**: Interactive header entry with live preview
- **Cookie Manager**: Dedicated interface for cookie configuration
- **Progress Indicators**: Visual feedback during scanning

#### WiFi Module TUI
- **AP Selector**: Interactive access point picker with signal strength
- **Auto-Detection**: Automatic wireless interface discovery
- **Form-Based Input**: Clean forms for all attack parameters
- **Live Scanning**: Real-time AP discovery with SSID/BSSID display
- **Comprehensive Coverage**: TUI for all 10 WiFi attack types

### 🔧 Technical Improvements

#### Dependencies
- Added `github.com/charmbracelet/bubbletea` v1.3.10
- Added `github.com/charmbracelet/bubbles` v0.21.0
- Added `github.com/charmbracelet/lipgloss` v1.1.0
- Updated filepicker API usage to v0.21.0

#### Architecture
- Migrated from `cli.go` to `tui.go` in all modules
- Implemented `tea.Model` interface for all interactive components
- Created reusable form, list, and picker patterns
- Centralized style management with color theming

#### Code Quality
- Removed deprecated CLI prompt code
- Consistent error handling with styled messages
- Better separation of concerns (UI vs logic)
- Improved user feedback throughout

### 📚 Documentation

#### New Files
- `README.md`: Comprehensive project overview with features and usage
- `CHANGELOG.md`: This file - tracking all changes
- Updated `WARP.md`: Reflects new TUI architecture

#### Updated Documentation
- Architecture diagrams showing TUI components
- Developer guide for adding new modules
- Style guide for UI consistency
- Keyboard shortcuts reference

### 🎨 User Experience

#### Visual Improvements
- Color-coded messages (success, error, warning, info)
- Emoji indicators for better visual scanning
- Bordered input fields with focus indicators
- Styled titles and subtitles throughout
- List items with descriptions and filtering

#### Navigation
- Consistent keyboard shortcuts across all modules
- Back navigation with Esc key
- Quick quit with Ctrl+C or 'q'
- Tab navigation for multi-field forms
- Arrow key selection for lists

#### Feedback
- Real-time validation messages
- Progress updates during long operations
- Clear error messages with actionable guidance
- Success confirmations with next steps

### 🔄 Breaking Changes

- Removed old CLI modules (replaced with TUI equivalents)
- Changed main menu from numbered options to arrow-key selection
- Module entry points now use `Run*Module()` instead of `Interact*()`
- File paths now use interactive picker instead of plain text input

### 🐛 Bug Fixes

- Fixed filepicker compatibility with bubbles v0.21.0
- Resolved DidSelectFile API usage
- Corrected go.mod dependency versions
- Fixed terminal size detection in responsive layouts

### 📦 Build & Install

No changes to build process:
```bash
go build -v
./knife
```

Binary size: ~17MB (increased slightly due to TUI dependencies)

### 🔮 Coming Soon

- [ ] Animated progress bars for scanning operations
- [ ] Multi-pane layouts for advanced workflows
- [ ] Command history and autocomplete
- [ ] Configurable keybindings
- [ ] Custom color themes
- [ ] Mouse support (optional)

---

## [1.0.0] - Initial Release

### Features
- Basic CLI-based penetration testing toolkit
- Mobile, Phishing, Vulnerability, and WiFi modules
- Text-based prompts for user input
- ASCII art branding

---

**Legend:**
- 🎉 Major Release
- ✨ New Features
- 🔧 Technical Improvements
- 📚 Documentation
- 🎨 User Experience
- 🔄 Breaking Changes
- 🐛 Bug Fixes
- 📦 Build & Install
- 🔮 Coming Soon
