package mobile

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"knife/tui"
)

type mobileAction string

const (
	actionInjector       mobileAction = "Injector"
	actionDeepAnalysis   mobileAction = "APK Deep Analysis"
	actionRecon          mobileAction = "Recon"
	actionMonitor        mobileAction = "Monitor"
	actionLogcat         mobileAction = "Logcat Monitor"
	actionNetworkCapture mobileAction = "Network Capture"
	actionBackup         mobileAction = "Backup Extractor"
	actionSecurityScan   mobileAction = "Security Scanner"
)

type actionItem struct {
	title       string
	description string
}

func (i actionItem) Title() string       { return i.title }
func (i actionItem) Description() string { return i.description }
func (i actionItem) FilterValue() string { return i.title }

type mobileMenuModel struct {
	list   list.Model
	chosen string
}

func (m mobileMenuModel) Init() tea.Cmd {
	return nil
}

func (m mobileMenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter":
			if i, ok := m.list.SelectedItem().(actionItem); ok {
				m.chosen = i.title
			}
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		h, v := lipgloss.NewStyle().Margin(1, 2).GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m mobileMenuModel) View() string {
	return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
}

// File picker states
type filePickerState int

const (
	statePickAPK filePickerState = iota
	statePickPayload
	statePickOutput
	stateDone
)

type injectorModel struct {
	state        filePickerState
	filepicker   filepicker.Model
	textinput    textinput.Model
	apkPath      string
	payloadPath  string
	outputPath   string
	err          error
	quitting     bool
	useTextInput bool
}

func initialInjectorModel() injectorModel {
	fp := filepicker.New()
	fp.AllowedTypes = []string{".apk", ".dex"}
	fp.CurrentDirectory = "."

	ti := textinput.New()
	ti.Placeholder = "Enter path..."
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 50

	return injectorModel{
		state:        statePickAPK,
		filepicker:   fp,
		textinput:    ti,
		useTextInput: false,
	}
}

func (m injectorModel) Init() tea.Cmd {
	return m.filepicker.Init()
}

func (m injectorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "ctrl+t":
			// Toggle between filepicker and text input
			m.useTextInput = !m.useTextInput
			if m.useTextInput {
				m.textinput.Focus()
			}
			return m, nil
		case "enter":
			if m.useTextInput && m.textinput.Value() != "" {
				// Use text input value
				path := m.textinput.Value()
				switch m.state {
				case statePickAPK:
					m.apkPath = path
					m.state = statePickPayload
					m.textinput.SetValue("")
					m.textinput.Placeholder = "Enter payload path (.dex)..."
				case statePickPayload:
					m.payloadPath = path
					m.state = statePickOutput
					m.textinput.Placeholder = "Enter output path (e.g., assets/payload.dex)..."
				case statePickOutput:
					m.outputPath = path
					m.state = stateDone
					return m, tea.Quit
				}
				return m, nil
			}
		}
	}

	// Check if file was selected via filepicker
	if !m.useTextInput {
		if selected, path := m.filepicker.DidSelectFile(msg); selected {
			switch m.state {
			case statePickAPK:
				m.apkPath = path
				m.state = statePickPayload
				m.filepicker.CurrentDirectory = "."
				return m, m.filepicker.Init()
			case statePickPayload:
				m.payloadPath = path
				m.state = statePickOutput
				m.useTextInput = true
				m.textinput.Focus()
				m.textinput.Placeholder = "Enter output path inside APK (e.g., assets/payload.dex)..."
				return m, nil
			case statePickOutput:
				m.outputPath = path
				m.state = stateDone
				return m, tea.Quit
			}
		}

		if disabled, path := m.filepicker.DidSelectDisabledFile(msg); disabled {
			m.err = fmt.Errorf("file not allowed: %s", path)
			return m, nil
		}
	}

	var cmd tea.Cmd
	if m.useTextInput {
		m.textinput, cmd = m.textinput.Update(msg)
	} else {
		m.filepicker, cmd = m.filepicker.Update(msg)
	}
	return m, cmd
}

func (m injectorModel) View() string {
	if m.quitting {
		return ""
	}

	var s strings.Builder
	s.WriteString(tui.RenderTitle("APK Injector"))
	s.WriteString("\n\n")

	switch m.state {
	case statePickAPK:
		s.WriteString(tui.RenderSubtitle("Step 1/3: Select APK file"))
	case statePickPayload:
		s.WriteString(tui.RenderSubtitle("Step 2/3: Select payload file (.dex)"))
	case statePickOutput:
		s.WriteString(tui.RenderSubtitle("Step 3/3: Enter output path inside APK"))
	case stateDone:
		return ""
	}

	s.WriteString("\n\n")

	if m.apkPath != "" {
		s.WriteString(tui.RenderSuccess(fmt.Sprintf("APK: %s", m.apkPath)))
		s.WriteString("\n")
	}
	if m.payloadPath != "" {
		s.WriteString(tui.RenderSuccess(fmt.Sprintf("Payload: %s", m.payloadPath)))
		s.WriteString("\n")
	}

	s.WriteString("\n")

	if m.useTextInput {
		s.WriteString(tui.InputLabelStyle.Render("Path: "))
		s.WriteString(m.textinput.View())
		s.WriteString("\n\n")
		s.WriteString(tui.RenderHelp("ctrl+t: switch to file picker • enter: confirm • q: quit"))
	} else {
		s.WriteString(m.filepicker.View())
		s.WriteString("\n\n")
		s.WriteString(tui.RenderHelp("ctrl+t: switch to text input • q: quit"))
	}

	if m.err != nil {
		s.WriteString("\n\n")
		s.WriteString(tui.RenderError(m.err.Error()))
	}

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

type reconModel struct {
	textinput textinput.Model
	apkPath   string
	submitted bool
	err       error
}

func initialReconModel() reconModel {
	ti := textinput.New()
	ti.Placeholder = "Enter APK path..."
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 50

	return reconModel{
		textinput: ti,
	}
}

func (m reconModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m reconModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter":
			if m.textinput.Value() != "" {
				m.apkPath = m.textinput.Value()
				m.submitted = true
				return m, tea.Quit
			}
		}
	}

	m.textinput, cmd = m.textinput.Update(msg)
	return m, cmd
}

func (m reconModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("APK Reconnaissance"))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderSubtitle("Enter the path to the APK file"))
	s.WriteString("\n\n")
	s.WriteString(tui.InputLabelStyle.Render("APK Path: "))
	s.WriteString(m.textinput.View())
	s.WriteString("\n\n")
	s.WriteString(tui.RenderHelp("enter: analyze • q/esc: quit"))

	if m.err != nil {
		s.WriteString("\n\n")
		s.WriteString(tui.RenderError(m.err.Error()))
	}

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// ========== Logcat Configuration Model ==========

type logcatConfigModel struct {
	packageInput  textinput.Model
	levelList     list.Model
	focusedField  int
	submitted     bool
	config        LogcatConfig
}

func initialLogcatConfigModel() logcatConfigModel {
	// Package filter input
	pkgInput := textinput.New()
	pkgInput.Placeholder = "com.example.app (optional)"
	pkgInput.CharLimit = 256
	pkgInput.Width = 50

	// Log level selection
	levels := []list.Item{
		actionItem{title: "Info", description: "Info level (default)"},
		actionItem{title: "Verbose", description: "All logs including verbose"},
		actionItem{title: "Debug", description: "Debug and above"},
		actionItem{title: "Warning", description: "Warnings and errors only"},
		actionItem{title: "Error", description: "Errors only"},
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	levelList := list.New(levels, delegate, 0, 10)
	levelList.Title = "Log Level"
	levelList.Styles.Title = tui.TitleStyle
	levelList.SetShowStatusBar(false)
	levelList.SetFilteringEnabled(false)

	m := logcatConfigModel{
		packageInput: pkgInput,
		levelList:    levelList,
		focusedField: 0,
	}

	m.packageInput.Focus()
	return m
}

func (m logcatConfigModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m logcatConfigModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "tab", "shift+tab":
			if m.focusedField == 0 {
				m.focusedField = 1
				m.packageInput.Blur()
			} else {
				m.focusedField = 0
				m.packageInput.Focus()
			}
			return m, nil
		case "enter":
			if m.focusedField == 1 {
				// Submit
				levelMap := map[string]LogLevel{
					"Info":    LogInfo,
					"Verbose": LogVerbose,
					"Debug":   LogDebug,
					"Warning": LogWarn,
					"Error":   LogError,
				}

				selectedLevel := LogInfo
				if i, ok := m.levelList.SelectedItem().(actionItem); ok {
					if level, exists := levelMap[i.title]; exists {
						selectedLevel = level
					}
				}

				m.config = LogcatConfig{
					Level:         selectedLevel,
					PackageFilter: m.packageInput.Value(),
					ClearFirst:    true,
				}
				m.submitted = true
				return m, tea.Quit
			}
		}
	case tea.WindowSizeMsg:
		h, _ := lipgloss.NewStyle().Margin(1, 2).GetFrameSize()
		m.levelList.SetSize(msg.Width-h, 10)
	}

	var cmd tea.Cmd
	if m.focusedField == 0 {
		m.packageInput, cmd = m.packageInput.Update(msg)
	} else {
		m.levelList, cmd = m.levelList.Update(msg)
	}
	return m, cmd
}

func (m logcatConfigModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("Logcat Monitor Configuration"))
	s.WriteString("\n\n")

	// Package filter
	s.WriteString(tui.InputLabelStyle.Render("Package Filter: "))
	s.WriteString(m.packageInput.View())
	s.WriteString("\n\n")

	// Log level
	if m.focusedField == 1 {
		s.WriteString(m.levelList.View())
	} else {
		s.WriteString(tui.RenderSubtitle("Log Level: " + m.levelList.SelectedItem().(actionItem).title))
	}

	s.WriteString("\n\n")
	s.WriteString(tui.RenderHelp("tab: next field • enter: start monitoring • q/esc: cancel"))

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// ========== Network Capture Configuration Model ==========

type networkCaptureModel struct {
	proxyTypeList  list.Model
	proxyIPInput   textinput.Model
	proxyPortInput textinput.Model
	focusedField   int
	submitted      bool
	guide          NetworkCaptureGuide
}

func initialNetworkCaptureModel() networkCaptureModel {
	// Proxy type selection
	proxyTypes := []list.Item{
		actionItem{title: "mitmproxy", description: "Free open-source MITM proxy"},
		actionItem{title: "burp", description: "Burp Suite Professional"},
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	proxyList := list.New(proxyTypes, delegate, 0, 8)
	proxyList.Title = "Proxy Tool"
	proxyList.Styles.Title = tui.TitleStyle
	proxyList.SetShowStatusBar(false)
	proxyList.SetFilteringEnabled(false)

	// Proxy IP input
	ipInput := textinput.New()
	ipInput.Placeholder = "192.168.1.100"
	ipInput.CharLimit = 15
	ipInput.Width = 30

	// Proxy port input
	portInput := textinput.New()
	portInput.Placeholder = "8080"
	portInput.CharLimit = 5
	portInput.Width = 10

	m := networkCaptureModel{
		proxyTypeList:  proxyList,
		proxyIPInput:   ipInput,
		proxyPortInput: portInput,
		focusedField:   0,
	}

	return m
}

func (m networkCaptureModel) Init() tea.Cmd {
	return nil
}

func (m networkCaptureModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "tab":
			m.focusedField = (m.focusedField + 1) % 3
			m.updateFocus()
			return m, nil
		case "shift+tab":
			m.focusedField = (m.focusedField - 1 + 3) % 3
			m.updateFocus()
			return m, nil
		case "enter":
			if m.focusedField == 2 {
				// Submit
				proxyType := "mitmproxy"
				if i, ok := m.proxyTypeList.SelectedItem().(actionItem); ok {
					proxyType = i.title
				}

				proxyIP := m.proxyIPInput.Value()
				if proxyIP == "" {
					proxyIP = "192.168.1.100"
				}

				proxyPort := m.proxyPortInput.Value()
				if proxyPort == "" {
					proxyPort = "8080"
				}

				m.guide = NetworkCaptureGuide{
					ProxyType: proxyType,
					ProxyIP:   proxyIP,
					ProxyPort: proxyPort,
				}
				m.submitted = true
				return m, tea.Quit
			} else {
				m.focusedField = (m.focusedField + 1) % 3
				m.updateFocus()
				return m, nil
			}
		}
	case tea.WindowSizeMsg:
		h, _ := lipgloss.NewStyle().Margin(1, 2).GetFrameSize()
		m.proxyTypeList.SetSize(msg.Width-h, 8)
	}

	var cmd tea.Cmd
	switch m.focusedField {
	case 0:
		m.proxyTypeList, cmd = m.proxyTypeList.Update(msg)
	case 1:
		m.proxyIPInput, cmd = m.proxyIPInput.Update(msg)
	case 2:
		m.proxyPortInput, cmd = m.proxyPortInput.Update(msg)
	}
	return m, cmd
}

func (m *networkCaptureModel) updateFocus() {
	m.proxyIPInput.Blur()
	m.proxyPortInput.Blur()

	switch m.focusedField {
	case 1:
		m.proxyIPInput.Focus()
	case 2:
		m.proxyPortInput.Focus()
	}
}

func (m networkCaptureModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("Network Capture Configuration"))
	s.WriteString("\n\n")

	// Proxy type
	if m.focusedField == 0 {
		s.WriteString(m.proxyTypeList.View())
	} else {
		selectedProxy := "mitmproxy"
		if i, ok := m.proxyTypeList.SelectedItem().(actionItem); ok {
			selectedProxy = i.title
		}
		s.WriteString(tui.RenderSubtitle("Proxy Tool: " + selectedProxy))
	}
	s.WriteString("\n\n")

	// Proxy IP
	s.WriteString(tui.InputLabelStyle.Render("Proxy IP: "))
	s.WriteString(m.proxyIPInput.View())
	s.WriteString("\n\n")

	// Proxy port
	s.WriteString(tui.InputLabelStyle.Render("Proxy Port: "))
	s.WriteString(m.proxyPortInput.View())
	s.WriteString("\n\n")

	s.WriteString(tui.RenderHelp("tab: next field • enter: continue • q/esc: cancel"))

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// ========== Backup Configuration Model ==========

type backupConfigModel struct {
	packageInput textinput.Model
	submitted    bool
	packageName  string
}

func initialBackupConfigModel() backupConfigModel {
	pkgInput := textinput.New()
	pkgInput.Placeholder = "com.example.app"
	pkgInput.CharLimit = 256
	pkgInput.Width = 50
	pkgInput.Focus()

	return backupConfigModel{
		packageInput: pkgInput,
	}
}

func (m backupConfigModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m backupConfigModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter":
			if m.packageInput.Value() != "" {
				m.packageName = m.packageInput.Value()
				m.submitted = true
				return m, tea.Quit
			}
		}
	}

	var cmd tea.Cmd
	m.packageInput, cmd = m.packageInput.Update(msg)
	return m, cmd
}

func (m backupConfigModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("Android Backup Extractor"))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderSubtitle("Enter the package name to backup"))
	s.WriteString("\n\n")
	s.WriteString(tui.InputLabelStyle.Render("Package Name: "))
	s.WriteString(m.packageInput.View())
	s.WriteString("\n\n")
	s.WriteString(tui.RenderHelp("enter: create backup • q/esc: cancel"))

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// ========== Handler Functions ==========

// RunMobileModule displays the mobile module menu
func RunMobileModule() {
	items := []list.Item{
		actionItem{
			title:       string(actionInjector),
			description: "Inject payload into APK (requires uber-apk-signer)",
		},
		actionItem{
			title:       string(actionDeepAnalysis),
			description: "Deep APK analysis: components, permissions, security issues",
		},
		actionItem{
			title:       string(actionRecon),
			description: "Basic APK metadata analysis (aapt badging)",
		},
		actionItem{
			title:       string(actionMonitor),
			description: "Monitor Android device processes (requires ADB)",
		},
		actionItem{
			title:       string(actionLogcat),
			description: "Real-time Android log monitoring with filtering (requires ADB)",
		},
		actionItem{
			title:       string(actionNetworkCapture),
			description: "Setup guide for mobile traffic interception (MITM proxy)",
		},
		actionItem{
			title:       string(actionBackup),
			description: "Create and analyze Android app backups (requires ADB)",
		},
		actionItem{
			title:       string(actionSecurityScan),
			description: "Automated security vulnerability scanner",
		},
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New(items, delegate, 0, 0)
	l.Title = "🤖 Mobile Pentesting Tools"
	l.Styles.Title = tui.TitleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	m := mobileMenuModel{list: l}

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(mobileMenuModel); ok && m.chosen != "" {
		switch m.chosen {
		case string(actionInjector):
			runInjector()
		case string(actionDeepAnalysis):
			runDeepAnalysis()
		case string(actionRecon):
			runRecon()
		case string(actionMonitor):
			Monitor()
		case string(actionLogcat):
			runLogcat()
		case string(actionNetworkCapture):
			runNetworkCapture()
		case string(actionBackup):
			runBackup()
		case string(actionSecurityScan):
			runSecurityScan()
		}
	}
}

func runInjector() {
	p := tea.NewProgram(initialInjectorModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(injectorModel); ok && m.state == stateDone {
		fmt.Println()
		fmt.Println(tui.RenderInfo("Starting APK injection..."))
		fmt.Println()

		err := KnifeInjectCLI(m.apkPath, m.payloadPath, m.outputPath)
		if err != nil {
			fmt.Println(tui.RenderError(fmt.Sprintf("Injection failed: %v", err)))
		} else {
			fmt.Println(tui.RenderSuccess("Injection completed successfully!"))
		}
	}
}

func runRecon() {
	p := tea.NewProgram(initialReconModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(reconModel); ok && m.submitted {
		fmt.Println()
		fmt.Println(tui.RenderInfo("Analyzing APK..."))
		fmt.Println()
		ParseAPKMeat(m.apkPath)
	}
}

func runDeepAnalysis() {
	p := tea.NewProgram(initialReconModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(reconModel); ok && m.submitted {
		fmt.Println()
		fmt.Println(tui.RenderInfo("Performing deep APK analysis..."))
		fmt.Println()
		
		analysis, err := DeepAnalyzeAPK(m.apkPath)
		if err != nil {
			fmt.Println(tui.RenderError(fmt.Sprintf("Analysis failed: %v", err)))
			return
		}
		
		PrintAnalysis(analysis)
	}
}

func runLogcat() {
	// Check for connected devices first
	devices, err := GetConnectedDevices()
	if err != nil || len(devices) == 0 {
		fmt.Println(tui.RenderError("No Android devices connected via ADB"))
		fmt.Println(tui.RenderInfo("Connect device and enable USB debugging, then try again"))
		return
	}

	fmt.Printf("Device detected: %s\n", devices[0])

	// Run TUI for configuration
	p := tea.NewProgram(initialLogcatConfigModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(logcatConfigModel); ok && m.submitted {
		fmt.Println()
		MonitorLogcat(m.config)
	}
}

func runNetworkCapture() {
	// Run TUI for configuration
	p := tea.NewProgram(initialNetworkCaptureModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(networkCaptureModel); ok && m.submitted {
		fmt.Println()
		DisplayNetworkCaptureInstructions(m.guide)

		// Ask about ADB proxy configuration
		fmt.Println("\nConfigure proxy via ADB? (y/n): ")
		var configure string
		fmt.Scanln(&configure)

		if strings.ToLower(configure) == "y" {
			if err := SetupADBProxy(m.guide.ProxyIP, m.guide.ProxyPort); err != nil {
				fmt.Println(tui.RenderError(fmt.Sprintf("Failed to set proxy: %v", err)))
			}
		}
	}
}

func runBackup() {
	// Check for connected devices first
	devices, err := GetConnectedDevices()
	if err != nil || len(devices) == 0 {
		fmt.Println(tui.RenderError("No Android devices connected via ADB"))
		return
	}

	fmt.Printf("Device: %s\n", devices[0])

	// Run TUI for package name input
	p := tea.NewProgram(initialBackupConfigModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(backupConfigModel); ok && m.submitted {
		outputPath := m.packageName + "_backup.ab"

		config := BackupConfig{
			PackageName: m.packageName,
			OutputPath:  outputPath,
			IncludeAPK:  true,
			IncludeOBB:  false,
			AllData:     false,
		}

		if err := CreateBackup(config); err != nil {
			fmt.Println(tui.RenderError(fmt.Sprintf("Backup failed: %v", err)))
			return
		}

		// Extract backup
		fmt.Println("\nExtract backup? (y/n): ")
		var extract string
		fmt.Scanln(&extract)

		if strings.ToLower(extract) == "y" {
			tarFile, err := ExtractBackup(outputPath)
			if err != nil {
				fmt.Println(tui.RenderError(fmt.Sprintf("Extraction failed: %v", err)))
				return
			}

			// List contents
			if err := ListBackupContents(tarFile); err != nil {
				fmt.Println(tui.RenderError(fmt.Sprintf("Failed to list contents: %v", err)))
				return
			}

			// Security analysis
			if err := AnalyzeBackupSecurity(tarFile); err != nil {
				fmt.Println(tui.RenderError(fmt.Sprintf("Security analysis failed: %v", err)))
			}
		}
	}
}

func runSecurityScan() {
	p := tea.NewProgram(initialReconModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(reconModel); ok && m.submitted {
		fmt.Println()
		fmt.Println(tui.RenderInfo("Scanning APK for security issues..."))
		fmt.Println()
		
		result, err := ScanAPKSecurity(m.apkPath)
		if err != nil {
			fmt.Println(tui.RenderError(fmt.Sprintf("Security scan failed: %v", err)))
			return
		}
		
		PrintSecurityReport(result)
	}
}

