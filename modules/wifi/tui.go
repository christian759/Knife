package wifi

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"knife/tui"
)

type wifiAction string

const (
	actionDeauth     wifiAction = "Deauth"
	actionEvilTwin   wifiAction = "Evil Twin"
	actionGeolocate  wifiAction = "Geo-locate"
	actionHandshake  wifiAction = "Handshake"
	actionInjector   wifiAction = "Injector"
	actionInterface  wifiAction = "Interface"
	actionMacSpoofer wifiAction = "Mac Spoofer"
	actionPMKID      wifiAction = "PMKID"
	actionSniffer    wifiAction = "Sniffer"
	actionScanner    wifiAction = "Scanner"
)

type wifiActionItem struct {
	title       string
	description string
}

func (i wifiActionItem) Title() string       { return i.title }
func (i wifiActionItem) Description() string { return i.description }
func (i wifiActionItem) FilterValue() string { return i.title }

type wifiMenuModel struct {
	list   list.Model
	chosen string
}

func (m wifiMenuModel) Init() tea.Cmd {
	return nil
}

func (m wifiMenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter":
			if i, ok := m.list.SelectedItem().(wifiActionItem); ok {
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

func (m wifiMenuModel) View() string {
	return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
}

// AP Item for list selection
type apItem struct {
	ap AP
}

func (i apItem) Title() string {
	ssid := i.ap.SSID
	if ssid == "" {
		ssid = "<hidden>"
	}
	return fmt.Sprintf("%s (%.1f dBm)", ssid, i.ap.Signal)
}

func (i apItem) Description() string {
	return fmt.Sprintf("BSSID: %s", i.ap.BSSID)
}

func (i apItem) FilterValue() string {
	return i.ap.SSID + " " + i.ap.BSSID
}

type apSelectionModel struct {
	list   list.Model
	chosen *AP
}

func (m apSelectionModel) Init() tea.Cmd {
	return nil
}

func (m apSelectionModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter":
			if i, ok := m.list.SelectedItem().(apItem); ok {
				m.chosen = &i.ap
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

func (m apSelectionModel) View() string {
	return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
}

// Multi-input form for various WiFi operations
type formField struct {
	label       string
	placeholder string
	value       string
	input       textinput.Model
}

type formModel struct {
	fields   []formField
	focused  int
	title    string
	subtitle string
	done     bool
}

func newFormModel(title, subtitle string, fields []formField) formModel {
	// Initialize text inputs
	for i := range fields {
		ti := textinput.New()
		ti.Placeholder = fields[i].placeholder
		ti.CharLimit = 256
		ti.Width = 50
		if i == 0 {
			ti.Focus()
		}
		fields[i].input = ti
	}

	return formModel{
		fields:   fields,
		title:    title,
		subtitle: subtitle,
	}
}

func (m formModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m formModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "tab", "shift+tab", "enter", "up", "down":
			s := msg.String()

			// Enter on last field submits
			if s == "enter" && m.focused == len(m.fields)-1 {
				// Copy values
				for i := range m.fields {
					m.fields[i].value = m.fields[i].input.Value()
				}
				m.done = true
				return m, tea.Quit
			}

			// Cycle inputs
			if s == "up" || s == "shift+tab" {
				m.focused--
			} else {
				m.focused++
			}

			if m.focused > len(m.fields)-1 {
				m.focused = 0
			} else if m.focused < 0 {
				m.focused = len(m.fields) - 1
			}

			cmds := make([]tea.Cmd, len(m.fields))
			for i := 0; i < len(m.fields); i++ {
				if i == m.focused {
					cmds[i] = m.fields[i].input.Focus()
				} else {
					m.fields[i].input.Blur()
				}
			}
			return m, tea.Batch(cmds...)
		}
	}

	// Update focused field
	var cmd tea.Cmd
	m.fields[m.focused].input, cmd = m.fields[m.focused].input.Update(msg)
	return m, cmd
}

func (m formModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle(m.title))
	s.WriteString("\n\n")
	if m.subtitle != "" {
		s.WriteString(tui.RenderSubtitle(m.subtitle))
		s.WriteString("\n\n")
	}

	for i, field := range m.fields {
		s.WriteString(tui.InputLabelStyle.Render(field.label + ": "))
		s.WriteString("\n")
		if i == m.focused {
			s.WriteString(tui.FocusedInputStyle.Render(field.input.View()))
		} else {
			s.WriteString(tui.BlurredInputStyle.Render(field.input.View()))
		}
		s.WriteString("\n\n")
	}

	s.WriteString(tui.RenderHelp("tab: next field • enter: submit • q/esc: quit"))

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// RunWifiModule displays the WiFi module menu
func RunWifiModule() {
	items := []list.Item{
		wifiActionItem{
			title:       string(actionDeauth),
			description: "Deauthentication attack on selected AP",
		},
		wifiActionItem{
			title:       string(actionEvilTwin),
			description: "Create rogue access point",
		},
		wifiActionItem{
			title:       string(actionGeolocate),
			description: "Geolocate AP using Google API",
		},
		wifiActionItem{
			title:       string(actionHandshake),
			description: "Capture WPA handshake",
		},
		wifiActionItem{
			title:       string(actionInjector),
			description: "Beacon frame flooding",
		},
		wifiActionItem{
			title:       string(actionInterface),
			description: "Manage wireless interfaces",
		},
		wifiActionItem{
			title:       string(actionMacSpoofer),
			description: "Randomize MAC address",
		},
		wifiActionItem{
			title:       string(actionPMKID),
			description: "Capture PMKID for offline cracking",
		},
		wifiActionItem{
			title:       string(actionSniffer),
			description: "Packet sniffer and probe request monitor",
		},
		wifiActionItem{
			title:       string(actionScanner),
			description: "Scan for nearby WiFi networks",
		},
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New(items, delegate, 0, 0)
	l.Title = "📡 WiFi Attack Tools"
	l.Styles.Title = tui.TitleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	m := wifiMenuModel{list: l}

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(wifiMenuModel); ok && m.chosen != "" {
		handleWifiAction(m.chosen)
	}
}

func handleWifiAction(action string) {
	switch action {
	case string(actionDeauth):
		runDeauth()
	case string(actionEvilTwin):
		runEvilTwin()
	case string(actionGeolocate):
		runGeolocate()
	case string(actionHandshake):
		runHandshake()
	case string(actionInjector):
		runInjector()
	case string(actionInterface):
		runInterface()
	case string(actionMacSpoofer):
		runMacSpoofer()
	case string(actionPMKID):
		runPMKID()
	case string(actionSniffer):
		runSniffer()
	case string(actionScanner):
		runScanner()
	}
}

func selectAP(title string) *AP {
	ifaces, err := GetWirelessInterfaces()
	if err != nil || len(ifaces) == 0 {
		fmt.Println(tui.RenderError("No wireless interfaces detected"))
		return nil
	}

	iface := strings.TrimSpace(ifaces[0])
	fmt.Println(tui.RenderInfo(fmt.Sprintf("Scanning on interface %s...", iface)))

	aps, err := scanAPs(iface)
	if err != nil || len(aps) == 0 {
		fmt.Println(tui.RenderError("No access points found"))
		return nil
	}

	items := make([]list.Item, len(aps))
	for i, ap := range aps {
		items[i] = apItem{ap: ap}
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New(items, delegate, 0, 0)
	l.Title = title
	l.Styles.Title = tui.TitleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	m := apSelectionModel{list: l}

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return nil
	}

	if m, ok := finalModel.(apSelectionModel); ok {
		return m.chosen
	}
	return nil
}

func runDeauth() {
	ap := selectAP("📡 Select AP for Deauth Attack")
	if ap == nil {
		return
	}

	form := newFormModel(
		"Deauth Attack",
		fmt.Sprintf("Target: %s (%s)", ap.SSID, ap.BSSID),
		[]formField{
			{label: "Target MAC (or ff:ff:ff:ff:ff:ff for broadcast)", placeholder: "ff:ff:ff:ff:ff:ff"},
			{label: "Packet Count", placeholder: "100"},
		},
	)

	p := tea.NewProgram(form)
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(formModel); ok && m.done {
		target := m.fields[0].value
		count, _ := strconv.Atoi(m.fields[1].value)

		ifaces, _ := GetWirelessInterfaces()
		if len(ifaces) > 0 {
			fmt.Println()
			fmt.Println(tui.RenderInfo("Executing deauth attack..."))
			err := DeauthAttack(ifaces[0], ap.BSSID, target, count)
			if err != nil {
				fmt.Println(tui.RenderError(err.Error()))
			} else {
				fmt.Println(tui.RenderSuccess("Deauth packets sent"))
			}
		}
	}
}

func runEvilTwin() {
	form := newFormModel(
		"Evil Twin Attack",
		"Create a rogue access point",
		[]formField{
			{label: "Interface", placeholder: "wlan0"},
			{label: "SSID to fake", placeholder: "FreeWiFi"},
		},
	)

	p := tea.NewProgram(form)
	finalModel, err := p.Run()
	if err != nil {
		return
	}

	if m, ok := finalModel.(formModel); ok && m.done {
		fmt.Println()
		fmt.Println(tui.RenderInfo("Starting Evil Twin..."))
		StartEvilTwin(m.fields[0].value, m.fields[1].value)
		fmt.Println(tui.RenderWarning("Press Ctrl+C to stop"))
	}
}

func runGeolocate() {
	ap := selectAP("📍 Select AP to Geolocate")
	if ap == nil {
		return
	}

	form := newFormModel(
		"Geolocate AP",
		fmt.Sprintf("Target: %s (%s)", ap.SSID, ap.BSSID),
		[]formField{
			{label: "Google API Key", placeholder: "AIza..."},
		},
	)

	p := tea.NewProgram(form)
	finalModel, err := p.Run()
	if err != nil {
		return
	}

	if m, ok := finalModel.(formModel); ok && m.done {
		apiKey := m.fields[0].value
		req := []WiFiAccessPoint{{MacAddress: ap.BSSID, SignalStrength: int(ap.Signal)}}

		fmt.Println()
		fmt.Println(tui.RenderInfo("Querying geolocation..."))
		resp, err := Geolocate(req, apiKey)
		if err != nil {
			fmt.Println(tui.RenderError(err.Error()))
		} else {
			fmt.Printf("%s Lat: %.6f, Lng: %.6f (Accuracy: %.2fm)\n",
				tui.RenderSuccess("Location found:"),
				resp.Location.Lat, resp.Location.Lng, resp.Accuracy)
		}
	}
}

func runHandshake() {
	form := newFormModel(
		"Handshake Capture",
		"Capture WPA handshake for offline cracking",
		[]formField{
			{label: "Interface", placeholder: "wlan0"},
			{label: "Output file", placeholder: "handshake.pcap"},
			{label: "Timeout (seconds)", placeholder: "60"},
		},
	)

	p := tea.NewProgram(form)
	finalModel, err := p.Run()
	if err != nil {
		return
	}

	if m, ok := finalModel.(formModel); ok && m.done {
		timeout, _ := strconv.Atoi(m.fields[2].value)
		fmt.Println()
		fmt.Println(tui.RenderInfo("Capturing handshake..."))
		err := CaptureHandshake(m.fields[0].value, m.fields[1].value, time.Duration(timeout)*time.Second)
		if err != nil {
			fmt.Println(tui.RenderError(err.Error()))
		} else {
			fmt.Println(tui.RenderSuccess("Handshake captured"))
		}
	}
}

func runInjector() {
	form := newFormModel(
		"Beacon Injector",
		"Flood area with fake SSIDs",
		[]formField{
			{label: "Interface", placeholder: "wlan0"},
			{label: "SSID to flood", placeholder: "FakeNetwork"},
			{label: "Count", placeholder: "100"},
		},
	)

	p := tea.NewProgram(form)
	finalModel, err := p.Run()
	if err != nil {
		return
	}

	if m, ok := finalModel.(formModel); ok && m.done {
		count, _ := strconv.Atoi(m.fields[2].value)
		fmt.Println()
		fmt.Println(tui.RenderInfo("Injecting beacon frames..."))
		InjectBeaconFlood(m.fields[0].value, m.fields[1].value, count)
		fmt.Println(tui.RenderSuccess("Beacon flood complete"))
	}
}

func runInterface() {
	items := []list.Item{
		wifiActionItem{title: "List Interface", description: "Show all wireless interfaces"},
		wifiActionItem{title: "Enable Monitor", description: "Enable monitor mode"},
		wifiActionItem{title: "Disable Monitor", description: "Disable monitor mode"},
		wifiActionItem{title: "Interface Up", description: "Bring interface up"},
		wifiActionItem{title: "Interface Down", description: "Bring interface down"},
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle

	l := list.New(items, delegate, 0, 0)
	l.Title = "🔧 Interface Management"
	l.Styles.Title = tui.TitleStyle

	m := wifiMenuModel{list: l}
	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, _ := p.Run()

	if m, ok := finalModel.(wifiMenuModel); ok && m.chosen != "" {
		if m.chosen == "List Interface" {
			fmt.Println()
			HandleWifiAction(m.chosen, "")
		} else {
			form := newFormModel("Interface Action", m.chosen, []formField{
				{label: "Interface", placeholder: "wlan0"},
			})
			p := tea.NewProgram(form)
			if fm, err := p.Run(); err == nil {
				if fmm, ok := fm.(formModel); ok && fmm.done {
					fmt.Println()
					HandleWifiAction(m.chosen, fmm.fields[0].value)
				}
			}
		}
	}
}

func runMacSpoofer() {
	ifaces, err := GetWirelessInterfaces()
	if err != nil || len(ifaces) == 0 {
		fmt.Println(tui.RenderError("No wireless interfaces detected"))
		return
	}

	iface := strings.TrimSpace(ifaces[0])
	fmt.Println()
	fmt.Println(tui.RenderInfo(fmt.Sprintf("Using interface: %s", iface)))

	current, err := GetCurrentMAC(iface)
	if err == nil {
		fmt.Println(tui.RenderInfo(fmt.Sprintf("Current MAC: %s", current)))
	}

	fmt.Println()
	fmt.Println(tui.RenderInfo("Randomizing MAC address..."))
	newMac, err := RandomMAC(iface)
	if err != nil {
		fmt.Println(tui.RenderError(err.Error()))
	} else {
		fmt.Println(tui.RenderSuccess(fmt.Sprintf("New MAC: %s", newMac)))
	}
}

func runPMKID() {
	ifaces, err := GetWirelessInterfaces()
	if err != nil || len(ifaces) == 0 {
		fmt.Println(tui.RenderError("No wireless interfaces detected"))
		return
	}

	form := newFormModel(
		"PMKID Capture",
		"Capture PMKID for offline cracking",
		[]formField{
			{label: "Interface", placeholder: ifaces[0]},
			{label: "Output file", placeholder: "pmkid.pcap"},
			{label: "Timeout (seconds)", placeholder: "60"},
		},
	)

	p := tea.NewProgram(form)
	finalModel, err := p.Run()
	if err != nil {
		return
	}

	if m, ok := finalModel.(formModel); ok && m.done {
		timeout, _ := strconv.Atoi(m.fields[2].value)
		fmt.Println()
		fmt.Println(tui.RenderInfo("Capturing PMKID..."))
		err := CapturePMKID(m.fields[0].value, m.fields[1].value, time.Duration(timeout)*time.Second)
		if err != nil {
			fmt.Println(tui.RenderError(err.Error()))
		} else {
			fmt.Println(tui.RenderSuccess("PMKID captured"))
		}
	}
}

// Sniffer Model
type sniffMsg string
type sniffFinishedMsg struct{}

type snifferModel struct {
	list      list.Model
	spinner   spinner.Model
	sub       chan string
	listening bool
	err       error
}

func waitForPacket(sub chan string) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-sub
		if !ok {
			return sniffFinishedMsg{}
		}
		return sniffMsg(msg)
	}
}

func initialSnifferModel(iface string, timeout time.Duration) snifferModel {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New([]list.Item{}, delegate, 0, 0)
	l.Title = "👃 Packet Sniffer"
	l.Styles.Title = tui.TitleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	sub := make(chan string)
	
	// Start sniffer in goroutine
	go func() {
		defer close(sub)
		SniffProbes(iface, timeout, sub)
	}()

	return snifferModel{
		list:      l,
		spinner:   s,
		sub:       sub,
		listening: true,
	}
}

func (m snifferModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForPacket(m.sub))
}

func (m snifferModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" || msg.String() == "esc" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		h, v := lipgloss.NewStyle().Margin(1, 2).GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	case sniffMsg:
		m.list.InsertItem(0, scanItem{ssid: string(msg)}) // Reuse scanItem for simplicity
		return m, waitForPacket(m.sub)
	case sniffFinishedMsg:
		m.listening = false
		m.list.Title = "👃 Sniffing Complete"
		return m, nil
	}

	var cmd tea.Cmd
	var cmds []tea.Cmd

	if m.listening {
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	m.list, cmd = m.list.Update(msg)
	cmds = append(cmds, cmd)
	
	return m, tea.Batch(cmds...)
}

func (m snifferModel) View() string {
	if m.listening {
		// Show spinner in title or status bar?
		// For now, let's just append it to the title if possible, or just rely on the list updating
		// Actually, let's just show the list, as it updates in real-time.
		// The spinner might be distracting if the list is moving.
		// But let's keep the spinner update logic just in case we want to show it.
		return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
	}
	return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
}

func runSniffer() {
	ifaces, err := GetWirelessInterfaces()
	if err != nil || len(ifaces) == 0 {
		fmt.Println(tui.RenderError("No wireless interfaces detected"))
		return
	}

	form := newFormModel(
		"Packet Sniffer",
		"Sniff probe requests",
		[]formField{
			{label: "Interface", placeholder: ifaces[0]},
			{label: "Timeout (seconds)", placeholder: "30"},
		},
	)

	p := tea.NewProgram(form)
	finalModel, err := p.Run()
	if err != nil {
		return
	}

	if m, ok := finalModel.(formModel); ok && m.done {
		iface := m.fields[0].value
		timeout, _ := strconv.Atoi(m.fields[1].value)
		IsRootOrSudoRelaunch()

		// Run the sniffer TUI
		sniffer := initialSnifferModel(iface, time.Duration(timeout)*time.Second)
		p := tea.NewProgram(sniffer, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running sniffer: %v\n", err)
		}
	}
}

// Scan Result Item
type scanItem struct {
	ssid string
}

func (i scanItem) Title() string       { return i.ssid }
func (i scanItem) Description() string { return "WiFi Network" }
func (i scanItem) FilterValue() string { return i.ssid }

type scanModel struct {
	list     list.Model
	spinner  spinner.Model
	scanning bool
	err      error
}

type scanResultMsg []string
type scanErrorMsg error

func scanNetworksCmd() tea.Cmd {
	return func() tea.Msg {
		ifaces, err := GetWirelessInterfaces()
		if err != nil || len(ifaces) == 0 {
			return scanErrorMsg(fmt.Errorf("no wireless interfaces found"))
		}
		
		// Scan on first interface for now
		ssids, err := ScanNetworks(ifaces[0])
		if err != nil {
			return scanErrorMsg(err)
		}
		return scanResultMsg(ssids)
	}
}

func initialScanModel() scanModel {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New([]list.Item{}, delegate, 0, 0)
	l.Title = "📡 Scanning Networks..."
	l.Styles.Title = tui.TitleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return scanModel{
		list:     l,
		spinner:  s,
		scanning: true,
	}
}

func (m scanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, scanNetworksCmd())
}

func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" || msg.String() == "esc" {
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		h, v := lipgloss.NewStyle().Margin(1, 2).GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	case scanResultMsg:
		m.scanning = false
		m.list.Title = fmt.Sprintf("📡 Found %d Networks", len(msg))
		items := make([]list.Item, len(msg))
		for i, ssid := range msg {
			items[i] = scanItem{ssid: ssid}
		}
		m.list.SetItems(items)
		return m, nil
	case scanErrorMsg:
		m.scanning = false
		m.err = msg
		m.list.Title = "❌ Scan Failed"
		return m, nil
	}

	var cmd tea.Cmd
	var cmds []tea.Cmd

	if m.scanning {
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	m.list, cmd = m.list.Update(msg)
	cmds = append(cmds, cmd)
	
	return m, tea.Batch(cmds...)
}

func (m scanModel) View() string {
	if m.err != nil {
		return lipgloss.NewStyle().Margin(1, 2).Render(tui.RenderError(m.err.Error()) + "\n\nPress q to quit")
	}
	
	if m.scanning {
		return lipgloss.NewStyle().Margin(1, 2).Render(
			fmt.Sprintf("\n %s Scanning for networks...\n\n%s", m.spinner.View(), tui.RenderInfo("Please wait...")))
	}

	return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
}

func runScanner() {
	IsRootOrSudoRelaunch()
	p := tea.NewProgram(initialScanModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running scanner: %v\n", err)
	}
}
