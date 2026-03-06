package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"knife/tui"
)

type vulnSessionState int

const (
	stateTarget vulnSessionState = iota
	stateScanners
	stateConfig
	stateScanning
	stateSummary
)

type scannerItem struct {
	info     ScannerInfo
	selected bool
}

func (i scannerItem) Title() string       { 
	if i.selected {
		return "[x] " + i.info.Name
	}
	return "[ ] " + i.info.Name
}
func (i scannerItem) Description() string { return i.info.Description }
func (i scannerItem) FilterValue() string { return i.info.Name }

type mainModel struct {
	state          vulnSessionState
	targetInput    textinput.Model
	scannerList    list.Model
	configFields   []vulnFormField
	focusedField   int
	progress       progress.Model
	
	// Data
	targetURL      string
	availableScanners []ScannerInfo
	selected      map[ScannerType]bool
	
	// Scan settings
	workers        int
	intensity      int
	depth          int
	
	// Execution
	coordinator    *ScannerCoordinator
	results        *ScanResult
	progressMsg    ScanProgress
	err            error
	done           bool
}

func initialModel() mainModel {
	// Target input
	ti := textinput.New()
	ti.Placeholder = "https://example.com"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 60

	// Scanner list
	scanners := GetScannerInfo()
	items := make([]list.Item, len(scanners))
	for i, s := range scanners {
		items[i] = scannerItem{info: s, selected: true} // Default all on
	}
	
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Select Scanners to Enable"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = tui.TitleStyle
	
	// Progress
	p := progress.New(progress.WithDefaultGradient())

	// Config fields
	configFields := []vulnFormField{
		{label: "Workers (Concurrency)", placeholder: "10", value: "10"},
		{label: "Intensity (1-5)", placeholder: "3", value: "3"},
		{label: "Max Crawl Depth", placeholder: "2", value: "2"},
	}
	for i := range configFields {
		cti := textinput.New()
		cti.Placeholder = configFields[i].placeholder
		cti.SetValue(configFields[i].value)
		configFields[i].input = cti
	}

	selected := make(map[ScannerType]bool)
	for _, s := range scanners {
		selected[s.Type] = true
	}

	return mainModel{
		state:          stateTarget,
		targetInput:    ti,
		scannerList:    l,
		configFields:   configFields,
		progress:       p,
		availableScanners: scanners,
		selected:       selected,
		workers:        10,
		intensity:      3,
		depth:          2,
	}
}

func (m mainModel) Init() tea.Cmd {
	return textinput.Blink
}

type scanProgressMsg ScanProgress
type scanFinishedMsg struct {
	result *ScanResult
	err    error
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.scannerList.SetSize(msg.Width-4, msg.Height-10)
		m.progress.Width = msg.Width - 10
		return m, nil

	case scanProgressMsg:
		m.progressMsg = ScanProgress(msg)
		// Update progress bar based on completed scanners
		if m.coordinator != nil {
			completed := 0
			for _, res := range m.coordinator.scannerResults {
				if res.Status == "completed" || res.Status == "failed" {
					completed++
				}
			}
			total := len(m.config.EnabledScanners)
			if total > 0 {
				return m, m.progress.SetPercent(float64(completed) / float64(total))
			}
		}
		return m, nil

	case scanFinishedMsg:
		m.results = msg.result
		m.err = msg.err
		m.state = stateSummary
		return m, nil
	}

	// State-specific updates
	switch m.state {
	case stateTarget:
		return m.updateTarget(msg)
	case stateScanners:
		return m.updateScanners(msg)
	case stateConfig:
		return m.updateConfig(msg)
	case stateScanning:
		return m, nil // Handled by background process
	case stateSummary:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m mainModel) updateTarget(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
		m.targetURL = strings.TrimSpace(m.targetInput.Value())
		if m.targetURL != "" {
			m.state = stateScanners
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.targetInput, cmd = m.targetInput.Update(msg)
	return m, cmd
}

func (m mainModel) updateScanners(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case " ":
			// Toggle selected
			i := m.scannerList.Index()
			item := m.scannerList.Items()[i].(scannerItem)
			item.selected = !item.selected
			m.selected[item.info.Type] = item.selected
			
			items := m.scannerList.Items()
			items[i] = item
			m.scannerList.SetItems(items)
			return m, nil
		case "enter":
			m.state = stateConfig
			m.configFields[0].input.Focus()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.scannerList, cmd = m.scannerList.Update(msg)
	return m, cmd
}

func (m mainModel) updateConfig(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "up", "shift+tab":
			m.focusedField--
		case "down", "tab", "enter":
			if m.focusedField == len(m.configFields)-1 && k.String() == "enter" {
				// START SCAN
				return m.startScan()
			}
			m.focusedField++
		}

		if m.focusedField < 0 {
			m.focusedField = len(m.configFields) - 1
		} else if m.focusedField >= len(m.configFields) {
			m.focusedField = 0
		}

		// Update focus
		cmds := make([]tea.Cmd, len(m.configFields))
		for i := range m.configFields {
			if i == m.focusedField {
				cmds[i] = m.configFields[i].input.Focus()
			} else {
				m.configFields[i].input.Blur()
			}
		}
		
		// Update values from inputs
		fmt.Sscanf(m.configFields[0].input.Value(), "%d", &m.workers)
		fmt.Sscanf(m.configFields[1].input.Value(), "%d", &m.intensity)
		fmt.Sscanf(m.configFields[2].input.Value(), "%d", &m.depth)

		return m, tea.Batch(cmds...)
	}

	var cmd tea.Cmd
	m.configFields[m.focusedField].input, cmd = m.configFields[m.focusedField].input.Update(msg)
	return m, cmd
}

func (m mainModel) startScan() (tea.Model, tea.Cmd) {
	m.state = stateScanning
	
	enabled := []ScannerType{}
	for st, sel := range m.selected {
		if sel {
			enabled = append(enabled, st)
		}
	}

	config := ScanConfig{
		Target:          m.targetURL,
		EnabledScanners: enabled,
		Workers:         m.workers,
		Intensity:       m.intensity,
		MaxDepth:        m.depth,
		MaxPages:        50,
		Throttle:        100 * time.Millisecond,
		CustomPayloads:  make(map[string][]string),
	}

	m.coordinator = NewScannerCoordinator(config)

	// Background scan function
	runScan := func() tea.Msg {
		res, err := m.coordinator.RunAllScans()
		return scanFinishedMsg{result: res, err: err}
	}

	// Progress listener function
	listenProgress := func() tea.Msg {
		for p := range m.coordinator.GetProgressChannel() {
			return scanProgressMsg(p)
		}
		return nil
	}

	return m, tea.Batch(runScan, listenProgress)
}

func (m mainModel) View() string {
	var s strings.Builder
	s.WriteString(tui.GetScaryLogo())
	s.WriteString("\n\n")

	switch m.state {
	case stateTarget:
		s.WriteString(tui.RenderTitle("Target Selection"))
		s.WriteString("\n")
		s.WriteString(tui.InputLabelStyle.Render("Target URL:"))
		s.WriteString("\n")
		s.WriteString(tui.FocusedInputStyle.Render(m.targetInput.View()))
		s.WriteString("\n\n")
		s.WriteString(tui.RenderHelp("enter: continue • esc: quit"))

	case stateScanners:
		s.WriteString(m.scannerList.View())
		s.WriteString("\n")
		s.WriteString(tui.RenderHelp("space: toggle • enter: continue • esc: quit"))

	case stateConfig:
		s.WriteString(tui.RenderTitle("Scan Configuration"))
		s.WriteString("\n")
		for i, f := range m.configFields {
			label := f.label + ":"
			if i == m.focusedField {
				s.WriteString(tui.SelectedItemStyle.Render("> " + label))
			} else {
				s.WriteString(tui.NormalItemStyle.Render("  " + label))
			}
			s.WriteString("\n")
			s.WriteString(f.input.View())
			s.WriteString("\n\n")
		}
		s.WriteString(tui.RenderHelp("tab/arrows: move • enter: START SCAN • esc: quit"))

	case stateScanning:
		s.WriteString(tui.RenderTitle("Scanning in Progress..."))
		s.WriteString("\n\n")
		s.WriteString(m.progress.View())
		s.WriteString("\n\n")
		if m.progressMsg.ScannerName != "" {
			s.WriteString(fmt.Sprintf("Current: %s (%s)\n", m.progressMsg.ScannerName, m.progressMsg.Status))
			s.WriteString(fmt.Sprintf("Findings: %d\n", m.progressMsg.FindingsCount))
		}
		s.WriteString("\n")
		s.WriteString(tui.RenderWarning("Please stay focused. Attack is active."))

	case stateSummary:
		s.WriteString(tui.RenderTitle("Scan Summary"))
		s.WriteString("\n")
		if m.err != nil {
			s.WriteString(tui.RenderError(m.err.Error()))
		} else if m.results != nil {
			s.WriteString(tui.RenderSuccess(fmt.Sprintf("Scan complete on %s", m.results.Target)))
			s.WriteString("\n")
			s.WriteString(fmt.Sprintf("Duration: %v\n", m.results.Duration))
			s.WriteString(fmt.Sprintf("Total Findings: %d\n", len(m.results.Findings)))
			s.WriteString("\n")
			
			// Group by type
			summary := m.coordinator.GetSummary()
			for k, v := range summary {
				if v > 0 && k != "Total" {
					if k == "Critical" || k == "High" {
						s.WriteString(tui.ErrorStyle.Render(fmt.Sprintf("• %s: %d\n", k, v)))
					} else {
						s.WriteString(fmt.Sprintf("• %s: %d\n", k, v))
					}
				}
			}
		}
		s.WriteString("\n")
		s.WriteString(tui.RenderHelp("enter: close scanner • esc: quit"))
	}

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// Interact runs the vulnerability scanner with the improved TUI
func Interact() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
