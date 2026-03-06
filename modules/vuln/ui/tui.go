package ui

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"knife/modules/vuln/engine"
	"knife/tui"
)

// vulnFormField represents a configuration form field
type vulnFormField struct {
	label       string
	placeholder string
	value       string
	input       textinput.Model
}

type vulnSessionState int

const (
	stateTarget vulnSessionState = iota
	stateScanners
	stateConfig
	stateScanning
	stateSummary
)

type mainModel struct {
	state        vulnSessionState
	targetInput  textinput.Model
	configFields []vulnFormField
	focusedField int
	progress     progress.Model

	// Data
	targetURL          string
	availableScanners  []engine.ScannerInfo
	selected           map[engine.ScannerType]bool
	scannerCursor      int
	uiError            string
	scannerStatus      map[string]string
	scannerFindings    map[string]int
	scanStartedAt      time.Time
	progressPercent    float64
	lastProgressUpdate string
	reportPath         string

	// Scan settings
	workers   int
	intensity int
	depth     int

	// Execution
	coordinator *engine.ScannerCoordinator
	results     *engine.ScanResult
	progressMsg engine.ScanProgress
	err         error
}

func initialModel() mainModel {
	ti := textinput.New()
	ti.Placeholder = "https://example.com"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 60

	p := progress.New(progress.WithDefaultGradient())

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

	scanners := engine.GetScannerInfo()
	selected := make(map[engine.ScannerType]bool, len(scanners))
	for _, s := range scanners {
		selected[s.Type] = true
	}

	return mainModel{
		state:              stateTarget,
		targetInput:        ti,
		configFields:       configFields,
		progress:           p,
		availableScanners:  scanners,
		selected:           selected,
		scannerStatus:      make(map[string]string),
		scannerFindings:    make(map[string]int),
		workers:            10,
		intensity:          3,
		depth:              2,
		progressPercent:    0,
		lastProgressUpdate: "waiting",
	}
}

func (m mainModel) Init() tea.Cmd {
	return textinput.Blink
}

type scanProgressMsg engine.ScanProgress
type scanFinishedMsg struct {
	result     *engine.ScanResult
	err        error
	reportPath string
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.progress.Width = msg.Width - 10
		return m, nil

	case scanProgressMsg:
		m.progressMsg = engine.ScanProgress(msg)
		m.uiError = ""
		m.lastProgressUpdate = fmt.Sprintf("%s: %s", msg.ScannerName, msg.Status)
		if msg.ScannerName != "" {
			m.scannerStatus[msg.ScannerName] = msg.Status
			m.scannerFindings[msg.ScannerName] = msg.FindingsCount
		}

		total := m.selectedCount()
		if total > 0 {
			completed := m.completedCount()
			m.progressPercent = float64(completed) / float64(total)
			return m, tea.Batch(m.progress.SetPercent(m.progressPercent), m.listenProgress())
		}
		return m, m.listenProgress()

	case scanFinishedMsg:
		m.results = msg.result
		m.err = msg.err
		m.reportPath = msg.reportPath
		m.state = stateSummary
		m.progressPercent = 1
		return m, m.progress.SetPercent(1)
	}

	switch m.state {
	case stateTarget:
		return m.updateTarget(msg)
	case stateScanners:
		return m.updateScanners(msg)
	case stateConfig:
		return m.updateConfig(msg)
	case stateScanning:
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "esc" {
			return m, tea.Quit
		}
		return m, nil
	case stateSummary:
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "enter", "esc":
				return m, tea.Quit
			}
		}
	}

	return m, nil
}

func (m mainModel) updateTarget(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return m, tea.Quit
		case "enter":
			m.targetURL = strings.TrimSpace(m.targetInput.Value())
			if m.targetURL == "" {
				m.uiError = "target URL cannot be empty"
				return m, nil
			}
			m.uiError = ""
			m.state = stateScanners
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.targetInput, cmd = m.targetInput.Update(msg)
	return m, cmd
}

func (m mainModel) updateScanners(msg tea.Msg) (tea.Model, tea.Cmd) {
	if len(m.availableScanners) == 0 {
		m.uiError = "no scanners available"
		return m, nil
	}

	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return m, tea.Quit
		case "up", "k":
			if m.scannerCursor > 0 {
				m.scannerCursor--
			}
			return m, nil
		case "down", "j":
			if m.scannerCursor < len(m.availableScanners)-1 {
				m.scannerCursor++
			}
			return m, nil
		case " ":
			cur := m.availableScanners[m.scannerCursor]
			m.selected[cur.Type] = !m.selected[cur.Type]
			m.uiError = ""
			return m, nil
		case "a":
			for _, s := range m.availableScanners {
				m.selected[s.Type] = true
			}
			m.uiError = ""
			return m, nil
		case "n":
			for _, s := range m.availableScanners {
				m.selected[s.Type] = false
			}
			m.uiError = ""
			return m, nil
		case "i":
			for _, s := range m.availableScanners {
				m.selected[s.Type] = !m.selected[s.Type]
			}
			m.uiError = ""
			return m, nil
		case "b":
			m.state = stateTarget
			return m, nil
		case "enter":
			if m.selectedCount() == 0 {
				m.uiError = "select at least one scanner before continuing"
				return m, nil
			}
			m.uiError = ""
			m.state = stateConfig
			m.focusedField = 0
			m.configFields[0].input.Focus()
			return m, nil
		}
	}
	return m, nil
}

func (m mainModel) updateConfig(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return m, tea.Quit
		case "b":
			m.state = stateScanners
			return m, nil
		case "up", "shift+tab":
			m.focusedField--
		case "down", "tab":
			m.focusedField++
		case "ctrl+s":
			return m.startScan()
		case "enter":
			if m.focusedField == len(m.configFields)-1 {
				return m.startScan()
			}
			m.focusedField++
		}

		if m.focusedField < 0 {
			m.focusedField = len(m.configFields) - 1
		} else if m.focusedField >= len(m.configFields) {
			m.focusedField = 0
		}

		cmds := make([]tea.Cmd, len(m.configFields))
		for i := range m.configFields {
			if i == m.focusedField {
				cmds[i] = m.configFields[i].input.Focus()
			} else {
				m.configFields[i].input.Blur()
			}
		}
		m.parseConfigValues()
		return m, tea.Batch(cmds...)
	}

	var cmd tea.Cmd
	m.configFields[m.focusedField].input, cmd = m.configFields[m.focusedField].input.Update(msg)
	m.parseConfigValues()
	return m, cmd
}

func (m *mainModel) parseConfigValues() {
	if v, err := strconv.Atoi(strings.TrimSpace(m.configFields[0].input.Value())); err == nil {
		m.workers = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m.configFields[1].input.Value())); err == nil {
		m.intensity = v
	}
	if v, err := strconv.Atoi(strings.TrimSpace(m.configFields[2].input.Value())); err == nil {
		m.depth = v
	}
}

func (m mainModel) startScan() (tea.Model, tea.Cmd) {
	m.parseConfigValues()
	if m.selectedCount() == 0 {
		m.uiError = "select at least one scanner"
		return m, nil
	}
	if m.workers < 1 {
		m.uiError = "workers must be >= 1"
		return m, nil
	}
	if m.intensity < 1 || m.intensity > 5 {
		m.uiError = "intensity must be between 1 and 5"
		return m, nil
	}
	if m.depth < 1 {
		m.uiError = "max crawl depth must be >= 1"
		return m, nil
	}

	m.state = stateScanning
	m.scanStartedAt = time.Now()
	m.progressPercent = 0
	m.lastProgressUpdate = "starting scan"
	m.scannerStatus = make(map[string]string)
	m.scannerFindings = make(map[string]int)
	m.uiError = ""

	enabled := make([]engine.ScannerType, 0, m.selectedCount())
	for _, s := range m.availableScanners {
		if m.selected[s.Type] {
			enabled = append(enabled, s.Type)
		}
	}

	config := engine.ScanConfig{
		Target:          m.targetURL,
		EnabledScanners: enabled,
		Workers:         m.workers,
		Intensity:       m.intensity,
		MaxDepth:        m.depth,
		MaxPages:        50,
		Throttle:        100 * time.Millisecond,
		CustomPayloads:  make(map[string][]string),
	}

	m.coordinator = engine.NewScannerCoordinator(config)

	runScan := func() tea.Msg {
		res, err := m.coordinator.RunAllScans()
		reportPath := ""
		if err == nil && res != nil {
			reportPath, err = engine.WriteUnifiedReport(res.Findings, "", m.targetURL)
		}
		return scanFinishedMsg{result: res, err: err, reportPath: reportPath}
	}

	return m, tea.Batch(runScan, m.listenProgress(), m.progress.SetPercent(0))
}

func (m mainModel) listenProgress() tea.Cmd {
	if m.coordinator == nil {
		return nil
	}
	return func() tea.Msg {
		for p := range m.coordinator.GetProgressChannel() {
			return scanProgressMsg(p)
		}
		return nil
	}
}

func (m mainModel) selectedCount() int {
	count := 0
	for _, s := range m.availableScanners {
		if m.selected[s.Type] {
			count++
		}
	}
	return count
}

func (m mainModel) completedCount() int {
	done := 0
	for _, info := range m.availableScanners {
		if !m.selected[info.Type] {
			continue
		}
		status := m.scannerStatus[string(info.Type)]
		if status == "completed" || status == "failed" {
			done++
		}
	}
	return done
}

func (m mainModel) formatScannerStatus(scannerType engine.ScannerType) string {
	status := m.scannerStatus[string(scannerType)]
	switch status {
	case "running":
		return tui.WarningStyle.Render("RUNNING")
	case "completed":
		return tui.SuccessStyle.Render("DONE")
	case "failed":
		return tui.ErrorStyle.Render("FAILED")
	default:
		return tui.HelpStyle.Render("PENDING")
	}
}

func (m mainModel) scannerSeverityStyle(sev string) lipgloss.Style {
	switch strings.ToLower(sev) {
	case "critical":
		return tui.ErrorStyle
	case "high":
		return tui.WarningStyle
	case "medium":
		return tui.InfoStyle
	default:
		return tui.HelpStyle
	}
}

func (m mainModel) renderScannerPicker() string {
	var b strings.Builder
	b.WriteString(tui.RenderTitle("Scanner Selection"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Selected: %d/%d\n\n", m.selectedCount(), len(m.availableScanners)))

	for i, s := range m.availableScanners {
		cursor := " "
		if i == m.scannerCursor {
			cursor = ">"
		}
		check := "[ ]"
		if m.selected[s.Type] {
			check = "[x]"
		}
		line := fmt.Sprintf("%s %s %-34s ", cursor, check, s.Name)
		b.WriteString(line)
		b.WriteString(m.scannerSeverityStyle(s.Severity).Render("[" + strings.ToUpper(s.Severity) + "]"))
		b.WriteString("\n")
	}

	if len(m.availableScanners) > 0 {
		current := m.availableScanners[m.scannerCursor]
		b.WriteString("\n")
		b.WriteString(tui.RenderBox(fmt.Sprintf("Description: %s\nType: %s", current.Description, current.Type)))
	}

	if m.uiError != "" {
		b.WriteString("\n")
		b.WriteString(tui.RenderError(m.uiError))
	}
	b.WriteString("\n\n")
	b.WriteString(tui.RenderHelp("j/k or arrows: move | space: toggle | a: all | n: none | i: invert | b: back | enter: continue | esc: quit"))
	return b.String()
}

func (m mainModel) renderConfig() string {
	var b strings.Builder
	b.WriteString(tui.RenderTitle("Scan Configuration"))
	b.WriteString("\n")

	for i, f := range m.configFields {
		label := f.label + ":"
		if i == m.focusedField {
			b.WriteString(tui.SelectedItemStyle.Render("> " + label))
		} else {
			b.WriteString(tui.NormalItemStyle.Render("  " + label))
		}
		b.WriteString("\n")
		b.WriteString(f.input.View())
		b.WriteString("\n\n")
	}

	if m.uiError != "" {
		b.WriteString(tui.RenderError(m.uiError))
		b.WriteString("\n")
	}
	b.WriteString(tui.RenderHelp("tab/arrows: move | enter on last field or ctrl+s: start | b: back | esc: quit"))
	return b.String()
}

func (m mainModel) renderScanning() string {
	var b strings.Builder
	b.WriteString(tui.RenderTitle("Scanning"))
	b.WriteString("\n\n")
	b.WriteString(m.progress.ViewAs(m.progressPercent))
	b.WriteString("\n")

	elapsed := time.Since(m.scanStartedAt).Round(time.Second)
	b.WriteString(fmt.Sprintf("Progress: %d/%d scanners complete\n", m.completedCount(), m.selectedCount()))
	b.WriteString(fmt.Sprintf("Elapsed: %s\n", elapsed))
	b.WriteString(fmt.Sprintf("Last update: %s\n", m.lastProgressUpdate))
	b.WriteString("\n")

	for _, info := range m.availableScanners {
		if !m.selected[info.Type] {
			continue
		}
		status := m.formatScannerStatus(info.Type)
		findings := m.scannerFindings[string(info.Type)]
		b.WriteString(fmt.Sprintf("- %-24s %s findings=%d\n", string(info.Type), status, findings))
	}

	b.WriteString("\n")
	if m.progressMsg.Error != nil {
		b.WriteString(tui.RenderError(m.progressMsg.Error.Error()))
	} else {
		b.WriteString(tui.RenderInfo("Scan running. Press esc to quit."))
	}
	return b.String()
}

func (m mainModel) renderSummary() string {
	var b strings.Builder
	b.WriteString(tui.RenderTitle("Scan Summary"))
	b.WriteString("\n")

	if m.err != nil {
		b.WriteString(tui.RenderError(m.err.Error()))
		b.WriteString("\n")
	} else if m.results != nil {
		b.WriteString(tui.RenderSuccess(fmt.Sprintf("Scan complete on %s", m.results.Target)))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("Duration: %v\n", m.results.Duration))
		b.WriteString(fmt.Sprintf("Total Findings: %d\n\n", len(m.results.Findings)))
		if m.reportPath != "" {
			b.WriteString(fmt.Sprintf("HTML Report: %s\n\n", m.reportPath))
		}

		summary := m.coordinator.GetSummary()
		severityOrder := []string{"Critical", "High", "Medium", "Low"}
		for _, sev := range severityOrder {
			if summary[sev] > 0 {
				b.WriteString(fmt.Sprintf("- %s: %d\n", sev, summary[sev]))
			}
		}

		types := make([]string, 0, len(summary))
		for k, v := range summary {
			if v > 0 && k != "Total" && k != "Critical" && k != "High" && k != "Medium" && k != "Low" {
				types = append(types, k)
			}
		}
		sort.Strings(types)
		if len(types) > 0 {
			b.WriteString("\nBy type:\n")
			for _, k := range types {
				b.WriteString(fmt.Sprintf("- %s: %d\n", k, summary[k]))
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(tui.RenderHelp("enter/esc: exit"))
	return b.String()
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
		if m.uiError != "" {
			s.WriteString("\n")
			s.WriteString(tui.RenderError(m.uiError))
		}
		s.WriteString("\n\n")
		s.WriteString(tui.RenderHelp("enter: continue | esc: quit"))
	case stateScanners:
		s.WriteString(m.renderScannerPicker())
	case stateConfig:
		s.WriteString(m.renderConfig())
	case stateScanning:
		s.WriteString(m.renderScanning())
	case stateSummary:
		s.WriteString(m.renderSummary())
	}

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// Interact runs the vulnerability scanner TUI.
func Interact() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("scanner UI error: %v", err)
		os.Exit(1)
	}
}
