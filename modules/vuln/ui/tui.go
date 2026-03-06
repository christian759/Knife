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

// vulnFormField represents a configuration form field.
type vulnFormField struct {
	key         string
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

	// Window
	windowWidth  int
	windowHeight int

	// Data
	targetURL          string
	availableScanners  []engine.ScannerInfo
	selected           map[engine.ScannerType]bool
	scannerCursor      int
	uiError            string
	uiNotice           string
	scannerStatus      map[string]string
	scannerFindings    map[string]int
	scannerModes       map[engine.ScannerType]string
	scanStartedAt      time.Time
	progressPercent    float64
	lastProgressUpdate string
	reportPath         string
	activityLog        []string
	scanDetailCursor   int
	summaryCursor      int
	showEvidence       bool

	// Scan settings
	workers          int
	intensity        int
	depth            int
	maxPages         int
	throttleMS       int
	networkProfile   string
	networkPorts     string
	networkTimeoutMS int
	networkWorkers   int
	networkDeepScan  bool

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
	ti.CharLimit = 256
	ti.Width = 72

	p := progress.New(progress.WithDefaultGradient())

	configFields := []vulnFormField{
		{key: "workers", label: "Workers (Concurrency)", placeholder: "10", value: "10"},
		{key: "intensity", label: "Intensity (1-5)", placeholder: "3", value: "3"},
		{key: "depth", label: "Max Crawl Depth", placeholder: "2", value: "2"},
		{key: "max_pages", label: "Max Crawl Pages", placeholder: "50", value: "50"},
		{key: "throttle_ms", label: "Throttle (ms)", placeholder: "100", value: "100"},
		{key: "network_profile", label: "Network Profile", placeholder: "infrastructure|web|hybrid", value: "infrastructure"},
		{key: "network_ports", label: "Network Ports (optional)", placeholder: "22,80,443,8000-8010", value: ""},
		{key: "network_timeout_ms", label: "Network Timeout (ms)", placeholder: "2000", value: "2000"},
		{key: "network_workers", label: "Network Workers (optional)", placeholder: "20", value: ""},
		{key: "network_deep_scan", label: "Network Deep Scan", placeholder: "false", value: "false"},
	}
	for i := range configFields {
		cti := textinput.New()
		cti.Placeholder = configFields[i].placeholder
		cti.SetValue(configFields[i].value)
		cti.Width = 58
		configFields[i].input = cti
	}

	scanners := engine.GetScannerInfo()
	selected := make(map[engine.ScannerType]bool, len(scanners))
	scannerModes := make(map[engine.ScannerType]string, len(scanners))
	for _, s := range scanners {
		selected[s.Type] = true
		scannerModes[s.Type] = "balanced"
	}

	return mainModel{
		state:              stateTarget,
		targetInput:        ti,
		configFields:       configFields,
		progress:           p,
		availableScanners:  scanners,
		selected:           selected,
		scannerModes:       scannerModes,
		scannerStatus:      make(map[string]string),
		scannerFindings:    make(map[string]int),
		workers:            10,
		intensity:          3,
		depth:              2,
		maxPages:           50,
		throttleMS:         100,
		networkProfile:     "infrastructure",
		networkTimeoutMS:   2000,
		networkDeepScan:    false,
		progressPercent:    0,
		lastProgressUpdate: "waiting",
		activityLog:        []string{},
		showEvidence:       true,
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
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height
		m.targetInput.Width = max(48, msg.Width-24)
		m.progress.Width = max(24, msg.Width-16)
		for i := range m.configFields {
			m.configFields[i].input.Width = max(36, msg.Width-34)
		}
		return m, nil

	case scanProgressMsg:
		m.progressMsg = engine.ScanProgress(msg)
		m.uiError = ""
		m.lastProgressUpdate = fmt.Sprintf("%s: %s", msg.ScannerName, msg.Status)
		if msg.ScannerName != "" {
			m.scannerStatus[msg.ScannerName] = msg.Status
			m.scannerFindings[msg.ScannerName] = msg.FindingsCount
			m.lastProgressUpdate = fmt.Sprintf("%s: %s (%s)", msg.ScannerName, msg.Status, m.scannerGoal(msg.ScannerName))
			m.appendActivity(fmt.Sprintf("[%s] %s findings=%d", msg.ScannerName, strings.ToUpper(msg.Status), msg.FindingsCount))
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
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "esc":
				return m, tea.Quit
			case "up", "k":
				if m.scanDetailCursor > 0 {
					m.scanDetailCursor--
				}
				return m, nil
			case "down", "j":
				if m.scanDetailCursor < len(m.availableScanners)-1 {
					m.scanDetailCursor++
				}
				return m, nil
			}
		}
		return m, nil
	case stateSummary:
		if k, ok := msg.(tea.KeyMsg); ok {
			switch k.String() {
			case "enter", "esc":
				return m, tea.Quit
			case "up", "k":
				if m.summaryCursor > 0 {
					m.summaryCursor--
				}
				return m, nil
			case "down", "j":
				if m.results != nil && m.summaryCursor < len(m.results.Findings)-1 {
					m.summaryCursor++
				}
				return m, nil
			case "e":
				m.showEvidence = !m.showEvidence
				return m, nil
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
			m.uiNotice = ""
			m.state = stateScanners
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.targetInput, cmd = m.targetInput.Update(msg)
	return m, cmd
}

func scannerModeOptions(scannerType engine.ScannerType) []string {
	switch scannerType {
	case engine.ScannerHeaders, engine.ScannerFiles:
		return []string{"balanced", "aggressive"}
	default:
		return []string{"stealth", "balanced", "aggressive", "deep"}
	}
}

func scannerModeDescription(scannerType engine.ScannerType, mode string) string {
	switch mode {
	case "stealth":
		return "low-noise checks with smaller payload breadth"
	case "aggressive":
		return "broader payload families and stronger signal extraction"
	case "deep":
		return "maximum depth and heavy payload mutation for hard targets"
	default:
		return "standard production-friendly coverage and verification"
	}
}

func (m *mainModel) cycleScannerMode(scannerType engine.ScannerType, delta int) {
	options := scannerModeOptions(scannerType)
	current := strings.ToLower(strings.TrimSpace(m.scannerModes[scannerType]))
	if current == "" {
		current = options[0]
	}
	idx := 0
	for i := range options {
		if options[i] == current {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(options)) % len(options)
	m.scannerModes[scannerType] = options[idx]
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
			m.uiNotice = ""
			return m, nil
		case "t":
			cur := m.availableScanners[m.scannerCursor]
			m.cycleScannerMode(cur.Type, 1)
			m.uiNotice = fmt.Sprintf("%s mode -> %s", cur.Type, m.scannerModes[cur.Type])
			m.uiError = ""
			return m, nil
		case "left", "h":
			cur := m.availableScanners[m.scannerCursor]
			m.cycleScannerMode(cur.Type, -1)
			m.uiNotice = fmt.Sprintf("%s mode -> %s", cur.Type, m.scannerModes[cur.Type])
			return m, nil
		case "right", "l":
			cur := m.availableScanners[m.scannerCursor]
			m.cycleScannerMode(cur.Type, 1)
			m.uiNotice = fmt.Sprintf("%s mode -> %s", cur.Type, m.scannerModes[cur.Type])
			return m, nil
		case "a":
			for _, s := range m.availableScanners {
				m.selected[s.Type] = true
			}
			m.uiNotice = "all scanners selected"
			m.uiError = ""
			return m, nil
		case "n":
			for _, s := range m.availableScanners {
				m.selected[s.Type] = false
			}
			m.uiNotice = "all scanners cleared"
			m.uiError = ""
			return m, nil
		case "1":
			m.applyPreset("web")
			return m, nil
		case "2":
			m.applyPreset("network")
			return m, nil
		case "3":
			m.applyPreset("full")
			return m, nil
		case "i":
			for _, s := range m.availableScanners {
				m.selected[s.Type] = !m.selected[s.Type]
			}
			m.uiNotice = "selection inverted"
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
			m.uiNotice = ""
			m.state = stateConfig
			m.focusedField = 0
			m.configFields[0].input.Focus()
			return m, nil
		}
	}
	return m, nil
}

func (m *mainModel) applyPreset(preset string) {
	for _, s := range m.availableScanners {
		m.selected[s.Type] = false
		m.scannerModes[s.Type] = "balanced"
	}

	switch preset {
	case "web":
		for _, s := range m.availableScanners {
			if s.Type != engine.ScannerNetwork {
				m.selected[s.Type] = true
			}
		}
		m.scannerModes[engine.ScannerXSS] = "aggressive"
		m.scannerModes[engine.ScannerSQL] = "aggressive"
		m.scannerModes[engine.ScannerCSRF] = "deep"
		m.uiNotice = "preset applied: web app focus"
	case "network":
		enabled := map[engine.ScannerType]bool{
			engine.ScannerNetwork:          true,
			engine.ScannerSSRF:             true,
			engine.ScannerXXE:              true,
			engine.ScannerRCE:              true,
			engine.ScannerCommandInjection: true,
			engine.ScannerHeaders:          true,
			engine.ScannerFiles:            true,
		}
		for _, s := range m.availableScanners {
			if enabled[s.Type] {
				m.selected[s.Type] = true
			}
		}
		m.scannerModes[engine.ScannerNetwork] = "deep"
		m.scannerModes[engine.ScannerSSRF] = "aggressive"
		m.scannerModes[engine.ScannerRCE] = "aggressive"
		m.scannerModes[engine.ScannerCommandInjection] = "aggressive"
		m.uiNotice = "preset applied: network and privilege-escalation focus"
	default:
		for _, s := range m.availableScanners {
			m.selected[s.Type] = true
			m.scannerModes[s.Type] = "aggressive"
		}
		m.scannerModes[engine.ScannerNetwork] = "deep"
		m.uiNotice = "preset applied: full coverage"
	}
	m.uiError = ""
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
		case "left", "h":
			if m.configFields[m.focusedField].key == "network_profile" {
				m.cycleNetworkProfile(-1)
				m.parseConfigValues()
				return m, nil
			}
		case "right", "l":
			if m.configFields[m.focusedField].key == "network_profile" {
				m.cycleNetworkProfile(1)
				m.parseConfigValues()
				return m, nil
			}
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

func (m *mainModel) cycleNetworkProfile(delta int) {
	profiles := []string{"infrastructure", "web", "hybrid"}
	cur := strings.ToLower(strings.TrimSpace(m.configFields[m.focusedField].input.Value()))
	idx := 0
	for i := range profiles {
		if profiles[i] == cur {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(profiles)) % len(profiles)
	m.configFields[m.focusedField].input.SetValue(profiles[idx])
}

func (m *mainModel) parseConfigValues() {
	for i := range m.configFields {
		val := strings.TrimSpace(m.configFields[i].input.Value())
		switch m.configFields[i].key {
		case "workers":
			if v, err := strconv.Atoi(val); err == nil {
				m.workers = v
			}
		case "intensity":
			if v, err := strconv.Atoi(val); err == nil {
				m.intensity = v
			}
		case "depth":
			if v, err := strconv.Atoi(val); err == nil {
				m.depth = v
			}
		case "max_pages":
			if v, err := strconv.Atoi(val); err == nil {
				m.maxPages = v
			}
		case "throttle_ms":
			if v, err := strconv.Atoi(val); err == nil {
				m.throttleMS = v
			}
		case "network_profile":
			m.networkProfile = strings.ToLower(val)
		case "network_ports":
			m.networkPorts = val
		case "network_timeout_ms":
			if v, err := strconv.Atoi(val); err == nil {
				m.networkTimeoutMS = v
			}
		case "network_workers":
			if val == "" {
				m.networkWorkers = 0
			} else if v, err := strconv.Atoi(val); err == nil {
				m.networkWorkers = v
			}
		case "network_deep_scan":
			switch strings.ToLower(val) {
			case "1", "true", "yes", "on":
				m.networkDeepScan = true
			default:
				m.networkDeepScan = false
			}
		}
	}
}

func normalizeNetworkProfile(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "infrastructure", "infra", "web", "hybrid", "mixed", "all":
		if raw == "infra" {
			return "infrastructure"
		}
		if raw == "mixed" || raw == "all" {
			return "hybrid"
		}
		return raw
	default:
		return ""
	}
}

func (m mainModel) networkSelected() bool {
	return m.selected[engine.ScannerNetwork]
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
	if m.maxPages < 1 {
		m.uiError = "max crawl pages must be >= 1"
		return m, nil
	}
	if m.throttleMS < 0 {
		m.uiError = "throttle must be >= 0"
		return m, nil
	}

	networkProfile := normalizeNetworkProfile(m.networkProfile)
	if m.networkSelected() {
		if networkProfile == "" {
			m.uiError = "network profile must be infrastructure, web, or hybrid"
			return m, nil
		}
		if m.networkTimeoutMS < 100 {
			m.uiError = "network timeout must be >= 100ms"
			return m, nil
		}
		if m.networkWorkers < 0 {
			m.uiError = "network workers must be >= 0"
			return m, nil
		}
	}

	m.state = stateScanning
	m.scanStartedAt = time.Now()
	m.progressPercent = 0
	m.lastProgressUpdate = "starting scan"
	m.scannerStatus = make(map[string]string)
	m.scannerFindings = make(map[string]int)
	m.uiError = ""
	m.uiNotice = ""
	m.activityLog = []string{fmt.Sprintf("[setup] target=%s", m.targetURL)}

	enabled := make([]engine.ScannerType, 0, m.selectedCount())
	for _, s := range m.availableScanners {
		if m.selected[s.Type] {
			enabled = append(enabled, s.Type)
		}
	}

	scannerOptions := make(map[string]string)
	for _, s := range m.availableScanners {
		if !m.selected[s.Type] {
			continue
		}
		mode := strings.TrimSpace(strings.ToLower(m.scannerModes[s.Type]))
		if mode == "" {
			mode = "balanced"
		}
		scannerOptions["mode_"+string(s.Type)] = mode
	}
	if m.networkSelected() {
		scannerOptions["network_profile"] = networkProfile
		scannerOptions["network_timeout_ms"] = strconv.Itoa(m.networkTimeoutMS)
		if strings.TrimSpace(m.networkPorts) != "" {
			scannerOptions["network_ports"] = strings.TrimSpace(m.networkPorts)
		}
		if m.networkWorkers > 0 {
			scannerOptions["network_workers"] = strconv.Itoa(m.networkWorkers)
		}
		if m.networkDeepScan {
			scannerOptions["network_deep_scan"] = "true"
		}
	}

	config := engine.ScanConfig{
		Target:          m.targetURL,
		EnabledScanners: enabled,
		Workers:         m.workers,
		Intensity:       m.intensity,
		MaxDepth:        m.depth,
		MaxPages:        m.maxPages,
		Throttle:        time.Duration(m.throttleMS) * time.Millisecond,
		CustomPayloads:  make(map[string][]string),
		ScannerOptions:  scannerOptions,
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

func (m *mainModel) appendActivity(line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	m.activityLog = append(m.activityLog, line)
	if len(m.activityLog) > 40 {
		m.activityLog = m.activityLog[len(m.activityLog)-40:]
	}
}

func (m mainModel) scannerInfoByType(scannerType string) (engine.ScannerInfo, bool) {
	for _, info := range m.availableScanners {
		if string(info.Type) == scannerType {
			return info, true
		}
	}
	return engine.ScannerInfo{}, false
}

func (m mainModel) scannerGoal(scannerType string) string {
	if info, ok := m.scannerInfoByType(scannerType); ok {
		return info.Description
	}
	return "running vulnerability checks"
}

func (m mainModel) scannerMethod(scannerType string) string {
	switch scannerType {
	case string(engine.ScannerXSS):
		return "payload reflection + DOM pattern checks"
	case string(engine.ScannerCSRF):
		return "form discovery + anti-CSRF token validation"
	case string(engine.ScannerSQL):
		return "injection payload probes + SQL error signals"
	case string(engine.ScannerLFI):
		return "path traversal payload probes"
	case string(engine.ScannerSSRF):
		return "URL parameter probes to internal resources"
	case string(engine.ScannerCommandInjection):
		return "shell metacharacter payload probes"
	case string(engine.ScannerRCE):
		return "code execution payload heuristics"
	case string(engine.ScannerDirectoryTraversal):
		return "dot-dot-slash traversal checks"
	case string(engine.ScannerXXE):
		return "XML entity payload checks"
	case string(engine.ScannerOpenRedirect):
		return "redirect parameter tampering"
	case string(engine.ScannerHeaders):
		return "security header presence checks"
	case string(engine.ScannerFiles):
		return "common sensitive path discovery"
	case string(engine.ScannerNetwork):
		return "infrastructure port/service exposure checks"
	default:
		return "automated scanner logic"
	}
}

func findingGoal(findingType string) string {
	switch strings.ToLower(findingType) {
	case "xss":
		return "find reflected/stored script execution paths"
	case "csrf":
		return "find state-changing forms without CSRF protection"
	case "sql":
		return "find SQL parser errors and injectable parameters"
	case "lfi":
		return "find local file inclusion and traversal read paths"
	case "ssrf":
		return "find server-side request pivot paths"
	case "command injection":
		return "find command execution vectors through input"
	case "rce":
		return "find remote code execution primitives"
	case "directory traversal":
		return "find out-of-root file access paths"
	case "xxe":
		return "find XML parser entity expansion vectors"
	case "open redirect":
		return "find unsafe redirect destinations"
	case "headers":
		return "find missing hardening headers"
	case "files":
		return "find exposed sensitive files"
	case "network service":
		return "find exposed ports, admin planes, and pivot paths"
	default:
		return "identify suspicious behavior requiring review"
	}
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

func (m mainModel) renderTopBar() string {
	stage := map[vulnSessionState]string{
		stateTarget:   "Target",
		stateScanners: "Scanners",
		stateConfig:   "Config",
		stateScanning: "Scanning",
		stateSummary:  "Summary",
	}[m.state]

	left := fmt.Sprintf("Stage: %s", stage)
	right := fmt.Sprintf("Selected: %d/%d", m.selectedCount(), len(m.availableScanners))
	if m.state == stateScanning {
		right = fmt.Sprintf("Progress: %d%%", int(m.progressPercent*100))
	}

	available := max(20, m.windowWidth-8)
	space := available - lipgloss.Width(left) - lipgloss.Width(right)
	if space < 1 {
		space = 1
	}
	line := left + strings.Repeat(" ", space) + right
	return tui.RenderBox(line)
}

func (m mainModel) renderScannerPicker() string {
	var list strings.Builder
	list.WriteString(tui.RenderTitle("Scanner Selection"))
	list.WriteString("\n")
	list.WriteString(fmt.Sprintf("Selected: %d/%d\n\n", m.selectedCount(), len(m.availableScanners)))

	for i, s := range m.availableScanners {
		cursor := " "
		if i == m.scannerCursor {
			cursor = ">"
		}
		check := "[ ]"
		if m.selected[s.Type] {
			check = "[x]"
		}
		mode := m.scannerModes[s.Type]
		if mode == "" {
			mode = "balanced"
		}
		line := fmt.Sprintf("%s %s %-28s mode=%-10s ", cursor, check, s.Name, mode)
		list.WriteString(line)
		list.WriteString(m.scannerSeverityStyle(s.Severity).Render("[" + strings.ToUpper(s.Severity) + "]"))
		list.WriteString("\n")
	}

	detail := ""
	if len(m.availableScanners) > 0 {
		current := m.availableScanners[m.scannerCursor]
		mode := m.scannerModes[current.Type]
		if mode == "" {
			mode = "balanced"
		}
		detail = tui.RenderBox(fmt.Sprintf("Type: %s\nMode: %s\nGoal: %s\nMethod: %s\nMode effect: %s", current.Type, mode, current.Description, m.scannerMethod(string(current.Type)), scannerModeDescription(current.Type, mode)))
	}

	presets := tui.RenderBox("Presets\n1: Web App\n2: Network / Priv-Esc\n3: Full Coverage")

	leftW := max(60, m.windowWidth/2)
	rightW := max(38, m.windowWidth-leftW-10)
	leftPanel := lipgloss.NewStyle().Width(leftW).Render(list.String())
	rightPanel := lipgloss.NewStyle().Width(rightW).Render(detail + "\n\n" + presets)

	var body string
	if m.windowWidth > 120 {
		body = lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, "  ", rightPanel)
	} else {
		body = leftPanel + "\n" + rightPanel
	}

	var footer strings.Builder
	if m.uiError != "" {
		footer.WriteString("\n" + tui.RenderError(m.uiError))
	} else if m.uiNotice != "" {
		footer.WriteString("\n" + tui.RenderInfo(m.uiNotice))
	}
	footer.WriteString("\n\n")
	footer.WriteString(tui.RenderHelp("j/k or arrows: move | space: toggle | t or h/l: cycle mode | 1/2/3: presets | a: all | n: none | i: invert | b: back | enter: continue | esc: quit"))

	return body + footer.String()
}

func (m mainModel) renderConfig() string {
	var b strings.Builder
	b.WriteString(tui.RenderTitle("Scan Configuration"))
	b.WriteString("\n")
	if m.networkSelected() {
		b.WriteString(tui.RenderInfo("Network scanner selected: architecture options will be applied."))
	} else {
		b.WriteString(tui.RenderWarning("Network scanner not selected: network options will be ignored."))
	}
	b.WriteString("\n\n")

	for i, f := range m.configFields {
		prefix := "APP"
		if strings.HasPrefix(f.key, "network_") {
			prefix = "NET"
		}

		line := fmt.Sprintf("[%s] %s", prefix, f.label)
		if i == m.focusedField {
			b.WriteString(tui.SelectedItemStyle.Render("> " + line))
		} else {
			b.WriteString(tui.NormalItemStyle.Render("  " + line))
		}
		b.WriteString("\n")
		b.WriteString(f.input.View())
		b.WriteString("\n\n")
	}

	if m.uiError != "" {
		b.WriteString(tui.RenderError(m.uiError) + "\n")
	}
	b.WriteString(tui.RenderHelp("tab/arrows: move | left/right on Network Profile: cycle | enter on last field or ctrl+s: start | b: back | esc: quit"))
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
		mode := m.scannerModes[info.Type]
		if mode == "" {
			mode = "balanced"
		}
		b.WriteString(fmt.Sprintf("- %-24s %s findings=%d mode=%s\n", string(info.Type), status, findings, mode))
	}

	selectedScanners := make([]engine.ScannerInfo, 0, len(m.availableScanners))
	for _, info := range m.availableScanners {
		if m.selected[info.Type] {
			selectedScanners = append(selectedScanners, info)
		}
	}
	if len(selectedScanners) > 0 {
		if m.scanDetailCursor < 0 {
			m.scanDetailCursor = 0
		}
		if m.scanDetailCursor >= len(selectedScanners) {
			m.scanDetailCursor = len(selectedScanners) - 1
		}
		cur := selectedScanners[m.scanDetailCursor]
		mode := m.scannerModes[cur.Type]
		if mode == "" {
			mode = "balanced"
		}
		b.WriteString("\nFocused scanner:\n")
		b.WriteString(fmt.Sprintf("- %s (%s)\n", cur.Name, cur.Type))
		b.WriteString(fmt.Sprintf("- mode: %s\n", mode))
		b.WriteString(fmt.Sprintf("- technique: %s\n", m.scannerMethod(string(cur.Type))))
		b.WriteString(fmt.Sprintf("- mode effect: %s\n", scannerModeDescription(cur.Type, mode)))
	}

	b.WriteString("\nRecent activity:\n")
	if len(m.activityLog) == 0 {
		b.WriteString("- waiting for first scanner event...\n")
	} else {
		start := len(m.activityLog) - 10
		if start < 0 {
			start = 0
		}
		for i := start; i < len(m.activityLog); i++ {
			b.WriteString("- " + m.activityLog[i] + "\n")
		}
	}
	b.WriteString("\n")
	if m.progressMsg.Error != nil {
		b.WriteString(tui.RenderError(m.progressMsg.Error.Error()))
	} else {
		b.WriteString(tui.RenderInfo("Scan running. j/k to inspect scanner details, esc to quit."))
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

		if len(m.results.Findings) > 0 {
			if m.summaryCursor >= len(m.results.Findings) {
				m.summaryCursor = len(m.results.Findings) - 1
			}
			if m.summaryCursor < 0 {
				m.summaryCursor = 0
			}
			b.WriteString("\nFindings Browser:\n")
			window := 10
			start := m.summaryCursor - window/2
			if start < 0 {
				start = 0
			}
			end := start + window
			if end > len(m.results.Findings) {
				end = len(m.results.Findings)
			}
			for i := start; i < end; i++ {
				cursor := " "
				if i == m.summaryCursor {
					cursor = ">"
				}
				f := m.results.Findings[i]
				b.WriteString(fmt.Sprintf("%s [%s] %s | %s\n", cursor, f.Severity, f.Type, f.URL))
			}

			f := m.results.Findings[m.summaryCursor]
			b.WriteString("\nSelected Finding Detail:\n")
			b.WriteString(fmt.Sprintf("- Name: %s\n", f.Name))
			b.WriteString(fmt.Sprintf("- Type: %s\n", f.Type))
			b.WriteString(fmt.Sprintf("- Severity: %s\n", f.Severity))
			if f.Method != "" {
				b.WriteString(fmt.Sprintf("- Method: %s\n", f.Method))
			}
			if f.Param != "" {
				b.WriteString(fmt.Sprintf("- Parameter: %s\n", f.Param))
			}
			if f.Payload != "" {
				b.WriteString(fmt.Sprintf("- Payload: %s\n", f.Payload))
			}
			b.WriteString(fmt.Sprintf("- Scanner Goal: %s\n", findingGoal(f.Type)))
			if m.showEvidence && f.Evidence != "" {
				b.WriteString(fmt.Sprintf("- Evidence: %s\n", f.Evidence))
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(tui.RenderHelp("j/k or arrows: browse findings | e: toggle evidence | enter/esc: exit"))
	return b.String()
}

func (m mainModel) View() string {
	var s strings.Builder
	s.WriteString(tui.GetScaryLogo())
	s.WriteString("\n")
	s.WriteString(m.renderTopBar())
	s.WriteString("\n\n")

	switch m.state {
	case stateTarget:
		s.WriteString(tui.RenderTitle("Target Selection"))
		s.WriteString("\n")
		s.WriteString(tui.InputLabelStyle.Render("Target URL:"))
		s.WriteString("\n")
		s.WriteString(tui.FocusedInputStyle.Render(m.targetInput.View()))
		if m.uiError != "" {
			s.WriteString("\n" + tui.RenderError(m.uiError))
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Interact runs the vulnerability scanner TUI.
func Interact() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("scanner UI error: %v", err)
		os.Exit(1)
	}
}
