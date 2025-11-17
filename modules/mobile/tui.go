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
	actionInjector mobileAction = "Injector"
	actionRecon    mobileAction = "Recon"
	actionMonitor  mobileAction = "Monitor"
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

// RunMobileModule displays the mobile module menu
func RunMobileModule() {
	items := []list.Item{
		actionItem{
			title:       string(actionInjector),
			description: "Inject payload into APK (requires uber-apk-signer)",
		},
		actionItem{
			title:       string(actionRecon),
			description: "Analyze APK metadata and structure",
		},
		actionItem{
			title:       string(actionMonitor),
			description: "Monitor Android device processes (requires ADB)",
		},
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New(items, delegate, 0, 0)
	l.Title = "🤖 Mobile Attack Tools"
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
		case string(actionRecon):
			runRecon()
		case string(actionMonitor):
			Monitor()
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
