package vuln

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"knife/tui"
)

type vulnFormField struct {
	label       string
	placeholder string
	value       string
	input       textinput.Model
}

type vulnFormModel struct {
	fields  []vulnFormField
	focused int
	done    bool
}

func newVulnFormModel() vulnFormModel {
	fields := []vulnFormField{
		{
			label:       "Target URL",
			placeholder: "http://example.com/page",
		},
		{
			label:       "Add custom headers? (Y/N)",
			placeholder: "N",
		},
		{
			label:       "Add cookies? (Y/N)",
			placeholder: "N",
		},
	}

	// Initialize text inputs
	for i := range fields {
		ti := textinput.New()
		ti.Placeholder = fields[i].placeholder
		ti.CharLimit = 512
		ti.Width = 60
		if i == 0 {
			ti.Focus()
		}
		fields[i].input = ti
	}

	return vulnFormModel{
		fields: fields,
	}
}

func (m vulnFormModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m vulnFormModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

func (m vulnFormModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("Website Vulnerability Scanner"))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderSubtitle("This tool checks for common web vulnerabilities like XSS, SQLi, LFI, etc."))
	s.WriteString("\n\n")

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

type headerFormModel struct {
	headers  map[string]string
	input    textinput.Model
	done     bool
	canceled bool
}

func newHeaderFormModel() headerFormModel {
	ti := textinput.New()
	ti.Placeholder = "Key: Value (empty to finish)"
	ti.Focus()
	ti.CharLimit = 512
	ti.Width = 60

	return headerFormModel{
		headers: make(map[string]string),
		input:   ti,
	}
}

func (m headerFormModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m headerFormModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.canceled = true
			return m, tea.Quit
		case "enter":
			value := strings.TrimSpace(m.input.Value())
			if value == "" {
				// Done entering headers
				m.done = true
				return m, tea.Quit
			}

			// Parse header
			parts := strings.SplitN(value, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				m.headers[key] = val
				m.input.SetValue("")
			}
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m headerFormModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("Add Custom Headers"))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderSubtitle("Enter each header in 'Key: Value' format. Leave blank to finish."))
	s.WriteString("\n\n")

	// Show existing headers
	if len(m.headers) > 0 {
		s.WriteString(tui.RenderInfo("Current headers:"))
		s.WriteString("\n")
		for k, v := range m.headers {
			s.WriteString(fmt.Sprintf("  • %s: %s\n", k, v))
		}
		s.WriteString("\n")
	}

	s.WriteString(tui.InputLabelStyle.Render("Header: "))
	s.WriteString("\n")
	s.WriteString(tui.FocusedInputStyle.Render(m.input.View()))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderHelp("enter: add header (or finish if empty) • q/esc: cancel"))

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

type cookieFormModel struct {
	input    textinput.Model
	value    string
	done     bool
	canceled bool
}

func newCookieFormModel() cookieFormModel {
	ti := textinput.New()
	ti.Placeholder = "key1=val1; key2=val2"
	ti.Focus()
	ti.CharLimit = 512
	ti.Width = 60

	return cookieFormModel{
		input: ti,
	}
}

func (m cookieFormModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m cookieFormModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.canceled = true
			return m, tea.Quit
		case "enter":
			m.value = strings.TrimSpace(m.input.Value())
			m.done = true
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m cookieFormModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("Add Cookies"))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderSubtitle("Enter cookies in the format: key1=val1; key2=val2"))
	s.WriteString("\n\n")

	s.WriteString(tui.InputLabelStyle.Render("Cookies: "))
	s.WriteString("\n")
	s.WriteString(tui.FocusedInputStyle.Render(m.input.View()))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderHelp("enter: submit • q/esc: cancel"))

	return lipgloss.NewStyle().Margin(1, 2).Render(s.String())
}

// Interact runs the vulnerability scanner with TUI
func Interact() {
	// Main form
	p := tea.NewProgram(newVulnFormModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	m, ok := finalModel.(vulnFormModel)
	if !ok || !m.done {
		return
	}

	target := strings.TrimSpace(m.fields[0].value)
	if target == "" {
		fmt.Println(tui.RenderError("Target URL is required"))
		return
	}

	addHeaders := strings.TrimSpace(m.fields[1].value)
	addCookies := strings.TrimSpace(m.fields[2].value)

	// Headers
	headers := make(map[string]string)
	if strings.EqualFold(addHeaders, "Y") {
		p := tea.NewProgram(newHeaderFormModel())
		finalModel, err := p.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		if hm, ok := finalModel.(headerFormModel); ok && !hm.canceled {
			headers = hm.headers
		}
	}

	// Cookies
	cookies := ""
	if strings.EqualFold(addCookies, "Y") {
		p := tea.NewProgram(newCookieFormModel())
		finalModel, err := p.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		if cm, ok := finalModel.(cookieFormModel); ok && !cm.canceled {
			cookies = cm.value
		}
	}

	// Start comprehensive scan
	fmt.Println()
	fmt.Println(tui.RenderInfo(fmt.Sprintf("Starting comprehensive vulnerability scan on: %s", target)))
	fmt.Println(tui.RenderWarning("This will run ALL vulnerability scanners and may take several minutes..."))
	fmt.Println()
	time.Sleep(2 * time.Second)

	err = RunAllVulnScanners(target, headers, cookies)
	if err != nil {
		fmt.Println(tui.RenderError(fmt.Sprintf("Scan failed: %v", err)))
		return
	}

	fmt.Println()
	fmt.Println(tui.RenderSuccess("✓ Scan complete!"))
	fmt.Println(tui.RenderInfo(fmt.Sprintf("Total findings: %d", len(allUnifiedFindings))))
	fmt.Println(tui.RenderHelp("HTML report has been generated. Check your home directory."))
}
