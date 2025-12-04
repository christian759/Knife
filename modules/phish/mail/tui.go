package mail

import (
	"fmt"
	"knife/tui"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type mailFormField struct {
	label       string
	placeholder string
	value       string
	input       textinput.Model
}

type mailFormModel struct {
	fields  []mailFormField
	focused int
	done    bool
}

func newMailFormModel() mailFormModel {
	fields := []mailFormField{
		{
			label:       "Heading",
			placeholder: "Title of the Email",
		},
		{
			label:       "Sender's Email",
			placeholder: "sender@example.com",
		},
		{
			label:       "Sender's Name",
			placeholder: "John Doe",
		},
		{
			label:       "Recipient's Email",
			placeholder: "recipient@example.com",
		},
		{
			label:       "Cc",
			placeholder: "[Optional]",
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

	return mailFormModel{
		fields: fields,
	}
}

func (m mailFormModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m mailFormModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

func (m mailFormModel) View() string {
	var s strings.Builder
	s.WriteString(tui.RenderTitle("Automated Email Phishing"))
	s.WriteString("\n\n")
	s.WriteString(tui.RenderSubtitle("This tool checks for sending emails and phishing"))
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

// Interact runs the mail phishing module with TUI
func RunEmailPhishModule() {
	// Main form
	p := tea.NewProgram(newMailFormModel())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	m, ok := finalModel.(mailFormModel)
	if !ok || !m.done {
		return
	}

	heading := strings.TrimSpace(m.fields[0].value)
	if heading == "" {
		fmt.Println(tui.RenderError("Heading is required"))
		return
	}

	// Start comprehensive scan
	fmt.Println()
	fmt.Println(tui.RenderWarning("This will run ALL vulnerability scanners and may take several minutes..."))
	fmt.Println()
	time.Sleep(2 * time.Second)

	fmt.Println()
}
