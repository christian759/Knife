package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"

	"knife/modules/mobile"
	"knife/modules/phish"
	"knife/modules/vuln"
	"knife/modules/wifi"
	"knife/tui"
)

const (
	ModuleMobile = "Mobile attack"
	ModulePhish  = "Phishing"
	ModuleVuln   = "Web vulnerability"
	ModuleWifi   = "Wifi attack"
)

type moduleItem struct {
	title       string
	description string
}

func (i moduleItem) Title() string       { return i.title }
func (i moduleItem) Description() string { return i.description }
func (i moduleItem) FilterValue() string { return i.title }

type mainModel struct {
	list   list.Model
	chosen string
	quit   bool
}

func (m mainModel) Init() tea.Cmd {
	return nil
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quit = true
			return m, tea.Quit
		case "enter":
			if i, ok := m.list.SelectedItem().(moduleItem); ok {
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

func (m mainModel) View() string {
	if m.quit {
		return ""
	}
	return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
}

func main() {
	// Display title
	fmt.Println()
	fmt.Println(tui.RenderTitle("KNIFE - Penetration Testing Toolkit"))
	fmt.Println(tui.RenderSubtitle("Select a module to begin"))
	fmt.Println()

	// Create module items
	items := []list.Item{
		moduleItem{
			title:       ModuleMobile,
			description: "APK injection, reconnaissance, and monitoring",
		},
		moduleItem{
			title:       ModulePhish,
			description: "Multi-template phishing server (Facebook, Gmail, Instagram, Netflix, Outlook)",
		},
		moduleItem{
			title:       ModuleVuln,
			description: "Automated web vulnerability scanner (XSS, SQLi, LFI, RCE)",
		},
		moduleItem{
			title:       ModuleWifi,
			description: "WiFi security testing tools (Deauth, Evil Twin, Handshake, etc.)",
		},
	}

	// Create list
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New(items, delegate, 0, 0)
	l.Title = "📋 Available Modules"
	l.Styles.Title = tui.TitleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	m := mainModel{list: l}

	// Run bubble tea program
	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Handle selection
	if m, ok := finalModel.(mainModel); ok && m.chosen != "" {
		switch m.chosen {
		case ModuleMobile:
			mobile.RunMobileModule()
		case ModulePhish:
			phish.RunPhishModule()
		case ModuleVuln:
			vuln.Interact()
		case ModuleWifi:
			wifi.RunWifiModule()
		}
	}
}
