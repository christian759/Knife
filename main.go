package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
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
	list      list.Model
	chosen    string
	quit      bool
	fontLines []string // Store the loaded font data
	header    string   // Store the rendered header string
	width     int      // Store terminal width
}

func (m mainModel) Init() tea.Cmd {
	return nil
}

// updateHeader regenerates the header string
// This is called on init and on window resize.
func (m *mainModel) updateHeader() {
	// 1. Generate ASCII Art
	argStr := "Go-Knife"
	sepArgs := strings.Split(argStr, "\\n")

	// Use the model's width and fontLines
	// We pass m.width-4 to account for the margin
	art := generateAsciiArt(sepArgs, m.fontLines, "left", m.width-4)

	// 2. Render Titles (assuming these return strings)
	title := tui.RenderTitle("KNIFE - Penetration Testing Toolkit")
	subtitle := tui.RenderSubtitle("Select a module to begin")

	// 3. Combine them using a strings.Builder
	var sb strings.Builder
	sb.WriteString(art)
	sb.WriteString("\n") // Add a newline after art
	sb.WriteString(title)
	sb.WriteString("\n") // Add newline after title
	sb.WriteString(subtitle)
	// sb.WriteString("\n") // No need for last newline, JoinVertical will handle it

	m.header = sb.String()
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
		m.width = msg.Width // Store the new width
		m.updateHeader()    // Regenerate the header

		// Calculate layout
		marginStyle := lipgloss.NewStyle().Margin(1, 2)
		h, v := marginStyle.GetFrameSize()

		// Calculate header height
		headerHeight := strings.Count(m.header, "\n")
		if m.header != "" {
			headerHeight++ // account for the content lines
		}

		// Set list size
		listHeight := msg.Height - v - headerHeight
		m.list.SetSize(msg.Width-h, listHeight)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m mainModel) View() string {
	if m.quit {
		return ""
	}
	// Combine header and list vertically
	content := lipgloss.JoinVertical(lipgloss.Top, m.header, m.list.View())
	// Render with margin
	return lipgloss.NewStyle().Margin(1, 2).Render(content)
}

// This is your refactored function.
// It no longer prints, it returns a string.
func generateAsciiArt(sentences []string, textFile []string, position string, w int) string {
	var sb strings.Builder // Use a string builder for efficiency

	for i, word := range sentences {
		if word == "" {
			if i != 0 {
				sb.WriteRune('\n') // Was fmt.Println()
			}
			continue
		}
		wordCount := 1
		for _, char := range word {
			if char == ' ' {
				wordCount++
			}
		}
		wordLen := 0
		for i := 0; i < len(word); i++ {
			for lineIndex, line := range textFile {
				// Added a check to prevent index out of range
				if i < len(word) && lineIndex == (int(word[i])-32)*9+2 {
					wordLen += len(line)
					break
				}
			}
		}
		var spacesForJustify int
		originalPosition := position // Store original position
		if wordCount == 1 && position == "justify" {
			position = "center"
		} else if wordCount == 1 {
			if w > wordLen {
				spacesForJustify = (w - wordLen) / wordCount
			}
		} else {
			if w > wordLen && wordCount > 1 {
				spacesForJustify = (w - wordLen) / (wordCount - 1)
			}
		}

		spaces := 0
		if w > wordLen {
			spaces = w/2 - wordLen/2
		}

		for h := 1; h < 9; h++ {
			switch position {
			case "center":
				for i := 1; i <= spaces; i++ {
					sb.WriteString(" ") // Was fmt.Print(" ")
				}
			case "right":
				for i := 1; i <= spaces*2; i++ {
					sb.WriteString(" ") // Was fmt.Print(" ")
				}
			}
			for i := 0; i < len(word); i++ {
				for lineIndex, line := range textFile {
					if i < len(word) && lineIndex == (int(word[i])-32)*9+h { // Added check
						if position == "justify" && i != len(word)-1 && word[i] == ' ' {
							sb.WriteString(line) // Was fmt.Print(line)
							for i := 1; i <= spacesForJustify; i++ {
								sb.WriteString(" ") // Was fmt.Print(" ")
							}
						} else {
							sb.WriteString(line) // Was fmt.Print(line)
						}
						break
					}
				}
			}
			switch position {
			case "center":
				for i := 1; i <= spaces; i++ {
					sb.WriteString(" ") // Was fmt.Print(" ")
				}
			case "left":
				for i := 1; i <= spaces*2; i++ {
					sb.WriteString(" ") // Was fmt.Print(" ")
				}
			}
			// Only add newline if it's not the last line of the last sentence
			if h < 8 || i < len(sentences)-1 {
				sb.WriteRune('\n') // Was fmt.Println()
			}
		}
		position = originalPosition // Reset position for next loop
	}
	return sb.String() // Return the final, built string
}

func main() {
	// getTerminalSize() is no longer needed. Bubble Tea provides this.

	// Load the font file
	file, err := os.ReadFile("letters.txt")
	if err != nil {
		fmt.Println("Error reading letters.txt:", err)
		os.Exit(1)
	}
	lines := strings.Split(string(file), "\n")

	// All printing logic is removed from main
	// fmt.Println(...)

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

	// Create the model and pass in the font data
	m := mainModel{
		list:      l,
		fontLines: lines,
	}

	// Run bubble tea program
	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Handle selection (this part was already correct)
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
