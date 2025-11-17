package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
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

// getting terminal size
func getTerminalSize() (int, int, error) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}

	size := strings.Split(string(out), " ")
	width, err := strconv.Atoi(strings.TrimSpace(size[1]))
	if err != nil {
		return 0, 0, err
	}

	height, err := strconv.Atoi(strings.TrimSpace(size[0]))
	if err != nil {
		return 0, 0, err
	}

	return width, height, nil
}

func printAsciiArtAlign(sentences []string, textFile []string, position string, w int) {
	for i, word := range sentences {
		if word == "" {
			if i != 0 {
				fmt.Println()
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
				if lineIndex == (int(word[i])-32)*9+2 {
					wordLen += len(line)
					break
				}
			}
		}
		var spacesForJustify int
		if wordCount == 1 && position == "justify" {
			position = "center"
		} else if wordCount == 1 {
			spacesForJustify = (w - wordLen) / wordCount
		} else {
			spacesForJustify = (w - wordLen) / (wordCount - 1)
		}
		spaces := w/2 - wordLen/2
		for h := 1; h < 9; h++ {
			switch position {
			case "center":
				for i := 1; i <= spaces; i++ {
					fmt.Print(" ")
				}
			case "right":
				for i := 1; i <= spaces*2; i++ {
					fmt.Print(" ")
				}
			}
			for i := 0; i < len(word); i++ {
				for lineIndex, line := range textFile {
					if lineIndex == (int(word[i])-32)*9+h {
						if position == "justify" && i != len(word)-1 && word[i] == ' ' {
							fmt.Print(line)
							for i := 1; i <= spacesForJustify; i++ {
								fmt.Print(" ")
							}
						} else {
							fmt.Print(line)
						}
						break
					}
				}
			}
			switch position {
			case "center":
				for i := 1; i <= spaces; i++ {
					fmt.Print(" ")
				}
			case "left":
				for i := 1; i <= spaces*2; i++ {
					fmt.Print(" ")
				}
			}

			fmt.Println()
		}
	}
}

func main() {
	argStr := "Go-Knife"
	sepArgs := strings.Split(argStr, "\\n")

	width, _, _ := getTerminalSize()

	file, err := os.ReadFile("letters.txt")
	if err != nil {
		fmt.Println(err)
	}

	lines := strings.Split(string(file), "\n")
	printAsciiArtAlign(sepArgs, lines, "left", width)

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
