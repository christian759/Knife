package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// Colors
	// Colors - Scary Hacker Theme
	PrimaryColor   = lipgloss.AdaptiveColor{Light: "#D63031", Dark: "#FF0000"} // Blood Red
	SecondaryColor = lipgloss.AdaptiveColor{Light: "#00B894", Dark: "#00FF41"} // Matrix Green
	AccentColor    = lipgloss.AdaptiveColor{Light: "#6C5CE7", Dark: "#A29BFE"} // Cyber Purple
	TextColor      = lipgloss.AdaptiveColor{Light: "#2D3436", Dark: "#F5F6FA"}
	SubtleColor    = lipgloss.AdaptiveColor{Light: "#636E72", Dark: "#4B4B4B"}
	WarningColor   = lipgloss.AdaptiveColor{Light: "#E17055", Dark: "#FAB1A0"}
	ErrorColor     = lipgloss.AdaptiveColor{Light: "#D63031", Dark: "#FF0000"}
	SuccessColor   = lipgloss.AdaptiveColor{Light: "#00B894", Dark: "#00FF41"}
	HackerGreen    = lipgloss.Color("#00FF41")
	BloodRed       = lipgloss.Color("#FF0000")

	// Styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(BloodRed).
			Background(lipgloss.Color("#000000")).
			Padding(0, 1).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(HackerGreen).
			Italic(true).
			MarginBottom(1)

	SelectedItemStyle = lipgloss.NewStyle().
				Foreground(AccentColor).
				Bold(true).
				PaddingLeft(2)

	NormalItemStyle = lipgloss.NewStyle().
			PaddingLeft(4)

	HelpStyle = lipgloss.NewStyle().
			Foreground(SubtleColor).
			MarginTop(1)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ErrorColor).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(SuccessColor).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(WarningColor).
			Bold(true)

	InfoStyle = lipgloss.NewStyle().
			Foreground(SecondaryColor)

	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(PrimaryColor).
			Padding(1, 2)

	InputLabelStyle = lipgloss.NewStyle().
			Foreground(SecondaryColor).
			Bold(true)

	FocusedInputStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(AccentColor)

	BlurredInputStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(SubtleColor)
)

// RenderTitle renders the main title
func RenderTitle(title string) string {
	return TitleStyle.Render(" [!] " + title + " [!] ")
}

// GetScaryLogo returns ASCII art for the scanner
func GetScaryLogo() string {
	logo := `
  ██╗  ██╗███╗   ██╗██╗███████╗███████╗
  ██║ ██╔╝████╗  ██║██║██╔════╝██╔════╝
  █████╔╝ ██╔██╗ ██║██║█████╗  █████╗  
  ██╔═██╗ ██║╚██╗██║██║██╔══╝  ██╔══╝  
  ██║  ██╗██║ ╚████║██║██║     ███████╗
  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝
    > WEB VULNERABILITY TERMINAL <
`
	return lipgloss.NewStyle().Foreground(BloodRed).Bold(true).Render(logo)
}

// RenderSubtitle renders a subtitle
func RenderSubtitle(subtitle string) string {
	return SubtitleStyle.Render("> " + subtitle)
}

// RenderError renders an error message
func RenderError(msg string) string {
	return ErrorStyle.Render("❌ " + msg)
}

// RenderSuccess renders a success message
func RenderSuccess(msg string) string {
	return SuccessStyle.Render("✅ " + msg)
}

// RenderWarning renders a warning message
func RenderWarning(msg string) string {
	return WarningStyle.Render("⚠️  " + msg)
}

// RenderInfo renders an info message
func RenderInfo(msg string) string {
	return InfoStyle.Render("ℹ️  " + msg)
}

// RenderHelp renders help text
func RenderHelp(help string) string {
	return HelpStyle.Render(help)
}

// RenderBox renders content in a box
func RenderBox(content string) string {
	return BoxStyle.Render(content)
}
