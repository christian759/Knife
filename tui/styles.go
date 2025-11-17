package tui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	// Colors
	PrimaryColor   = lipgloss.AdaptiveColor{Light: "#FF0000", Dark: "#FF6B6B"}
	SecondaryColor = lipgloss.AdaptiveColor{Light: "#0000FF", Dark: "#4ECDC4"}
	AccentColor    = lipgloss.AdaptiveColor{Light: "#00FF00", Dark: "#95E1D3"}
	TextColor      = lipgloss.AdaptiveColor{Light: "#1A1A1A", Dark: "#FAFAFA"}
	SubtleColor    = lipgloss.AdaptiveColor{Light: "#6C6C6C", Dark: "#888888"}
	WarningColor   = lipgloss.AdaptiveColor{Light: "#FF9500", Dark: "#FFB84D"}
	ErrorColor     = lipgloss.AdaptiveColor{Light: "#FF0000", Dark: "#FF6B6B"}
	SuccessColor   = lipgloss.AdaptiveColor{Light: "#00C851", Dark: "#4ADE80"}

	// Styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(PrimaryColor).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(SecondaryColor).
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

// RenderTitle renders the main title with ASCII art style
func RenderTitle(title string) string {
	return TitleStyle.Render("🔪 " + title)
}

// RenderSubtitle renders a subtitle
func RenderSubtitle(subtitle string) string {
	return SubtitleStyle.Render(subtitle)
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
