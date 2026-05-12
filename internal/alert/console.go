package alert

import (
    "fmt"
	"strings"
    "github.com/charmbracelet/lipgloss"

    "watchtower/internal/detection"
)

var highStyle = lipgloss.NewStyle().
    Foreground(lipgloss.Color("#FF0000")).
    Bold(true)

var mediumStyle = lipgloss.NewStyle().
    Foreground(lipgloss.Color("#FFA500")).
    Bold(true)

func PrintDetection(det detection.Detection) {

    style := mediumStyle

    if det.Severity == "high" {
        style = highStyle
    }

    fmt.Println(style.Render(
        fmt.Sprintf(
            "[%s] %s | %s",
            strings.ToUpper(det.Severity),
            det.Name,
            det.Event.ProcessName,
        ),
    ))
}
