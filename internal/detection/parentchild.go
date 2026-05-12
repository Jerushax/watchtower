package detection

import (
	"strings"

	"watchtower/internal/telemetry"
)

var suspiciousParentChild = map[string][]string{

	"winword.exe": {
		"powershell.exe",
		"cmd.exe",
		"wscript.exe",
		"cscript.exe",
		"mshta.exe",
	},

	"excel.exe": {
		"powershell.exe",
		"cmd.exe",
		"wscript.exe",
	},

	"outlook.exe": {
		"powershell.exe",
		"cmd.exe",
		"rundll32.exe",
	},

	"chrome.exe": {
		"powershell.exe",
	},

	"acrord32.exe": {
		"powershell.exe",
		"cmd.exe",
	},
}

func DetectParentChildAnomaly(
	event telemetry.TelemetryEvent,
	parentName string,
) *Detection {

	child := strings.ToLower(event.ProcessName)
	parent := strings.ToLower(parentName)

	children, exists := suspiciousParentChild[parent]

	if !exists {
		return nil
	}

	for _, suspiciousChild := range children {

		if child == suspiciousChild {

			return &Detection{
				Name:     "Suspicious Parent-Child Process",
				Severity: "high",
				Score:    50,
				Reason:   parent + " spawned " + child,
				Event:    event,
			}
		}
	}

	return nil
}