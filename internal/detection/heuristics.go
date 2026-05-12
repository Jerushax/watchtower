package detection

import (
    "strings"

    "watchtower/internal/telemetry"
)

func DetectTempExecution(
    event telemetry.TelemetryEvent,
) *Detection {

    path := strings.ToLower(event.Path)

    if strings.Contains(path, "\\temp\\") ||
        strings.Contains(path, "\\appdata\\") {

        return &Detection{
            Name:     "Temp Execution",
            Severity: "medium",
            Score:    30,
            Reason:   "Process executed from temp location",
            Event:    event,
        }
    }

    return nil
}
