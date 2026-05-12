package telemetry

import "time"

type EventType string

const (
	ProcessEvent EventType = "process"
)

type TelemetryEvent struct {
	Timestamp time.Time `json:"timestamp"`

	Type EventType `json:"type"`

	ProcessName string `json:"process_name"`

	ParentName string `json:"parent_name"`

	PID  int32 `json:"pid"`
	PPID int32 `json:"ppid"`

	Path string `json:"path"`

	CommandLine string `json:"command_line"`

	CPUPercent float64 `json:"cpu_percent"`
}