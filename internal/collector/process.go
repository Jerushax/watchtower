package collector

import (
	"context"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"watchtower/internal/telemetry"
)

type ProcessCollector struct {
	seen map[int32]bool
	out  chan telemetry.TelemetryEvent
}

func NewProcessCollector(
	out chan telemetry.TelemetryEvent,
) *ProcessCollector {

	return &ProcessCollector{
		seen: make(map[int32]bool),
		out:  out,
	}
}

func (p *ProcessCollector) Run(ctx context.Context) {

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {

		case <-ctx.Done():
			return

		case <-ticker.C:
			p.collect()
		}
	}
}

func (p *ProcessCollector) collect() {

	processes, err := process.Processes()
	if err != nil {
		return
	}

	for _, proc := range processes {

		if p.seen[proc.Pid] {
			continue
		}

		p.seen[proc.Pid] = true

		name, _ := proc.Name()

		if name == "" {
			continue
		}

		cmdline, _ := proc.Cmdline()
		exe, _ := proc.Exe()
		ppid, _ := proc.Ppid()
		cpu, _ := proc.CPUPercent()
		parentName := "unknown"

		parentProc, err := process.NewProcess(ppid)

		if err == nil {

			parent, err := parentProc.Name()

			if err == nil {
				parentName = parent
			}
		}
		event := telemetry.TelemetryEvent{
			Timestamp:   time.Now(),
			Type:        telemetry.ProcessEvent,
			ProcessName: name,
			PID:         proc.Pid,
			PPID:        ppid,
			ParentName: parentName,
			Path:        exe,
			CommandLine: cmdline,
			CPUPercent:  cpu,
		}

		if isInteresting(event) {
			p.out <- event
		}
	}
}

func isInteresting(
	event telemetry.TelemetryEvent,
) bool {

	cmd := strings.ToLower(event.CommandLine)
	path := strings.ToLower(event.Path)
	name := strings.ToLower(event.ProcessName)

	suspicious := []string{
		"powershell",
		"-enc",
		"encodedcommand",
		"iex",
		"downloadstring",
		"frombase64string",
		"invoke-webrequest",
		"net.webclient",

		"cmd.exe",
		"wscript",
		"cscript",
		"rundll32",
		"mshta",

		"xmrig",
		"lolminer",
		"nbminer",
		"trex",

		"temp",
		"appdata",
	}

	for _, s := range suspicious {

		if strings.Contains(cmd, s) ||
			strings.Contains(path, s) ||
			strings.Contains(name, s) {

			return true
		}
	}

	return false
}