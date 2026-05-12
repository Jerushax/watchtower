package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"watchtower/internal/collector"
	"watchtower/internal/detection"
	"watchtower/internal/logger"
	"watchtower/internal/telemetry"
)

func main() {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := logger.NewLogger()

	eventChan := make(chan telemetry.TelemetryEvent, 2048)

	procCollector := collector.NewProcessCollector(eventChan)

	engine, err := detection.NewEngine("rules")
	if err != nil {
		panic(err)
	}

	go procCollector.Run(ctx)

	sigChan := make(chan os.Signal, 1)

	signal.Notify(sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down WatchTower...")
		cancel()
	}()

	fmt.Println("🛡 WatchTower Behavioral Engine Active")

	for {
		select {

		case <-ctx.Done():
			return

		case event := <-eventChan:

			detections := engine.Evaluate(event)

			for _, det := range detections {

				fmt.Println("===================================")
				fmt.Printf("[ALERT] %s\n", det.Name)
				fmt.Printf("Severity: %s\n", det.Severity)
				fmt.Printf("Score: %d\n", det.Score)
				fmt.Printf("Process: %s\n", det.Event.ProcessName)
				fmt.Printf("Parent: %s\n", det.Event.ParentName)
				
				fmt.Printf("PID: %d\n", det.Event.PID)
				fmt.Printf("Path: %s\n", det.Event.Path)
				fmt.Printf("CMD: %s\n", det.Event.CommandLine)
				fmt.Println("===================================")

				log.Warn().
					Str("severity", det.Severity).
					Str("process", det.Event.ProcessName).
					Str("cmdline", det.Event.CommandLine).
					Int("score", det.Score).
					Msg(det.Name)
			}
		}
	}
}