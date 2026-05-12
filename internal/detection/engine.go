package detection

import (
    "strings"

    "watchtower/internal/telemetry"
)

type Detection struct {
    Name     string
    Severity string
    Score    int
    Reason   string
    Event    telemetry.TelemetryEvent
}

type Engine struct {
    Rules []*Rule
}

func NewEngine(ruleDir string) (*Engine, error) {

    rules, err := LoadRules(ruleDir)
    if err != nil {
        return nil, err
    }

    return &Engine{
        Rules: rules,
    }, nil
}

func (e *Engine) Evaluate(
    event telemetry.TelemetryEvent,
) []Detection {

    var detections []Detection

    cmd := strings.ToLower(event.CommandLine)
    path := strings.ToLower(event.Path)

    for _, rule := range e.Rules {

        for _, match := range rule.Matches {

            if strings.Contains(cmd, strings.ToLower(match)) ||
                strings.Contains(path, strings.ToLower(match)) {

                detections = append(detections, Detection{
                    Name:     rule.Name,
                    Severity: rule.Severity,
                    Score:    rule.Score,
                    Reason:   match,
                    Event:    event,
                })
            }
        }
    }
    parentDetection := DetectParentChildAnomaly(
        event,
        event.ParentName,
    )

    if parentDetection != nil {
        detections = append(detections, *parentDetection)
    }

    tempDetection := DetectTempExecution(event)
    if tempDetection != nil {
        detections = append(detections, *tempDetection)
    }

    return detections
}
