package logger

import (
    "os"

    "github.com/rs/zerolog"
)

func NewLogger() zerolog.Logger {

    file, err := os.OpenFile(
        "logs/watchtower.jsonl",
        os.O_APPEND|os.O_CREATE|os.O_WRONLY,
        0644,
    )

    if err != nil {
        panic(err)
    }

    return zerolog.New(file).
        With().
        Timestamp().
        Logger()
}
