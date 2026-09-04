// Package logging provides a tiny leveled logger (slog-backed) shared across
// the scanner. All logs go to stderr so stdout stays a clean data channel.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	mu     sync.RWMutex
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
)

// Init configures the global logger from --log-level (and --debug, which forces
// debug). Called once at startup.
func Init(level string, debug bool) {
	lv := parseLevel(level)
	if debug {
		lv = slog.LevelDebug
	}
	mu.Lock()
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
	mu.Unlock()
}

// SetWriter redirects log output (used by tests).
func SetWriter(w io.Writer, level string) {
	mu.Lock()
	logger = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: parseLevel(level)}))
	mu.Unlock()
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func get() *slog.Logger { mu.RLock(); defer mu.RUnlock(); return logger }

func Debug(msg string, args ...any) { get().Debug(msg, args...) }
func Info(msg string, args ...any)  { get().Info(msg, args...) }
func Warn(msg string, args ...any)  { get().Warn(msg, args...) }
func Error(msg string, args ...any) { get().Error(msg, args...) }
