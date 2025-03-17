package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Log levels
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"

	ColorGray = "\033[37m"
)

// Logger represents a logger instance
type Logger struct {
	level      string
	useColors  bool
	file       *os.File
	writer     io.Writer
	timeFormat string
}

// globalLogger is the default logger instance
var globalLogger *Logger

// InitLogger initializes the global logger
func InitLogger() error {
	// Default to stdout if not configured yet
	if globalLogger == nil {
		globalLogger = &Logger{
			level:      LevelInfo,
			useColors:  true,
			writer:     os.Stdout,
			timeFormat: "2006-01-02 15:04:05",
		}
	}

	// Once config is available, use it
	if Config.Logging.Level != "" {
		SetLogLevel(Config.Logging.Level)
	}

	// Determine if colors should be used
	colorMode := Config.Logging.ColorMode
	if colorMode == "auto" {
		// Auto-detect terminal capabilities
		if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
			SetColorMode(true)
		} else {
			SetColorMode(false)
		}
	} else {
		SetColorMode(colorMode == "always")
	}

	// Configure log file if specified
	if Config.Logging.File != "" {
		if err := SetLogFile(Config.Logging.File); err != nil {
			return err
		}
	}

	return nil
}

// SetLogLevel sets the minimum log level
func SetLogLevel(level string) {
	if level == "" {
		level = "info"
	}

	if globalLogger == nil {
		if err := InitLogger(); err != nil {
			fmt.Printf("Warning: Failed to initialize logger: %v\n", err)
			// Continue with default behavior even if there's an error
		}
	}

	globalLogger.level = level
}

// SetColorMode enables or disables ANSI color output
func SetColorMode(enable bool) {
	if globalLogger == nil {
		if err := InitLogger(); err != nil {
			fmt.Printf("Warning: Failed to initialize logger: %v\n", err)
			// Continue with default behavior even if there's an error
		}
	}
	globalLogger.useColors = enable
}

// SetLogFile sets the output file for logging
func SetLogFile(filePath string) error {
	if globalLogger == nil {
		err := InitLogger()
		if err != nil {
			return err
		}
	}

	// Expand ~ to home directory
	if strings.HasPrefix(filePath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			filePath = filepath.Join(homeDir, filePath[2:])
		}
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Open log file
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}

	// Close previous file if any
	if globalLogger.file != nil {
		err := globalLogger.file.Close()
		if err != nil {
			return err
		}
	}

	globalLogger.file = file

	// Use MultiWriter to write to both stdout and file
	globalLogger.writer = io.MultiWriter(os.Stdout, file)

	return nil
}

// LogLevelToInt converts a log level string to an integer for comparison
func LogLevelToInt(level string) int {
	switch level {
	case LevelDebug:
		return 0
	case LevelInfo:
		return 1
	case LevelWarn:
		return 2
	case LevelError:
		return 3
	default:
		return 1 // default to info
	}
}

// shouldLog determines if a message at the given level should be logged
func shouldLog(level string) bool {
	if globalLogger == nil {
		err := InitLogger()
		if err != nil {
			return false
		}
	}
	return LogLevelToInt(level) >= LogLevelToInt(globalLogger.level)
}

// getColorForLevel returns the ANSI color for a log level
func getColorForLevel(level string) string {
	if globalLogger == nil || !globalLogger.useColors {
		return ""
	}

	switch level {
	case LevelDebug:
		return ColorGray
	case LevelInfo:
		return ColorGreen
	case LevelWarn:
		return ColorYellow
	case LevelError:
		return ColorRed
	default:
		return ""
	}
}

// getLevelPrefix returns the formatted prefix for a log level
func getLevelPrefix(level string) string {
	prefix := strings.ToUpper(level)
	color := getColorForLevel(level)

	if color != "" {
		return fmt.Sprintf("%s%s%s", color, prefix, ColorReset)
	}

	return prefix
}

// log logs a message at the specified level
func log(level, format string, args ...interface{}) {
	if !shouldLog(level) {
		return
	}

	if globalLogger == nil {
		err := InitLogger()
		if err != nil {
			return
		}
	}

	// Get timestamp
	timestamp := time.Now().Format(globalLogger.timeFormat)

	// Format message
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf(format, args...)
	} else {
		message = format
	}

	// Final log line
	logLine := fmt.Sprintf("[%s] [%s] %s\n", timestamp, getLevelPrefix(level), message)

	// Write to the configured writer
	_, err := fmt.Fprint(globalLogger.writer, logLine)
	if err != nil {
		return
	}
}

// Debug logs a debug message
func Debug(format string, args ...interface{}) {
	log(LevelDebug, format, args...)
}

// Info logs an info message
func Info(format string, args ...interface{}) {
	log(LevelInfo, format, args...)
}

// Warn logs a warning message
func Warn(format string, args ...interface{}) {
	log(LevelWarn, format, args...)
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	log(LevelError, format, args...)
}

// CloseLogger Close closes the logger resources
func CloseLogger() {
	if globalLogger != nil && globalLogger.file != nil {
		err := globalLogger.file.Close()
		if err != nil {
			return
		}
		globalLogger.file = nil
	}
}
