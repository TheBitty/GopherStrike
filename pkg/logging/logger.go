// pkg/logging/logger.go
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	// Log levels
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	CRITICAL
)

var levelNames = map[LogLevel]string{
	DEBUG:    "DEBUG",
	INFO:     "INFO",
	WARNING:  "WARNING",
	ERROR:    "ERROR",
	CRITICAL: "CRITICAL",
}

// Logger represents the logging system
type Logger struct {
	mu             sync.Mutex
	level          LogLevel
	writers        map[LogLevel][]io.Writer
	formatter      Formatter
	enableConsole  bool
	consoleLevel   LogLevel
	showTimestamp  bool
	showSource     bool
	sourceRelative bool
}

// Formatter is an interface for formatting log messages
type Formatter interface {
	Format(level LogLevel, msg string, source string, timestamp time.Time) string
}

// DefaultFormatter is the default log formatter
type DefaultFormatter struct {
	colored bool
}

// Format formats a log message with the default format
func (f *DefaultFormatter) Format(level LogLevel, msg string, source string, timestamp time.Time) string {
	var levelColor string
	var resetColor = "\033[0m"

	// ANSI colors
	if f.colored {
		switch level {
		case DEBUG:
			levelColor = "\033[36m" // Cyan
		case INFO:
			levelColor = "\033[32m" // Green
		case WARNING:
			levelColor = "\033[33m" // Yellow
		case ERROR:
			levelColor = "\033[31m" // Red
		case CRITICAL:
			levelColor = "\033[35m" // Magenta
		}
	}

	// Build log message with or without colors
	timeStr := timestamp.Format("2006-01-02 15:04:05")
	if f.colored {
		return fmt.Sprintf("%s [%s%s%s] %s: %s", timeStr, levelColor, levelNames[level], resetColor, source, msg)
	}
	return fmt.Sprintf("%s [%s] %s: %s", timeStr, levelNames[level], source, msg)
}

// New creates a new logger with the specified log level
func New(level LogLevel) *Logger {
	logger := &Logger{
		level:          level,
		writers:        make(map[LogLevel][]io.Writer),
		formatter:      &DefaultFormatter{colored: true},
		enableConsole:  true,
		consoleLevel:   INFO,
		showTimestamp:  true,
		showSource:     true,
		sourceRelative: true,
	}

	// Add stdout as the default writer for all levels
	stdout := os.Stdout
	logger.writers[DEBUG] = []io.Writer{stdout}
	logger.writers[INFO] = []io.Writer{stdout}
	logger.writers[WARNING] = []io.Writer{stdout}
	logger.writers[ERROR] = []io.Writer{stdout}
	logger.writers[CRITICAL] = []io.Writer{stdout}

	return logger
}

// AddFileHandler adds a file as log destination for the specified level
func (l *Logger) AddFileHandler(filePath string, level LogLevel) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Create the directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open the log file
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Add the file writer for the specified level and all higher levels
	for lvl := level; lvl <= CRITICAL; lvl++ {
		l.writers[lvl] = append(l.writers[lvl], file)
	}

	return nil
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetFormatter sets the log formatter
func (l *Logger) SetFormatter(formatter Formatter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.formatter = formatter
}

// SetConsoleOutput enables or disables console logging
func (l *Logger) SetConsoleOutput(enable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enableConsole = enable
}

// SetConsoleLevel sets the minimum level for console logging
func (l *Logger) SetConsoleLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consoleLevel = level
}

// SetTimestampDisplay enables or disables showing timestamps
func (l *Logger) SetTimestampDisplay(show bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.showTimestamp = show
}

// SetSourceDisplay enables or disables showing source information
func (l *Logger) SetSourceDisplay(show bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.showSource = show
}

// getCallerInfo returns the file and line number of the caller
func getCallerInfo(skip int) string {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "unknown:0"
	}

	// Simplify the file path for readability
	fileName := filepath.Base(file)
	return fmt.Sprintf("%s:%d", fileName, line)
}

// log writes a log message with the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Format the message
	msg := fmt.Sprintf(format, args...)

	// Get source information
	source := ""
	if l.showSource {
		source = getCallerInfo(2)
	}

	// Format the complete log entry
	timestamp := time.Now()
	logEntry := l.formatter.Format(level, msg, source, timestamp)

	// Write to all writers for this level
	for _, writer := range l.writers[level] {
		fmt.Fprintln(writer, logEntry)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Critical logs a critical message
func (l *Logger) Critical(format string, args ...interface{}) {
	l.log(CRITICAL, format, args...)
}

// Create a global logger instance
var Global = New(INFO)

// Initialize the global logger with file handlers for each module
func init() {
	// Ensure logs directory exists
	if err := os.MkdirAll("logs", 0755); err != nil {
		log.Printf("Warning: Failed to create logs directory: %v", err)
		return
	}

	// Add file handlers for each module
	modules := []string{"general", "portscan", "subdomain", "osint", "webvuln", "s3scan", "email", "dirbrute", "resolver"}

	for _, module := range modules {
		logPath := filepath.Join("logs", module, "activity.log")
		if err := Global.AddFileHandler(logPath, INFO); err != nil {
			log.Printf("Warning: Failed to create log file for %s: %v", module, err)
		}

		// Add separate error log file
		errLogPath := filepath.Join("logs", module, "errors.log")
		if err := Global.AddFileHandler(errLogPath, ERROR); err != nil {
			log.Printf("Warning: Failed to create error log file for %s: %v", module, err)
		}
	}
}

// GetModuleLogger returns a logger for a specific module
func GetModuleLogger(moduleName string) *Logger {
	logger := New(Global.level)

	// Configure the logger with module-specific settings
	logPath := filepath.Join("logs", strings.ToLower(moduleName), "activity.log")
	errLogPath := filepath.Join("logs", strings.ToLower(moduleName), "errors.log")

	// Attempt to add file handlers
	if err := logger.AddFileHandler(logPath, INFO); err != nil {
		log.Printf("Warning: Failed to create log file for %s: %v", moduleName, err)
	}

	if err := logger.AddFileHandler(errLogPath, ERROR); err != nil {
		log.Printf("Warning: Failed to create error log file for %s: %v", moduleName, err)
	}

	return logger
}
