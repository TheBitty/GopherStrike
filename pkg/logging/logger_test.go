package logging

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoggerLevels(t *testing.T) {
	// Create a buffer to capture logs
	var buf bytes.Buffer

	// Create a new logger with a buffer as the writer
	logger := New(DEBUG)

	// Replace standard writers with our buffer
	for level := DEBUG; level <= CRITICAL; level++ {
		logger.writers[level] = []io.Writer{&buf}
	}

	// Log messages at different levels
	logger.Debug("This is a debug message")
	logger.Info("This is an info message")
	logger.Warning("This is a warning message")
	logger.Error("This is an error message")
	logger.Critical("This is a critical message")

	// Check if all messages were logged
	output := buf.String()

	if !strings.Contains(output, "DEBUG") {
		t.Error("Debug message was not logged")
	}

	if !strings.Contains(output, "INFO") {
		t.Error("Info message was not logged")
	}

	if !strings.Contains(output, "WARNING") {
		t.Error("Warning message was not logged")
	}

	if !strings.Contains(output, "ERROR") {
		t.Error("Error message was not logged")
	}

	if !strings.Contains(output, "CRITICAL") {
		t.Error("Critical message was not logged")
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	// Create a buffer to capture logs
	var buf bytes.Buffer

	// Create a new logger with INFO level
	logger := New(INFO)

	// Replace standard writers with our buffer
	for level := DEBUG; level <= CRITICAL; level++ {
		logger.writers[level] = []io.Writer{&buf}
	}

	// Log messages at different levels
	logger.Debug("This is a debug message")
	logger.Info("This is an info message")

	// Check if only INFO message was logged
	output := buf.String()

	if strings.Contains(output, "DEBUG") {
		t.Error("Debug message was logged when level was INFO")
	}

	if !strings.Contains(output, "INFO") {
		t.Error("Info message was not logged")
	}
}

func TestLoggerFileHandler(t *testing.T) {
	// Create a temporary directory for log files
	tempDir, err := os.MkdirTemp("", "logger_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a log file path
	logPath := filepath.Join(tempDir, "test.log")

	// Create a new logger
	logger := New(DEBUG)

	// Add a file handler
	err = logger.AddFileHandler(logPath, INFO)
	if err != nil {
		t.Fatalf("Failed to add file handler: %v", err)
	}

	// Log messages
	logger.Debug("This is a debug message")
	logger.Info("This is an info message")
	logger.Warning("This is a warning message")

	// Give the logger time to write to the file
	time.Sleep(100 * time.Millisecond)

	// Read the log file
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// Check if INFO and WARNING messages were logged to the file
	fileContent := string(content)

	if strings.Contains(fileContent, "DEBUG") {
		t.Error("Debug message was logged to file when minimum level was INFO")
	}

	if !strings.Contains(fileContent, "INFO") {
		t.Error("Info message was not logged to file")
	}

	if !strings.Contains(fileContent, "WARNING") {
		t.Error("Warning message was not logged to file")
	}
}

func TestGetModuleLogger(t *testing.T) {
	// Get a module logger
	logger := GetModuleLogger("testmodule")

	// Verify the logger was created
	if logger == nil {
		t.Error("GetModuleLogger returned nil")
	}

	// Check if log directory was created
	logDir := filepath.Join("logs", "testmodule")
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		t.Error("Log directory was not created")
	} else {
		// Clean up
		os.RemoveAll(logDir)
	}
}
