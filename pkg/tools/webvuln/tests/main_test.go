package tests

import (
	"flag"
	"os"
	"testing"
)

// TestMain handles setup and teardown for all tests in this package
func TestMain(m *testing.M) {
	// Parse testing flags
	flag.Parse()

	// Setup test environment
	setupTestEnvironment()

	// Run the tests
	result := m.Run()

	// Cleanup
	cleanupTestEnvironment()

	// Exit with the test result code
	os.Exit(result)
}

func setupTestEnvironment() {
	// Create test log directories
	if err := os.MkdirAll("logs/webvuln_test", 0755); err != nil {
		// Log error but continue since tests might still run in some cases
		// without the directory
		println("Warning: Failed to create test log directory:", err.Error())
	}
}

func cleanupTestEnvironment() {
	// Clean up test artifacts if needed
	// For now, we'll leave the logs for inspection
}
