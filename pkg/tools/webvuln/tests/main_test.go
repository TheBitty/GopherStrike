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
	os.MkdirAll("logs/webvuln_test", 0755)
}

func cleanupTestEnvironment() {
	// Clean up test artifacts if needed
	// For now, we'll leave the logs for inspection
}
