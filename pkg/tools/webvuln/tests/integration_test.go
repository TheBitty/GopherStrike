package tests

import (
	"GopherStrike/pkg/tools/webvuln"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestIntegration performs an end-to-end test of the web vulnerability scanner
// This is a more extensive test that exercises the full functionality
func TestIntegration(t *testing.T) {
	// Skip if we're in short mode
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Set up a vulnerable test server
	mux := http.NewServeMux()

	// Simple page with reflected XSS vulnerability
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// Vulnerable: direct reflection of user input
		content := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Test Page</title>
		</head>
		<body>
			<h1>Hello, ` + name + `!</h1>
			<p>Welcome to our test page.</p>
			<form action="/login" method="post">
				<input type="text" name="username" placeholder="Username">
				<input type="password" name="password" placeholder="Password">
				<input type="submit" value="Login">
			</form>
		</body>
		</html>
		`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(content))
	})

	// Create the test server
	server := httptest.NewServer(mux)
	defer server.Close()

	// Ensure log directory exists
	os.MkdirAll("logs/webvuln_test", 0755)

	// Configure the scanner
	options := webvuln.DefaultScanOptions()
	options.PayloadLevel = 1 // Use basic payloads for faster testing
	options.LogDirectory = "logs/webvuln_test"
	options.Timeout = 5 // Shorter timeout for tests
	options.MaxRequestsPerSecond = 30

	// Create target
	target := webvuln.ScanTarget{
		URL:     server.URL + "/page?name=test",
		Method:  "GET",
		Headers: map[string]string{},
	}

	// Initialize the scanner
	scanner := webvuln.NewScanner(options)

	// Run the scan
	report, err := scanner.Scan(target)
	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	// Verify we got results
	if report == nil {
		t.Fatal("No report was generated")
	}

	t.Logf("Scan completed in %v", report.EndTime.Sub(report.StartTime))
	t.Logf("Found %d vulnerability types", len(report.Results))

	// We should have at least found XSS and CSRF vulnerabilities
	foundXSS := false
	foundCSRF := false

	for _, result := range report.Results {
		if result.VulnerabilityType == webvuln.VulnTypeXSS && len(result.TestResults) > 0 {
			foundXSS = true
			t.Logf("Found XSS vulnerability: %s", result.TestResults[0].Description)
		}
		if result.VulnerabilityType == webvuln.VulnTypeCSRF && len(result.TestResults) > 0 {
			foundCSRF = true
			t.Logf("Found CSRF vulnerability: %s", result.TestResults[0].Description)
		}
	}

	if !foundXSS {
		t.Error("Failed to detect XSS vulnerability in vulnerable page")
	}

	if !foundCSRF {
		t.Error("Failed to detect CSRF vulnerability in form")
	}
}
