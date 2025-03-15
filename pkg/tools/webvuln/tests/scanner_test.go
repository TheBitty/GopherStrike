package tests

import (
	"GopherStrike/pkg/tools/webvuln"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// setupVulnerableServer creates a test server with deliberate vulnerabilities
func setupVulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	// Vulnerable to XSS
	mux.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		// Reflected XSS - vulnerable!
		fmt.Fprintf(w, "<html><body>You said: %s</body></html>", input)
	})

	// Vulnerable to SQL Injection
	mux.HandleFunc("/sql", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Simulate SQL error if injection is attempted
		if strings.Contains(id, "'") {
			fmt.Fprintf(w, "Error executing SQL query: SQL syntax error near '%s' in query", id)
		} else {
			fmt.Fprintf(w, "<html><body>Product ID: %s</body></html>", id)
		}
	})

	// Simulates a login form without CSRF protection
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, `<html><body>
				<form action="/login" method="POST">
					<input type="text" name="username">
					<input type="password" name="password">
					<input type="submit" value="Login">
				</form>
			</body></html>`)
		} else {
			username := r.FormValue("username")
			password := r.FormValue("password")

			// Simple credentials check
			if username == "admin" && password == "admin" {
				fmt.Fprint(w, "<html><body>Welcome to the dashboard!</body></html>")
			} else {
				fmt.Fprint(w, "<html><body>Invalid credentials</body></html>")
			}
		}
	})

	// Root handler with link to the vulnerable pages
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>
			<h1>Test Vulnerability Server</h1>
			<ul>
				<li><a href="/xss?input=test">XSS Test</a></li>
				<li><a href="/sql?id=1">SQL Test</a></li>
				<li><a href="/login">Login Form</a></li>
			</ul>
		</body></html>`)
	})

	// Create and start server
	return httptest.NewServer(mux)
}

func TestScanner(t *testing.T) {
	// Create test server with vulnerabilities
	server := setupVulnerableServer()
	defer server.Close()

	// Set up scan options
	options := webvuln.ScanOptions{
		PayloadLevel:           2,
		Timeout:                5,
		MaxRedirects:           3,
		IgnoreSSLErrors:        true,
		GenerateHTML:           false,
		OutputFormat:           "text",
		VerboseMode:            false,
		TestAllParams:          true,
		LogDirectory:           "logs/webvuln_test",
		MaxRequestsPerSecond:   20,
		EnableXSS:              true,
		EnableSQLInjection:     true,
		EnableCSRF:             true,
		EnableFileInclusion:    false, // Disabled to avoid file access during tests
		EnableMisconfiguration: true,
		EnableAuthTesting:      true,
		BruteForceTest:         false,
		ScanForms:              true,
		LoginURL:               "/login",
		UsernameField:          "username",
		PasswordField:          "password",
	}

	// Create scanner
	scanner := webvuln.NewScanner(options)

	// For XSS testing
	xssTarget := webvuln.ScanTarget{
		URL:     server.URL + "/xss?input=test",
		Method:  "GET",
		Headers: map[string]string{},
		Cookies: []string{},
	}

	xssReport, err := scanner.Scan(xssTarget)
	if err != nil {
		t.Fatalf("XSS Scanner failed with error: %v", err)
	}

	// For SQL testing
	sqlTarget := webvuln.ScanTarget{
		URL:     server.URL + "/sql?id=1",
		Method:  "GET",
		Headers: map[string]string{},
		Cookies: []string{},
	}

	sqlReport, err := scanner.Scan(sqlTarget)
	if err != nil {
		t.Fatalf("SQL Scanner failed with error: %v", err)
	}

	// For CSRF and misc testing
	csrfTarget := webvuln.ScanTarget{
		URL:     server.URL + "/login",
		Method:  "GET",
		Headers: map[string]string{},
		Cookies: []string{},
	}

	csrfReport, err := scanner.Scan(csrfTarget)
	if err != nil {
		t.Fatalf("CSRF Scanner failed with error: %v", err)
	}

	// Test for specific vulnerabilities in each report
	xssDetected := false
	sqlDetected := false
	csrfDetected := false
	misconfigDetected := false

	// Check XSS report
	for _, result := range xssReport.Results {
		if result.VulnerabilityType == webvuln.VulnTypeXSS && len(result.TestResults) > 0 {
			xssDetected = true
			t.Logf("Found XSS vulnerability: %s", result.TestResults[0].Description)
			break
		}
	}

	// Check SQL report
	for _, result := range sqlReport.Results {
		if result.VulnerabilityType == webvuln.VulnTypeSQLInjection && len(result.TestResults) > 0 {
			sqlDetected = true
			t.Logf("Found SQL vulnerability: %s", result.TestResults[0].Description)
			break
		}
	}

	// Check CSRF and misconfig report
	for _, result := range csrfReport.Results {
		if result.VulnerabilityType == webvuln.VulnTypeCSRF && len(result.TestResults) > 0 {
			csrfDetected = true
			t.Logf("Found CSRF vulnerability: %s", result.TestResults[0].Description)
		}
		if result.VulnerabilityType == webvuln.VulnTypeMisconfiguration && len(result.TestResults) > 0 {
			misconfigDetected = true
			t.Logf("Found misconfiguration: %s", result.TestResults[0].Description)
		}
	}

	// Since we have vulnerabilities, we should find at least some of them
	if !xssDetected {
		t.Error("Failed to detect XSS vulnerability")
	}
	if !sqlDetected {
		t.Error("Failed to detect SQL Injection vulnerability")
	}
	if !csrfDetected {
		t.Error("Failed to detect CSRF vulnerability")
	}
	if !misconfigDetected {
		t.Logf("Note: Misconfigurations may not always be detected in test environments")
	}
}
