package tests

import (
	"GopherStrike/pkg/tools/webvuln"
	"testing"
	"time"
)

func TestScanOptions(t *testing.T) {
	// Test default scan options
	options := webvuln.DefaultScanOptions()

	// Verify defaults are set to reasonable values
	if options.PayloadLevel < 1 || options.PayloadLevel > 5 {
		t.Errorf("Default payload level (%d) should be between 1 and 5", options.PayloadLevel)
	}

	if options.Timeout <= 0 {
		t.Errorf("Default timeout (%d) should be greater than 0", options.Timeout)
	}

	if options.MaxRedirects <= 0 {
		t.Errorf("Default max redirects (%d) should be greater than 0", options.MaxRedirects)
	}

	// Verify default enabled tests
	if !options.EnableXSS {
		t.Error("XSS testing should be enabled by default")
	}

	if !options.EnableSQLInjection {
		t.Error("SQL Injection testing should be enabled by default")
	}

	if !options.EnableCSRF {
		t.Error("CSRF testing should be enabled by default")
	}
}

func TestReport(t *testing.T) {
	// Create test data
	target := webvuln.ScanTarget{
		URL:    "https://example.com",
		Method: "GET",
	}

	options := webvuln.DefaultScanOptions()

	// Create a sample report
	report := webvuln.Report{
		Target:      target,
		ScanOptions: options,
		Results:     []webvuln.ScanResult{},
		StartTime:   time.Now().Add(-5 * time.Minute), // 5 minutes ago
		EndTime:     time.Now(),
	}

	// Use the Target and ScanOptions fields to remove unused write warnings
	if report.Target.URL == "" {
		t.Error("Target URL should not be empty")
	}

	if !report.ScanOptions.EnableXSS {
		t.Log("XSS testing was not enabled in the default options")
	}

	// Add test results
	xssResult := webvuln.ScanResult{
		VulnerabilityType: webvuln.VulnTypeXSS,
		TestResults: []webvuln.TestResult{
			{
				Payload: webvuln.Payload{
					Value:       "<script>alert('XSS')</script>",
					Type:        webvuln.VulnTypeXSS,
					Description: "Basic XSS Test",
					Level:       1,
				},
				URL:         "https://example.com/?input=<script>alert('XSS')</script>",
				Method:      "GET",
				Parameter:   "input",
				Description: "Reflected XSS in 'input' parameter",
				Severity:    webvuln.SeverityHigh,
			},
		},
	}

	sqlResult := webvuln.ScanResult{
		VulnerabilityType: webvuln.VulnTypeSQLInjection,
		TestResults: []webvuln.TestResult{
			{
				Payload: webvuln.Payload{
					Value:       "' OR '1'='1",
					Type:        webvuln.VulnTypeSQLInjection,
					Description: "Basic SQL Injection Test",
					Level:       1,
				},
				URL:         "https://example.com/?id=' OR '1'='1",
				Method:      "GET",
				Parameter:   "id",
				Description: "SQL Injection in 'id' parameter",
				Severity:    webvuln.SeverityCritical,
			},
		},
	}

	report.Results = append(report.Results, xssResult, sqlResult)

	// Test report data
	if len(report.Results) != 2 {
		t.Errorf("Report should have 2 results, got %d", len(report.Results))
	}

	// Check duration calculation
	duration := report.EndTime.Sub(report.StartTime)
	if duration < 4*time.Minute || duration > 6*time.Minute {
		t.Errorf("Expected duration around 5 minutes, got %v", duration)
	}

	// Verify vulnerability types
	foundXSS := false
	foundSQL := false

	for _, result := range report.Results {
		if result.VulnerabilityType == webvuln.VulnTypeXSS {
			foundXSS = true
		} else if result.VulnerabilityType == webvuln.VulnTypeSQLInjection {
			foundSQL = true
		}
	}

	if !foundXSS {
		t.Error("XSS vulnerability not found in report")
	}

	if !foundSQL {
		t.Error("SQL Injection vulnerability not found in report")
	}
}
