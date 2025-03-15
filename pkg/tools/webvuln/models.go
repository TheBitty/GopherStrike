// pkg/tools/webvuln/models.go
package webvuln

import (
	"time"
)

// VulnerabilityType represents the type of vulnerability
type VulnerabilityType string

// Severity represents the severity level of a vulnerability
type Severity string

const (
	// Vulnerability types
	VulnTypeXSS              VulnerabilityType = "XSS"
	VulnTypeSQLInjection     VulnerabilityType = "SQL_INJECTION"
	VulnTypeCSRF             VulnerabilityType = "CSRF"
	VulnTypeFileInclusion    VulnerabilityType = "FILE_INCLUSION"
	VulnTypeMisconfiguration VulnerabilityType = "MISCONFIGURATION"
	VulnTypeAuthWeak         VulnerabilityType = "AUTH_WEAK"
	VulnTypeInfoDisclosure   VulnerabilityType = "INFO_DISCLOSURE"

	// Severity levels
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

// BasicAuth represents basic authentication credentials
type BasicAuth struct {
	Username string
	Password string
}

// ScanTarget represents a target to scan
type ScanTarget struct {
	URL       string
	Method    string
	Headers   map[string]string
	Cookies   []string
	BasicAuth BasicAuth
}

// ScanOptions represents options for the vulnerability scanner
type ScanOptions struct {
	// Scan behavior options
	PayloadLevel         int // 1-5, 1 being basic payloads, 5 being comprehensive
	Timeout              int // In seconds
	MaxRedirects         int
	IgnoreSSLErrors      bool
	GenerateHTML         bool
	OutputFormat         string
	VerboseMode          bool
	TestAllParams        bool
	LogDirectory         string
	MaxRequestsPerSecond int

	// Vulnerability test options
	EnableXSS              bool
	EnableSQLInjection     bool
	EnableCSRF             bool
	EnableFileInclusion    bool
	EnableMisconfiguration bool
	EnableAuthTesting      bool
	EnableInfoDisclosure   bool

	// Authentication testing options
	LoginURL       string
	UsernameField  string
	PasswordField  string
	BruteForceTest bool
	ScanForms      bool
}

// TestResult represents the result of an individual test
type TestResult struct {
	Payload     Payload
	URL         string
	Method      string
	Parameter   string
	Description string
	Severity    Severity
}

// ScanResult represents the result of a vulnerability scan for a specific type
type ScanResult struct {
	VulnerabilityType VulnerabilityType
	TestResults       []TestResult
}

// Payload represents a payload for vulnerability testing
type Payload struct {
	Value       string
	Type        VulnerabilityType
	Description string
	Level       int // Complexity level 1-5
}

// Report represents a vulnerability scan report
type Report struct {
	Target      ScanTarget
	ScanOptions ScanOptions
	Results     []ScanResult
	StartTime   time.Time
	EndTime     time.Time
}

// DefaultScanOptions returns default scan options
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		PayloadLevel:         3,
		Timeout:              10,
		MaxRedirects:         5,
		IgnoreSSLErrors:      false,
		GenerateHTML:         true,
		OutputFormat:         "text",
		VerboseMode:          false,
		TestAllParams:        true,
		LogDirectory:         "logs/webvuln",
		MaxRequestsPerSecond: 10,

		EnableXSS:              true,
		EnableSQLInjection:     true,
		EnableCSRF:             true,
		EnableFileInclusion:    true,
		EnableMisconfiguration: true,
		EnableAuthTesting:      false,
		EnableInfoDisclosure:   true,

		BruteForceTest: false,
		ScanForms:      true,
	}
}
