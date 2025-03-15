// pkg/tools/osint/models.go
package osint

import (
	"time"
)

// Severity represents the severity level of a vulnerability
type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityNone     Severity = "None"
)

// Vulnerability represents a security vulnerability with its details
type Vulnerability struct {
	ID              string    `json:"id"`               // CVE ID
	Title           string    `json:"title"`            // Short title
	Description     string    `json:"description"`      // Detailed description
	Severity        Severity  `json:"severity"`         // Severity level
	CVSS            float64   `json:"cvss"`             // CVSS score
	AffectedSystems []string  `json:"affected_systems"` // Affected systems/products
	References      []string  `json:"references"`       // References URLs
	Published       time.Time `json:"published"`        // Publication date
	Modified        time.Time `json:"modified"`         // Last modification date
	Exploits        []string  `json:"exploits"`         // Known exploits
	Mitigations     []string  `json:"mitigations"`      // Recommended mitigations
	Source          string    `json:"source"`           // Source of the information (NVD, ExploitDB, etc.)
}

// ServerInfo represents information about a server
type ServerInfo struct {
	IPAddress       string            `json:"ip_address"`
	Hostname        string            `json:"hostname"`
	OS              string            `json:"os"`
	OSVersion       string            `json:"os_version"`
	ProductName     string            `json:"product_name"`
	ProductVersion  string            `json:"product_version"`
	Ports           []int             `json:"ports"`
	Services        map[int]string    `json:"services"` // Port to service mapping
	Headers         map[string]string `json:"headers"`  // HTTP headers
	Banners         map[int]string    `json:"banners"`  // Port to banner mapping
	EOLDate         time.Time         `json:"eol_date"` // End of life date for OS/product
	UpdateAvailable bool              `json:"update_available"`
	FirstSeen       time.Time         `json:"first_seen"`
	LastSeen        time.Time         `json:"last_seen"`
}

// FirmwareInfo represents information about device firmware
type FirmwareInfo struct {
	DeviceType      string    `json:"device_type"`      // Router, switch, camera, etc.
	Manufacturer    string    `json:"manufacturer"`     // Device manufacturer
	Model           string    `json:"model"`            // Device model
	FirmwareVersion string    `json:"firmware_version"` // Current firmware version
	ReleaseDate     time.Time `json:"release_date"`     // Release date of current version
	LatestVersion   string    `json:"latest_version"`   // Latest available version
	HasVulns        bool      `json:"has_vulns"`        // Has known vulnerabilities
	Vulnerabilities []string  `json:"vulnerabilities"`  // References to vulnerabilities
	EOLStatus       bool      `json:"eol_status"`       // End of life status
	EOLDate         time.Time `json:"eol_date"`         // End of life date
}

// ScanResult represents information from a vulnerability scan with matches
type ScanResult struct {
	ID              string             `json:"id"`
	Target          string             `json:"target"`           // IP or hostname
	ScanType        string             `json:"scan_type"`        // Type of scan
	ScanDate        time.Time          `json:"scan_date"`        // Date of scan
	ServerInfo      *ServerInfo        `json:"server_info"`      // Server information
	FirmwareInfo    *FirmwareInfo      `json:"firmware_info"`    // Firmware information
	Vulnerabilities []Vulnerability    `json:"vulnerabilities"`  // Matched vulnerabilities
	RawData         interface{}        `json:"raw_data"`         // Raw scan data
	ConfidenceScore map[string]float64 `json:"confidence_score"` // Confidence scores for each match
	RiskScore       float64            `json:"risk_score"`       // Overall risk score
}

// MatchResult represents a match between scan data and vulnerability database
type MatchResult struct {
	ScanID          string        `json:"scan_id"`
	Vulnerability   Vulnerability `json:"vulnerability"`
	ConfidenceScore float64       `json:"confidence_score"`
	MatchReason     string        `json:"match_reason"`
	MatchedFields   []string      `json:"matched_fields"`
}

// SearchQuery represents a query to search for vulnerabilities
type SearchQuery struct {
	Keywords       []string   `json:"keywords"`
	Products       []string   `json:"products"`
	Versions       []string   `json:"versions"`
	CVEIDs         []string   `json:"cve_ids"`
	SeverityLevels []Severity `json:"severity_levels"`
	FromDate       time.Time  `json:"from_date"`
	ToDate         time.Time  `json:"to_date"`
	MaxResults     int        `json:"max_results"`
}
