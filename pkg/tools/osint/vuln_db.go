// pkg/tools/osint/vuln_db.go
package osint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// Source identifiers
	SourceNVD       = "NVD"
	SourceExploitDB = "ExploitDB"
	SourceGithub    = "GitHub"

	// Cache duration - 24 hours
	cacheDuration = 24 * time.Hour

	// Default cache directory
	defaultCacheDir = "cache/vuln_db"
)

// VulnDBConnector interface defines methods for vulnerability database connectors
type VulnDBConnector interface {
	Search(query SearchQuery) ([]Vulnerability, error)
	GetByID(id string) (*Vulnerability, error)
	GetUpdates(since time.Time) ([]Vulnerability, error)
}

// NVDConnector implements VulnDBConnector for the NVD database
type NVDConnector struct {
	APIKey      string
	BaseURL     string
	CacheDir    string
	cacheExpiry time.Duration
	cacheLock   sync.RWMutex
}

// NewNVDConnector creates a new NVD connector with optional API key
func NewNVDConnector(apiKey string) *NVDConnector {
	cacheDir := filepath.Join("logs", defaultCacheDir, "nvd")
	// Create cache directory
	_ = os.MkdirAll(cacheDir, 0755)

	return &NVDConnector{
		APIKey:      apiKey,
		BaseURL:     "https://services.nvd.nist.gov/rest/json/cves/2.0",
		CacheDir:    cacheDir,
		cacheExpiry: cacheDuration,
	}
}

// Search searches the NVD database for vulnerabilities matching the query
func (c *NVDConnector) Search(query SearchQuery) ([]Vulnerability, error) {
	// Check cache first
	cacheKey := generateCacheKey("search", query)
	if vulns, found := c.checkCache(cacheKey); found {
		return vulns, nil
	}

	// Build query parameters
	params := url.Values{}

	if len(query.Keywords) > 0 {
		// Join keywords with AND operator
		keyword := ""
		for i, k := range query.Keywords {
			if i > 0 {
				keyword += " AND "
			}
			keyword += k
		}
		params.Add("keywordSearch", keyword)
	}

	if len(query.CVEIDs) > 0 {
		// Add specific CVE IDs if provided
		for _, id := range query.CVEIDs {
			params.Add("cveId", id)
		}
	}

	if len(query.Products) > 0 {
		// Add CPE product filters
		for _, product := range query.Products {
			params.Add("cpeName", product)
		}
	}

	// Add date ranges if specified
	if !query.FromDate.IsZero() {
		params.Add("pubStartDate", query.FromDate.Format(time.RFC3339))
	}
	if !query.ToDate.IsZero() {
		params.Add("pubEndDate", query.ToDate.Format(time.RFC3339))
	}

	// Set max results
	if query.MaxResults > 0 {
		params.Add("resultsPerPage", fmt.Sprintf("%d", query.MaxResults))
	} else {
		params.Add("resultsPerPage", "50") // Default limit
	}

	// Make API request
	reqURL := fmt.Sprintf("%s?%s", c.BaseURL, params.Encode())
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Add API key if provided
	if c.APIKey != "" {
		req.Header.Add("apiKey", c.APIKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}

	// Parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	// Map NVD JSON response to our vulnerability struct
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string    `json:"id"`
				Published    time.Time `json:"published"`
				LastModified time.Time `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSV31 struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	err = json.Unmarshal(body, &nvdResp)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	// Convert to our vulnerability model
	vulns := make([]Vulnerability, 0, len(nvdResp.Vulnerabilities))
	for _, item := range nvdResp.Vulnerabilities {
		vuln := Vulnerability{
			ID:         item.CVE.ID,
			Published:  item.CVE.Published,
			Modified:   item.CVE.LastModified,
			Source:     SourceNVD,
			References: make([]string, 0, len(item.CVE.References)),
		}

		// Get English description
		for _, desc := range item.CVE.Descriptions {
			if desc.Lang == "en" {
				vuln.Description = desc.Value
				vuln.Title = truncateString(desc.Value, 80) // Use first 80 chars as title
				break
			}
		}

		// Get CVSS score and severity
		if len(item.CVE.Metrics.CVSSMetricV31) > 0 {
			cvssData := item.CVE.Metrics.CVSSMetricV31[0].CVSSV31
			vuln.CVSS = cvssData.BaseScore

			// Map NVD severity to our severity enum
			switch cvssData.BaseSeverity {
			case "CRITICAL":
				vuln.Severity = SeverityCritical
			case "HIGH":
				vuln.Severity = SeverityHigh
			case "MEDIUM":
				vuln.Severity = SeverityMedium
			case "LOW":
				vuln.Severity = SeverityLow
			default:
				vuln.Severity = SeverityNone
			}
		}

		// Extract references
		for _, ref := range item.CVE.References {
			vuln.References = append(vuln.References, ref.URL)
		}

		vulns = append(vulns, vuln)
	}

	// Cache results
	c.cacheResults(cacheKey, vulns)

	return vulns, nil
}

// GetByID retrieves a vulnerability by its ID (e.g., CVE-2021-44228)
func (c *NVDConnector) GetByID(id string) (*Vulnerability, error) {
	// Check cache first
	cacheKey := generateCacheKey("id", id)
	if vulns, found := c.checkCache(cacheKey); found && len(vulns) > 0 {
		return &vulns[0], nil
	}

	// Create search query
	query := SearchQuery{
		CVEIDs: []string{id},
	}

	// Use search function
	vulns, err := c.Search(query)
	if err != nil {
		return nil, err
	}

	if len(vulns) == 0 {
		return nil, fmt.Errorf("vulnerability not found: %s", id)
	}

	return &vulns[0], nil
}

// GetUpdates retrieves vulnerabilities updated since a given date
func (c *NVDConnector) GetUpdates(since time.Time) ([]Vulnerability, error) {
	// Create search query
	query := SearchQuery{
		FromDate: since,
		ToDate:   time.Now(),
	}

	// Use search function
	return c.Search(query)
}

// checkCache checks if cached results exist and are still valid
func (c *NVDConnector) checkCache(key string) ([]Vulnerability, bool) {
	c.cacheLock.RLock()
	defer c.cacheLock.RUnlock()

	cacheFile := filepath.Join(c.CacheDir, key+".json")

	// Check if cache file exists
	info, err := os.Stat(cacheFile)
	if err != nil {
		return nil, false
	}

	// Check if cache is expired
	if time.Since(info.ModTime()) > c.cacheExpiry {
		return nil, false
	}

	// Read cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, false
	}

	var vulns []Vulnerability
	err = json.Unmarshal(data, &vulns)
	if err != nil {
		return nil, false
	}

	return vulns, true
}

// cacheResults caches search results
func (c *NVDConnector) cacheResults(key string, vulns []Vulnerability) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()

	cacheFile := filepath.Join(c.CacheDir, key+".json")

	// Marshal to JSON
	data, err := json.Marshal(vulns)
	if err != nil {
		return
	}

	// Write to cache file
	_ = os.WriteFile(cacheFile, data, 0644)
}

// generateCacheKey generates a cache key from query parameters
func generateCacheKey(prefix string, data interface{}) string {
	// Marshal data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		// Fallback to current timestamp if marshaling fails
		return fmt.Sprintf("%s_%d", prefix, time.Now().Unix())
	}

	// Simple hash function
	var hash uint32
	for _, b := range jsonData {
		hash = hash*31 + uint32(b)
	}

	return fmt.Sprintf("%s_%x", prefix, hash)
}

// truncateString truncates a string to the given maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
