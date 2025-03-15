// pkg/tools/osint/correlator.go
package osint

import (
	"fmt"
	"strings"
	"time"
)

// ConfidenceLevel represents a confidence level for a match
type ConfidenceLevel string

const (
	ConfidenceHigh   ConfidenceLevel = "High"
	ConfidenceMedium ConfidenceLevel = "Medium"
	ConfidenceLow    ConfidenceLevel = "Low"
)

// Correlator is the correlation engine that matches server/firmware info with vulnerabilities
type Correlator struct {
	VulnDB         VulnDBConnector
	MatchThreshold float64 // Minimum confidence score to include in results (0-1)
}

// NewCorrelator creates a new correlation engine with the given vulnerability database
func NewCorrelator(vulnDB VulnDBConnector) *Correlator {
	return &Correlator{
		VulnDB:         vulnDB,
		MatchThreshold: 0.6, // Default threshold is 60%
	}
}

// CorrelateServerInfo matches server information against known vulnerabilities
func (c *Correlator) CorrelateServerInfo(serverInfo *ServerInfo) ([]MatchResult, error) {
	results := make([]MatchResult, 0)

	// Skip if no product information
	if serverInfo.ProductName == "" {
		return results, nil
	}

	// Create search query based on server info
	query := SearchQuery{
		Products: []string{serverInfo.ProductName},
	}

	// Add version if available
	if serverInfo.ProductVersion != "" {
		query.Keywords = append(query.Keywords, serverInfo.ProductVersion)
	}

	// Search for vulnerabilities
	vulns, err := c.VulnDB.Search(query)
	if err != nil {
		return nil, fmt.Errorf("error searching vulnerabilities: %v", err)
	}

	// Calculate matches
	for _, vuln := range vulns {
		matchScore, matchReasons, matchedFields := calculateServerMatchScore(serverInfo, vuln)

		// Only include matches above threshold
		if matchScore >= c.MatchThreshold {
			results = append(results, MatchResult{
				ScanID:          fmt.Sprintf("server_%s", serverInfo.IPAddress),
				Vulnerability:   vuln,
				ConfidenceScore: matchScore,
				MatchReason:     strings.Join(matchReasons, "; "),
				MatchedFields:   matchedFields,
			})
		}
	}

	return results, nil
}

// CorrelateFirmwareInfo matches firmware information against known vulnerabilities
func (c *Correlator) CorrelateFirmwareInfo(firmwareInfo *FirmwareInfo) ([]MatchResult, error) {
	results := make([]MatchResult, 0)

	// Skip if no device info
	if firmwareInfo.DeviceType == "" || firmwareInfo.Manufacturer == "" {
		return results, nil
	}

	// Create search query
	query := SearchQuery{
		Keywords: []string{firmwareInfo.Manufacturer, firmwareInfo.DeviceType},
	}

	// Add model if available
	if firmwareInfo.Model != "" {
		query.Keywords = append(query.Keywords, firmwareInfo.Model)
	}

	// Add firmware version if available
	if firmwareInfo.FirmwareVersion != "" {
		query.Keywords = append(query.Keywords, firmwareInfo.FirmwareVersion)
	}

	// Search for vulnerabilities
	vulns, err := c.VulnDB.Search(query)
	if err != nil {
		return nil, fmt.Errorf("error searching vulnerabilities: %v", err)
	}

	// Calculate matches
	for _, vuln := range vulns {
		matchScore, matchReasons, matchedFields := calculateFirmwareMatchScore(firmwareInfo, vuln)

		// Only include matches above threshold
		if matchScore >= c.MatchThreshold {
			results = append(results, MatchResult{
				ScanID:          fmt.Sprintf("firmware_%s_%s", firmwareInfo.Manufacturer, firmwareInfo.Model),
				Vulnerability:   vuln,
				ConfidenceScore: matchScore,
				MatchReason:     strings.Join(matchReasons, "; "),
				MatchedFields:   matchedFields,
			})
		}
	}

	return results, nil
}

// CorrelateScanResults processes scan results and correlates with vulnerabilities
func (c *Correlator) CorrelateScanResults(scanResult *ScanResult) error {
	// Check for server information
	if scanResult.ServerInfo != nil {
		matches, err := c.CorrelateServerInfo(scanResult.ServerInfo)
		if err != nil {
			return fmt.Errorf("error correlating server info: %v", err)
		}

		// Add results to scan result
		for _, match := range matches {
			// Add vulnerability to list if not already present
			found := false
			for _, v := range scanResult.Vulnerabilities {
				if v.ID == match.Vulnerability.ID {
					found = true
					break
				}
			}

			if !found {
				scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, match.Vulnerability)
			}

			// Add confidence score
			if scanResult.ConfidenceScore == nil {
				scanResult.ConfidenceScore = make(map[string]float64)
			}
			scanResult.ConfidenceScore[match.Vulnerability.ID] = match.ConfidenceScore
		}
	}

	// Check for firmware information
	if scanResult.FirmwareInfo != nil {
		matches, err := c.CorrelateFirmwareInfo(scanResult.FirmwareInfo)
		if err != nil {
			return fmt.Errorf("error correlating firmware info: %v", err)
		}

		// Add results to scan result
		for _, match := range matches {
			// Add vulnerability to list if not already present
			found := false
			for _, v := range scanResult.Vulnerabilities {
				if v.ID == match.Vulnerability.ID {
					found = true
					break
				}
			}

			if !found {
				scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, match.Vulnerability)
			}

			// Add confidence score
			if scanResult.ConfidenceScore == nil {
				scanResult.ConfidenceScore = make(map[string]float64)
			}
			scanResult.ConfidenceScore[match.Vulnerability.ID] = match.ConfidenceScore
		}
	}

	// Calculate overall risk score based on vulnerability severities and confidence
	scanResult.RiskScore = calculateRiskScore(scanResult)

	return nil
}

// calculateServerMatchScore calculates a confidence score for a server-vulnerability match
func calculateServerMatchScore(serverInfo *ServerInfo, vuln Vulnerability) (float64, []string, []string) {
	var score float64 = 0
	reasons := make([]string, 0)
	matchedFields := make([]string, 0)

	// Look for product name in vulnerability information
	// Product name match is worth 50% of the score
	if serverInfo.ProductName != "" {
		productLower := strings.ToLower(serverInfo.ProductName)

		// Check if product name appears in vulnerability title, description or affected systems
		titleDescMatch := strings.Contains(strings.ToLower(vuln.Title), productLower) ||
			strings.Contains(strings.ToLower(vuln.Description), productLower)

		systemsMatch := false
		for _, system := range vuln.AffectedSystems {
			if strings.Contains(strings.ToLower(system), productLower) {
				systemsMatch = true
				break
			}
		}

		if titleDescMatch || systemsMatch {
			score += 0.5
			reasons = append(reasons, fmt.Sprintf("Product '%s' mentioned in vulnerability", serverInfo.ProductName))
			matchedFields = append(matchedFields, "ProductName")
		}
	}

	// Version match is worth 30% of the score
	if serverInfo.ProductVersion != "" {
		versionLower := strings.ToLower(serverInfo.ProductVersion)

		// Check if version appears in vulnerability information
		if strings.Contains(strings.ToLower(vuln.Title), versionLower) ||
			strings.Contains(strings.ToLower(vuln.Description), versionLower) {
			score += 0.3
			reasons = append(reasons, fmt.Sprintf("Version '%s' mentioned in vulnerability", serverInfo.ProductVersion))
			matchedFields = append(matchedFields, "ProductVersion")
		}
	}

	// OS match is worth 20% of the score
	if serverInfo.OS != "" {
		osLower := strings.ToLower(serverInfo.OS)

		// Check if OS appears in vulnerability information
		if strings.Contains(strings.ToLower(vuln.Title), osLower) ||
			strings.Contains(strings.ToLower(vuln.Description), osLower) {
			score += 0.2
			reasons = append(reasons, fmt.Sprintf("OS '%s' mentioned in vulnerability", serverInfo.OS))
			matchedFields = append(matchedFields, "OS")
		}
	}

	// Recency bonus - newer vulnerabilities are more likely to be relevant
	// Add up to 0.1 bonus for vulnerabilities less than 90 days old
	if !vuln.Published.IsZero() {
		daysAgo := time.Since(vuln.Published).Hours() / 24
		if daysAgo < 90 {
			recencyBonus := 0.1 * (1 - daysAgo/90)
			score += recencyBonus
			reasons = append(reasons, fmt.Sprintf("Vulnerability is recent (%.0f days old)", daysAgo))
		}
	}

	// If the server is EOL and the vulnerability is after EOL date, increase score
	if !serverInfo.EOLDate.IsZero() && serverInfo.UpdateAvailable &&
		!vuln.Published.IsZero() && vuln.Published.After(serverInfo.EOLDate) {
		eolBonus := 0.1
		score += eolBonus
		reasons = append(reasons, "Server is EOL and vulnerable to post-EOL exploits")
		matchedFields = append(matchedFields, "EOLStatus")
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score, reasons, matchedFields
}

// calculateFirmwareMatchScore calculates a confidence score for a firmware-vulnerability match
func calculateFirmwareMatchScore(firmwareInfo *FirmwareInfo, vuln Vulnerability) (float64, []string, []string) {
	var score float64 = 0
	reasons := make([]string, 0)
	matchedFields := make([]string, 0)

	// Manufacturer match is worth 30% of the score
	if firmwareInfo.Manufacturer != "" {
		manufacturerLower := strings.ToLower(firmwareInfo.Manufacturer)

		// Check if manufacturer appears in vulnerability information
		if strings.Contains(strings.ToLower(vuln.Title), manufacturerLower) ||
			strings.Contains(strings.ToLower(vuln.Description), manufacturerLower) {
			score += 0.3
			reasons = append(reasons, fmt.Sprintf("Manufacturer '%s' mentioned in vulnerability", firmwareInfo.Manufacturer))
			matchedFields = append(matchedFields, "Manufacturer")
		}
	}

	// Model match is worth 30% of the score
	if firmwareInfo.Model != "" {
		modelLower := strings.ToLower(firmwareInfo.Model)

		// Check if model appears in vulnerability information
		if strings.Contains(strings.ToLower(vuln.Title), modelLower) ||
			strings.Contains(strings.ToLower(vuln.Description), modelLower) {
			score += 0.3
			reasons = append(reasons, fmt.Sprintf("Model '%s' mentioned in vulnerability", firmwareInfo.Model))
			matchedFields = append(matchedFields, "Model")
		}
	}

	// Firmware version match is worth 40% of the score
	if firmwareInfo.FirmwareVersion != "" {
		versionLower := strings.ToLower(firmwareInfo.FirmwareVersion)

		// Check if version appears in vulnerability information
		if strings.Contains(strings.ToLower(vuln.Title), versionLower) ||
			strings.Contains(strings.ToLower(vuln.Description), versionLower) {
			score += 0.4
			reasons = append(reasons, fmt.Sprintf("Firmware version '%s' mentioned in vulnerability", firmwareInfo.FirmwareVersion))
			matchedFields = append(matchedFields, "FirmwareVersion")
		}
	}

	// If the firmware is EOL, increase the score
	if firmwareInfo.EOLStatus {
		eolBonus := 0.1
		score += eolBonus
		reasons = append(reasons, "Firmware is EOL, increasing vulnerability risk")
		matchedFields = append(matchedFields, "EOLStatus")
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score, reasons, matchedFields
}

// calculateRiskScore calculates an overall risk score for a scan result
func calculateRiskScore(scanResult *ScanResult) float64 {
	if len(scanResult.Vulnerabilities) == 0 {
		return 0
	}

	var totalScore float64 = 0

	// Calculate score based on vulnerability severity and confidence
	for _, vuln := range scanResult.Vulnerabilities {
		// Get base severity score (0-10)
		severityScore := vuln.CVSS

		// If no CVSS, estimate from severity level
		if severityScore == 0 {
			switch vuln.Severity {
			case SeverityCritical:
				severityScore = 9.0
			case SeverityHigh:
				severityScore = 7.0
			case SeverityMedium:
				severityScore = 5.0
			case SeverityLow:
				severityScore = 3.0
			default:
				severityScore = 1.0
			}
		}

		// Get confidence score (0-1)
		confidenceScore := 0.5 // Default medium confidence
		if scanResult.ConfidenceScore != nil {
			if score, found := scanResult.ConfidenceScore[vuln.ID]; found {
				confidenceScore = score
			}
		}

		// Calculate risk contribution for this vulnerability
		// Higher confidence and severity results in higher risk
		vulnRisk := (severityScore / 10) * confidenceScore
		totalScore += vulnRisk
	}

	// Normalize to a 0-10 scale, with diminishing returns for multiple vulnerabilities
	normalizedScore := 10 * (1 - (1 / (1 + totalScore)))

	// Apply additional risk factors

	// EOL status increases risk
	if scanResult.ServerInfo != nil && scanResult.ServerInfo.UpdateAvailable {
		// Add up to 2 points for EOL systems
		normalizedScore += 2
	}

	// Cap at 10
	if normalizedScore > 10 {
		normalizedScore = 10
	}

	return normalizedScore
}
