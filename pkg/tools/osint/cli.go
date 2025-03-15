// pkg/tools/osint/cli.go
package osint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	LogDirectory = "logs/osint"
)

// OSINTCmdOptions holds command line options for the OSINT tool
type OSINTCmdOptions struct {
	Target              string
	ScanType            string
	APIKey              string
	ConfidenceThreshold float64
	OutputFormat        string
}

// RunOSINTScanner is the main entry point for the OSINT tool
func RunOSINTScanner() error {
	// Print banner
	fmt.Println("\n===================================")
	fmt.Println("      GopherStrike InfoTracker")
	fmt.Println("      OSINT & Vulnerability Tool")
	fmt.Println("===================================")

	// Initialize options
	options := OSINTCmdOptions{
		ConfidenceThreshold: 0.6,
		OutputFormat:        "text",
	}

	// Create logs directory
	err := os.MkdirAll(LogDirectory, 0755)
	if err != nil {
		fmt.Printf("Warning: Failed to create logs directory: %v\n", err)
	}

	// Main menu loop
	for {
		printMainMenu()
		choice := getInput("Select an option")

		switch choice {
		case "1": // Lookup vulnerability
			lookupVulnerability()
		case "2": // Gather server information
			gatherServerInformation()
		case "3": // Gather firmware information
			gatherFirmwareInformation()
		case "4": // Correlate scan results
			correlateResults()
		case "5": // Settings
			configureSettings(&options)
		case "6": // Return to main menu
			fmt.Println("Returning to main menu...")
			return nil
		default:
			fmt.Println("Invalid option, please try again.")
		}
	}
}

// printMainMenu displays the OSINT tool menu
func printMainMenu() {
	fmt.Println("\nGopherStrike InfoTracker - Main Menu")
	fmt.Println("====================================")
	fmt.Println("1. Lookup Vulnerability")
	fmt.Println("2. Gather Server Information")
	fmt.Println("3. Gather Firmware Information")
	fmt.Println("4. Correlate Scan Results with Vulnerabilities")
	fmt.Println("5. Settings")
	fmt.Println("6. Return to Main Menu")
}

// lookupVulnerability searches for vulnerability information
func lookupVulnerability() {
	fmt.Println("\n--- Vulnerability Lookup ---")
	fmt.Println("Search Options:")
	fmt.Println("1. Search by CVE ID")
	fmt.Println("2. Search by Keywords")
	fmt.Println("3. Search by Product")
	fmt.Println("4. Go Back")

	choice := getInput("Select a search option")

	switch choice {
	case "1": // CVE ID
		cveID := getInput("Enter CVE ID (e.g., CVE-2021-44228)")
		searchByCVE(cveID)
	case "2": // Keywords
		keywords := getInput("Enter keywords separated by spaces")
		keywordSlice := strings.Fields(keywords)
		searchByKeywords(keywordSlice)
	case "3": // Product
		product := getInput("Enter product name")
		version := getInput("Enter version (optional, press Enter to skip)")
		searchByProduct(product, version)
	case "4": // Go back
		return
	default:
		fmt.Println("Invalid option, returning to main menu.")
	}
}

// searchByCVE searches for a specific CVE
func searchByCVE(cveID string) {
	fmt.Printf("\nSearching for %s...\n", cveID)

	// Create NVD connector
	nvd := NewNVDConnector("")

	// Search for vulnerability
	vuln, err := nvd.GetByID(cveID)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Display result
	displayVulnerability(*vuln)

	// Option to save
	saveChoice := getInput("Save result to file? (y/n)")
	if strings.ToLower(saveChoice) == "y" {
		saveVulnerabilityToFile(*vuln)
	}
}

// searchByKeywords searches for vulnerabilities by keywords
func searchByKeywords(keywords []string) {
	fmt.Printf("\nSearching for keywords: %s\n", strings.Join(keywords, ", "))

	// Create NVD connector
	nvd := NewNVDConnector("")

	// Create search query
	query := SearchQuery{
		Keywords:   keywords,
		MaxResults: 20,
	}

	// Search for vulnerabilities
	vulns, err := nvd.Search(query)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Display results
	fmt.Printf("\nFound %d vulnerabilities matching your keywords.\n", len(vulns))
	displayVulnerabilityList(vulns)

	// Option to view details
	idChoice := getInput("Enter CVE ID to view details (or leave empty to return)")
	if idChoice != "" {
		for _, vuln := range vulns {
			if vuln.ID == idChoice {
				displayVulnerability(vuln)

				// Option to save
				saveChoice := getInput("Save result to file? (y/n)")
				if strings.ToLower(saveChoice) == "y" {
					saveVulnerabilityToFile(vuln)
				}
				break
			}
		}
	}
}

// searchByProduct searches for vulnerabilities affecting a specific product
func searchByProduct(product, version string) {
	fmt.Printf("\nSearching for vulnerabilities affecting %s", product)
	if version != "" {
		fmt.Printf(" version %s", version)
	}
	fmt.Println("...")

	// Create NVD connector
	nvd := NewNVDConnector("")

	// Create search query
	query := SearchQuery{
		Products:   []string{product},
		MaxResults: 20,
	}

	// Add version as keyword if provided
	if version != "" {
		query.Keywords = append(query.Keywords, version)
	}

	// Search for vulnerabilities
	vulns, err := nvd.Search(query)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Display results
	fmt.Printf("\nFound %d vulnerabilities affecting %s.\n", len(vulns), product)
	displayVulnerabilityList(vulns)

	// Option to view details
	idChoice := getInput("Enter CVE ID to view details (or leave empty to return)")
	if idChoice != "" {
		for _, vuln := range vulns {
			if vuln.ID == idChoice {
				displayVulnerability(vuln)

				// Option to save
				saveChoice := getInput("Save result to file? (y/n)")
				if strings.ToLower(saveChoice) == "y" {
					saveVulnerabilityToFile(vuln)
				}
				break
			}
		}
	}
}

// gatherServerInformation collects information about a server
func gatherServerInformation() {
	fmt.Println("\n--- Server Information Gathering ---")
	target := getInput("Enter target IP or hostname")

	// Ask for ports to scan
	portsStr := getInput("Enter ports to scan (comma-separated, leave empty for defaults)")
	var ports []int

	if portsStr != "" {
		portStrs := strings.Split(portsStr, ",")
		for _, portStr := range portStrs {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err == nil && port > 0 && port < 65536 {
				ports = append(ports, port)
			}
		}
	}

	fmt.Printf("\nGathering information for %s...\n", target)

	// Gather server information
	serverInfo, err := GatherServerInfo(target, ports)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Display results
	displayServerInfo(serverInfo)

	// Option to save
	saveChoice := getInput("Save result to file? (y/n)")
	if strings.ToLower(saveChoice) == "y" {
		saveServerInfoToFile(serverInfo)
	}

	// Option to correlate with vulnerabilities
	correlateChoice := getInput("Correlate with vulnerability database? (y/n)")
	if strings.ToLower(correlateChoice) == "y" {
		// Create NVD connector
		nvd := NewNVDConnector("")

		// Create correlator
		correlator := NewCorrelator(nvd)

		fmt.Println("\nCorrelating with vulnerability database...")

		// Create scan result
		scanResult := &ScanResult{
			ID:         fmt.Sprintf("server_%s_%d", target, time.Now().Unix()),
			Target:     target,
			ScanType:   "ServerInfo",
			ScanDate:   time.Now(),
			ServerInfo: serverInfo,
		}

		// Correlate
		err = correlator.CorrelateScanResults(scanResult)
		if err != nil {
			fmt.Printf("Error correlating results: %v\n", err)
			return
		}

		// Display results
		displayScanResult(scanResult)

		// Option to save
		saveChoice = getInput("Save correlation result to file? (y/n)")
		if strings.ToLower(saveChoice) == "y" {
			saveScanResultToFile(scanResult)
		}
	}
}

// gatherFirmwareInformation collects information about device firmware
func gatherFirmwareInformation() {
	fmt.Println("\n--- Firmware Information Gathering ---")
	fmt.Println("Enter firmware details:")

	// Gather firmware information manually
	deviceType := getInput("Device type (e.g., Router, Switch, Camera)")
	manufacturer := getInput("Manufacturer")
	model := getInput("Model")
	firmwareVersion := getInput("Firmware version")

	// Parse release date
	releaseDate := time.Time{}
	releaseDateStr := getInput("Release date (YYYY-MM-DD, leave empty if unknown)")
	if releaseDateStr != "" {
		var err error
		releaseDate, err = time.Parse("2006-01-02", releaseDateStr)
		if err != nil {
			fmt.Println("Invalid date format, using current date instead.")
			releaseDate = time.Now()
		}
	}

	// Create firmware info
	firmwareInfo := &FirmwareInfo{
		DeviceType:      deviceType,
		Manufacturer:    manufacturer,
		Model:           model,
		FirmwareVersion: firmwareVersion,
		ReleaseDate:     releaseDate,
	}

	// Check for EOL status
	eolChoice := getInput("Is this firmware version EOL (End of Life)? (y/n)")
	firmwareInfo.EOLStatus = strings.ToLower(eolChoice) == "y"

	if firmwareInfo.EOLStatus {
		eolDateStr := getInput("EOL date (YYYY-MM-DD, leave empty if unknown)")
		if eolDateStr != "" {
			eolDate, err := time.Parse("2006-01-02", eolDateStr)
			if err != nil {
				fmt.Println("Invalid date format, using current date instead.")
				firmwareInfo.EOLDate = time.Now()
			} else {
				firmwareInfo.EOLDate = eolDate
			}
		}
	}

	// Display firmware info
	displayFirmwareInfo(firmwareInfo)

	// Option to save
	saveChoice := getInput("Save result to file? (y/n)")
	if strings.ToLower(saveChoice) == "y" {
		saveFirmwareInfoToFile(firmwareInfo)
	}

	// Option to correlate with vulnerabilities
	correlateChoice := getInput("Correlate with vulnerability database? (y/n)")
	if strings.ToLower(correlateChoice) == "y" {
		// Create NVD connector
		nvd := NewNVDConnector("")

		// Create correlator
		correlator := NewCorrelator(nvd)

		fmt.Println("\nCorrelating with vulnerability database...")

		// Create scan result
		scanResult := &ScanResult{
			ID:           fmt.Sprintf("firmware_%s_%s_%d", manufacturer, model, time.Now().Unix()),
			Target:       fmt.Sprintf("%s %s", manufacturer, model),
			ScanType:     "FirmwareInfo",
			ScanDate:     time.Now(),
			FirmwareInfo: firmwareInfo,
		}

		// Correlate
		err := correlator.CorrelateScanResults(scanResult)
		if err != nil {
			fmt.Printf("Error correlating results: %v\n", err)
			return
		}

		// Display results
		displayScanResult(scanResult)

		// Option to save
		saveChoice = getInput("Save correlation result to file? (y/n)")
		if strings.ToLower(saveChoice) == "y" {
			saveScanResultToFile(scanResult)
		}
	}
}

// correlateResults loads previous scan results and correlates them with vulnerabilities
func correlateResults() {
	fmt.Println("\n--- Correlate Previous Scan Results ---")

	// List available scan results
	scanFiles, err := listScanFiles()
	if err != nil {
		fmt.Printf("Error listing scan files: %v\n", err)
		return
	}

	if len(scanFiles) == 0 {
		fmt.Println("No previous scan results found.")
		return
	}

	fmt.Println("\nAvailable scan results:")
	for i, file := range scanFiles {
		fmt.Printf("%d. %s\n", i+1, filepath.Base(file))
	}

	// Get user choice
	choiceStr := getInput("Enter number to select a scan result (or 0 to cancel)")
	choice, err := strconv.Atoi(choiceStr)
	if err != nil || choice < 1 || choice > len(scanFiles) {
		fmt.Println("Invalid choice, returning to main menu.")
		return
	}

	// Load scan result
	scanResult, err := loadScanResult(scanFiles[choice-1])
	if err != nil {
		fmt.Printf("Error loading scan result: %v\n", err)
		return
	}

	// Create NVD connector
	nvd := NewNVDConnector("")

	// Create correlator
	correlator := NewCorrelator(nvd)

	fmt.Println("\nCorrelating with vulnerability database...")

	// Correlate
	err = correlator.CorrelateScanResults(scanResult)
	if err != nil {
		fmt.Printf("Error correlating results: %v\n", err)
		return
	}

	// Display results
	displayScanResult(scanResult)

	// Option to save
	saveChoice := getInput("Save updated result to file? (y/n)")
	if strings.ToLower(saveChoice) == "y" {
		saveScanResultToFile(scanResult)
	}
}

// configureSettings allows changing OSINT tool settings
func configureSettings(options *OSINTCmdOptions) {
	fmt.Println("\n--- Settings ---")
	fmt.Printf("1. NVD API Key: %s\n", maskString(options.APIKey))
	fmt.Printf("2. Confidence Threshold: %.1f\n", options.ConfidenceThreshold)
	fmt.Printf("3. Output Format: %s\n", options.OutputFormat)
	fmt.Printf("4. Return to Main Menu\n")

	choice := getInput("Select a setting to change")

	switch choice {
	case "1": // API Key
		options.APIKey = getInput("Enter NVD API Key (leave empty for no key)")
		fmt.Println("API Key updated.")
	case "2": // Confidence Threshold
		thresholdStr := getInput("Enter confidence threshold (0.0-1.0)")
		threshold, err := strconv.ParseFloat(thresholdStr, 64)
		if err == nil && threshold >= 0 && threshold <= 1 {
			options.ConfidenceThreshold = threshold
			fmt.Println("Confidence threshold updated.")
		} else {
			fmt.Println("Invalid threshold, keeping current value.")
		}
	case "3": // Output Format
		fmt.Println("Available formats: text, json, csv")
		format := getInput("Enter output format")
		if format == "text" || format == "json" || format == "csv" {
			options.OutputFormat = format
			fmt.Println("Output format updated.")
		} else {
			fmt.Println("Invalid format, keeping current value.")
		}
	case "4": // Return
		return
	default:
		fmt.Println("Invalid choice, returning to main menu.")
	}
}

// displayVulnerability prints vulnerability details
func displayVulnerability(vuln Vulnerability) {
	fmt.Println("\n=== Vulnerability Details ===")
	fmt.Printf("ID: %s\n", vuln.ID)
	fmt.Printf("Title: %s\n", vuln.Title)
	fmt.Printf("Description: %s\n", vuln.Description)
	fmt.Printf("Severity: %s (CVSS %.1f)\n", vuln.Severity, vuln.CVSS)

	if len(vuln.AffectedSystems) > 0 {
		fmt.Println("\nAffected Systems:")
		for _, system := range vuln.AffectedSystems {
			fmt.Printf("- %s\n", system)
		}
	}

	if len(vuln.References) > 0 {
		fmt.Println("\nReferences:")
		for _, ref := range vuln.References {
			fmt.Printf("- %s\n", ref)
		}
	}

	if len(vuln.Mitigations) > 0 {
		fmt.Println("\nMitigations:")
		for _, mitigation := range vuln.Mitigations {
			fmt.Printf("- %s\n", mitigation)
		}
	}

	fmt.Printf("\nPublished: %s\n", vuln.Published.Format("2006-01-02"))
	if !vuln.Modified.IsZero() {
		fmt.Printf("Last Modified: %s\n", vuln.Modified.Format("2006-01-02"))
	}

	fmt.Printf("Source: %s\n", vuln.Source)
}

// displayVulnerabilityList prints a list of vulnerabilities
func displayVulnerabilityList(vulns []Vulnerability) {
	if len(vulns) == 0 {
		fmt.Println("No vulnerabilities found.")
		return
	}

	fmt.Println("\n=== Vulnerabilities ===")
	fmt.Printf("%-15s %-10s %-7s %s\n", "CVE ID", "Severity", "CVSS", "Title")
	fmt.Printf("%s\n", strings.Repeat("-", 80))

	for _, vuln := range vulns {
		// Truncate title if needed
		title := vuln.Title
		if len(title) > 45 {
			title = title[:42] + "..."
		}

		fmt.Printf("%-15s %-10s %-7.1f %s\n", vuln.ID, vuln.Severity, vuln.CVSS, title)
	}
}

// displayServerInfo prints server information
func displayServerInfo(info *ServerInfo) {
	fmt.Println("\n=== Server Information ===")
	fmt.Printf("IP Address: %s\n", info.IPAddress)

	if info.Hostname != "" {
		fmt.Printf("Hostname: %s\n", info.Hostname)
	}

	if info.OS != "" {
		fmt.Printf("Operating System: %s", info.OS)
		if info.OSVersion != "" {
			fmt.Printf(" %s", info.OSVersion)
		}
		fmt.Println()
	}

	if info.ProductName != "" {
		fmt.Printf("Product: %s", info.ProductName)
		if info.ProductVersion != "" {
			fmt.Printf(" %s", info.ProductVersion)
		}
		fmt.Println()
	}

	if len(info.Ports) > 0 {
		fmt.Println("\nOpen Ports:")
		for _, port := range info.Ports {
			service := info.Services[port]
			fmt.Printf("- %d: %s\n", port, service)

			// Print banner if available
			if banner, found := info.Banners[port]; found && banner != "" {
				fmt.Printf("  Banner: %s\n", banner)
			}
		}
	}

	if len(info.Headers) > 0 {
		fmt.Println("\nHTTP Headers:")
		for name, value := range info.Headers {
			fmt.Printf("- %s: %s\n", name, value)
		}
	}

	if !info.EOLDate.IsZero() {
		fmt.Printf("\nEOL Date: %s\n", info.EOLDate.Format("2006-01-02"))
		if info.UpdateAvailable {
			fmt.Println("Status: EOL (updates no longer available)")
		}
	}
}

// displayFirmwareInfo prints firmware information
func displayFirmwareInfo(info *FirmwareInfo) {
	fmt.Println("\n=== Firmware Information ===")
	fmt.Printf("Device Type: %s\n", info.DeviceType)
	fmt.Printf("Manufacturer: %s\n", info.Manufacturer)
	fmt.Printf("Model: %s\n", info.Model)
	fmt.Printf("Firmware Version: %s\n", info.FirmwareVersion)

	if !info.ReleaseDate.IsZero() {
		fmt.Printf("Release Date: %s\n", info.ReleaseDate.Format("2006-01-02"))
	}

	if info.LatestVersion != "" {
		fmt.Printf("Latest Version: %s\n", info.LatestVersion)
	}

	if info.EOLStatus {
		fmt.Println("EOL Status: End of Life")
		if !info.EOLDate.IsZero() {
			fmt.Printf("EOL Date: %s\n", info.EOLDate.Format("2006-01-02"))
		}
	}
}

// displayScanResult prints a scan result with vulnerabilities
func displayScanResult(result *ScanResult) {
	fmt.Println("\n=== Scan Result ===")
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Scan Type: %s\n", result.ScanType)
	fmt.Printf("Scan Date: %s\n", result.ScanDate.Format("2006-01-02 15:04:05"))

	if len(result.Vulnerabilities) > 0 {
		fmt.Printf("\nVulnerabilities Found: %d\n", len(result.Vulnerabilities))
		fmt.Printf("Overall Risk Score: %.1f/10\n", result.RiskScore)

		fmt.Printf("\n%-15s %-10s %-7s %-15s %s\n", "CVE ID", "Severity", "CVSS", "Confidence", "Title")
		fmt.Printf("%s\n", strings.Repeat("-", 100))

		for _, vuln := range result.Vulnerabilities {
			// Get confidence score
			confidence := 0.0
			if result.ConfidenceScore != nil {
				if score, found := result.ConfidenceScore[vuln.ID]; found {
					confidence = score
				}
			}

			// Determine confidence level
			confidenceLevel := "Low"
			if confidence >= 0.8 {
				confidenceLevel = "High"
			} else if confidence >= 0.6 {
				confidenceLevel = "Medium"
			}

			// Truncate title if needed
			title := vuln.Title
			if len(title) > 45 {
				title = title[:42] + "..."
			}

			fmt.Printf("%-15s %-10s %-7.1f %-15s %s\n",
				vuln.ID, vuln.Severity, vuln.CVSS,
				fmt.Sprintf("%.1f%%(%s)", confidence*100, confidenceLevel),
				title)
		}
	} else {
		fmt.Println("\nNo vulnerabilities found.")
	}
}

// saveVulnerabilityToFile saves a vulnerability to a file
func saveVulnerabilityToFile(vuln Vulnerability) {
	// Create filename
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(LogDirectory, fmt.Sprintf("vuln_%s_%s.json", vuln.ID, timestamp))

	// Create JSON data
	data, err := json.MarshalIndent(vuln, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON: %v\n", err)
		return
	}

	// Write to file
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("Vulnerability saved to %s\n", filename)
}

// saveServerInfoToFile saves server information to a file
func saveServerInfoToFile(info *ServerInfo) {
	// Create filename
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(LogDirectory, fmt.Sprintf("server_%s_%s.json", info.IPAddress, timestamp))

	// Create JSON data
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON: %v\n", err)
		return
	}

	// Write to file
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("Server information saved to %s\n", filename)
}

// saveFirmwareInfoToFile saves firmware information to a file
func saveFirmwareInfoToFile(info *FirmwareInfo) {
	// Create filename
	timestamp := time.Now().Format("20060102_150405")
	safeName := strings.ReplaceAll(info.Manufacturer, " ", "_")
	safeModel := strings.ReplaceAll(info.Model, " ", "_")
	filename := filepath.Join(LogDirectory, fmt.Sprintf("firmware_%s_%s_%s.json", safeName, safeModel, timestamp))

	// Create JSON data
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON: %v\n", err)
		return
	}

	// Write to file
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("Firmware information saved to %s\n", filename)
}

// saveScanResultToFile saves a scan result to a file
func saveScanResultToFile(result *ScanResult) {
	// Create filename
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(LogDirectory, fmt.Sprintf("scan_%s_%s.json", result.ID, timestamp))

	// Create JSON data
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON: %v\n", err)
		return
	}

	// Write to file
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("Scan result saved to %s\n", filename)
}

// listScanFiles returns a list of scan result files
func listScanFiles() ([]string, error) {
	pattern := filepath.Join(LogDirectory, "scan_*.json")
	return filepath.Glob(pattern)
}

// loadScanResult loads a scan result from a file
func loadScanResult(filename string) (*ScanResult, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON
	var result ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// getInput reads user input with a prompt
func getInput(prompt string) string {
	fmt.Printf("%s: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// maskString masks a string for display
func maskString(s string) string {
	if s == "" {
		return "<none>"
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
