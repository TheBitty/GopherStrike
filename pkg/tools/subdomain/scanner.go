// pkg/tools/subdomain/scanner.go
package subdomain

import (
	"GopherStrike/pkg/tools"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// Output formats
	FormatText = "text"
	FormatJSON = "json"
	FormatCSV  = "csv"
)

// ScanContext holds shared data for the scan operation
type ScanContext struct {
	Domain          string
	WordlistPath    string
	WordlistSize    int
	StartTime       time.Time
	LogsDirectory   string
	OutputFormats   []string
	ProgressLock    sync.Mutex
	ProgressCurrent int
	ProgressTotal   int
}

// RunScanner is the main entry point for the subdomain scanner
func RunScanner() error {
	// Print banner
	fmt.Println("\n===================================")
	fmt.Println("      GopherStrike SubTapper")
	fmt.Println("      Subdomain Enumeration")
	fmt.Println("===================================")

	// Create context with cancellation for cleanup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize scan context
	scanCtx := &ScanContext{
		StartTime:     time.Now(),
		OutputFormats: []string{FormatText, FormatJSON},
		LogsDirectory: filepath.Join("logs", "subdomains"),
	}

	// Create logs directory
	if err := EnsureDirectory(scanCtx.LogsDirectory); err != nil {
		fmt.Printf("Warning: Failed to create logs directory: %v\n", err)
	}

	// Get the domain to scan
	domain, err := GetDomainInput()
	if err != nil {
		return err
	}
	scanCtx.Domain = domain

	// Get the wordlist path
	wordlistPath, err := GetWordlistPath()
	if err != nil {
		return err
	}
	scanCtx.WordlistPath = wordlistPath

	// Create scan options with optimal defaults
	options := tools.ScanOptions{
		WordlistPath: wordlistPath,
		Threads:      getDefaultThreadCount(),
		CheckHTTP:    true,
		CheckSSL:     true,
		Timeout:      5,
		ResolveIPs:   true,
	}

	// Allow user to customize options
	options, err = CustomizeOptions(options)
	if err != nil {
		return err
	}

	// Summary before starting
	fmt.Println("\n===== Scan Configuration =====")
	fmt.Printf("Target domain:      %s\n", domain)
	fmt.Printf("Wordlist:           %s\n", wordlistPath)
	fmt.Printf("Thread count:       %d\n", options.Threads)
	fmt.Printf("HTTP check:         %t\n", options.CheckHTTP)
	fmt.Printf("SSL check:          %t\n", options.CheckSSL)
	fmt.Printf("Connection timeout: %d seconds\n", options.Timeout)
	fmt.Printf("Resolve IPs:        %t\n", options.ResolveIPs)

	// Confirm scan
	fmt.Print("\nPress Enter to start the scan or Ctrl+C to abort...")
	fmt.Scanln()

	fmt.Printf("\nStarting subdomain scan for: %s\n", domain)
	fmt.Println("This may take a while depending on wordlist size...")

	// Start a go routine to show progress
	progressChan := make(chan struct{})
	go showProgressSpinner(ctx, progressChan)

	// Run the scan
	result, err := tools.ScanSubdomains(domain, options)

	// Signal progress routine to stop
	cancel()
	<-progressChan

	if err != nil {
		return fmt.Errorf("scan error: %v", err)
	}

	// Calculate duration
	duration := time.Since(scanCtx.StartTime)

	// Print summary
	fmt.Println("\n\n===== Scan Results =====")
	fmt.Printf("Scan completed in: %s\n", duration.Round(time.Second))
	fmt.Printf("Total subdomains found: %d\n", result.TotalFound)
	fmt.Printf("Active subdomains: %d\n", result.Active)

	// Print the results
	tools.PrintResults(result)

	// Save results to a file
	if err := SaveResults(scanCtx, *result); err != nil {
		fmt.Printf("Warning: Failed to save results: %v\n", err)
	}

	return nil
}

// showProgressSpinner displays a simple spinner to indicate progress
func showProgressSpinner(ctx context.Context, done chan struct{}) {
	defer close(done)

	spinChars := []string{"|", "/", "-", "\\"}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	i := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			fmt.Printf("\rScanning subdomains... %s", spinChars[i])
			i = (i + 1) % len(spinChars)
		}
	}
}

// SaveResults saves the scan results to files in different formats
func SaveResults(scanCtx *ScanContext, result tools.ScanResult) error {
	// Create logs directory if it doesn't exist
	if err := EnsureDirectory(scanCtx.LogsDirectory); err != nil {
		return err
	}

	// Generate timestamp for the filename
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	baseFilename := fmt.Sprintf("%s_%s", scanCtx.Domain, timestamp)

	// Sort results: active subdomains first, then alphabetically
	sortResults(&result)

	// Save in each requested format
	for _, format := range scanCtx.OutputFormats {
		var err error

		switch format {
		case FormatText:
			err = saveTextResults(scanCtx, result, filepath.Join(scanCtx.LogsDirectory, baseFilename+".txt"))
		case FormatJSON:
			err = saveJSONResults(scanCtx, result, filepath.Join(scanCtx.LogsDirectory, baseFilename+".json"))
		case FormatCSV:
			err = saveCSVResults(scanCtx, result, filepath.Join(scanCtx.LogsDirectory, baseFilename+".csv"))
		}

		if err != nil {
			fmt.Printf("Warning: Failed to save results in %s format: %v\n", format, err)
		}
	}

	fmt.Printf("\nResults saved to: %s/%s.*\n", scanCtx.LogsDirectory, baseFilename)
	return nil
}

// sortResults sorts the scan results with active subdomains first, then alphabetically
func sortResults(result *tools.ScanResult) {
	sort.Slice(result.Results, func(i, j int) bool {
		// First sort by active status (active first)
		if result.Results[i].Active != result.Results[j].Active {
			return result.Results[i].Active
		}
		// Then sort alphabetically
		return result.Results[i].Name < result.Results[j].Name
	})
}

// saveTextResults saves the results in human-readable text format
func saveTextResults(scanCtx *ScanContext, result tools.ScanResult, filename string) error {
	// Open the file for writing
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "GopherStrike SubTapper - Subdomain Scan Results\n")
	fmt.Fprintf(file, "=============================================\n\n")
	fmt.Fprintf(file, "Target Domain: %s\n", scanCtx.Domain)
	fmt.Fprintf(file, "Scan Time: %s\n", time.Now().Format(time.RFC1123))
	fmt.Fprintf(file, "Duration: %.2f seconds\n", result.Duration)
	fmt.Fprintf(file, "Wordlist: %s\n", scanCtx.WordlistPath)
	fmt.Fprintf(file, "Total Subdomains Found: %d\n", result.TotalFound)
	fmt.Fprintf(file, "Active Subdomains: %d\n\n", result.Active)

	// Write results table
	fmt.Fprintf(file, "%-40s %-15s %-7s %-20s\n", "SUBDOMAIN", "STATUS", "HTTP", "IP ADDRESSES")
	fmt.Fprintf(file, "%s\n", strings.Repeat("-", 90))

	// Write each subdomain
	for _, subdomain := range result.Results {
		writeSubdomainToFile(file, subdomain)
	}

	// Write footer
	fmt.Fprintf(file, "\n--- End of Report ---\n")
	fmt.Fprintf(file, "Generated by GopherStrike SubTapper on %s\n", time.Now().Format(time.RFC1123))

	return nil
}

// saveJSONResults saves the results in JSON format for machine processing
func saveJSONResults(scanCtx *ScanContext, result tools.ScanResult, filename string) error {
	// Add metadata to the result
	resultWithMeta := struct {
		tools.ScanResult
		Scanner    string `json:"scanner"`
		ReportTime string `json:"report_time"`
		WordList   string `json:"wordlist"`
	}{
		ScanResult: result,
		Scanner:    "GopherStrike SubTapper",
		ReportTime: time.Now().Format(time.RFC3339),
		WordList:   scanCtx.WordlistPath,
	}

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(resultWithMeta, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(filename, jsonData, 0644)
}

// saveCSVResults saves the results in CSV format for spreadsheet import
func saveCSVResults(_ *ScanContext, result tools.ScanResult, filename string) error {
	// Open the file for writing
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write CSV header
	fmt.Fprintln(file, "Subdomain,Status,HTTP Status,IP Addresses,Error")

	// Write each subdomain
	for _, subdomain := range result.Results {
		status := "Inactive"
		if subdomain.Active {
			status = "Active"
		}

		httpStatus := ""
		if subdomain.HTTPStatus > 0 {
			httpStatus = fmt.Sprintf("%d", subdomain.HTTPStatus)
		}

		ips := strings.Join(subdomain.IPs, "; ")

		// Escape any commas in fields
		subdomainName := strings.ReplaceAll(subdomain.Name, ",", "\\,")
		ips = strings.ReplaceAll(ips, ",", "\\,")
		errorField := strings.ReplaceAll(subdomain.Error, ",", "\\,")

		fmt.Fprintf(file, "%s,%s,%s,%s,%s\n",
			subdomainName, status, httpStatus, ips, errorField)
	}

	return nil
}

// writeSubdomainToFile writes a single subdomain entry to the results file
func writeSubdomainToFile(file *os.File, subdomain tools.SubdomainResult) {
	status := "Inactive"
	if subdomain.Active {
		status = "Active"
	}

	httpStatus := "-"
	if subdomain.HTTPStatus > 0 {
		httpStatus = fmt.Sprintf("%d", subdomain.HTTPStatus)
	}

	ipList := "N/A"
	if len(subdomain.IPs) > 0 {
		ipList = strings.Join(subdomain.IPs, ", ")
	}

	fmt.Fprintf(file, "%-40s %-15s %-7s %-20s\n",
		subdomain.Name, status, httpStatus, ipList)
}
