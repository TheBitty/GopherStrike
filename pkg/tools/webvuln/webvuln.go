// pkg/tools/webvuln/webvuln.go
package webvuln

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

// RunWebVulnScanner is the main entry point for the web vulnerability scanner
func RunWebVulnScanner() error {
	fmt.Println("\n[+] Web Application Vulnerability Scanner")
	fmt.Println("    =======================================")
	fmt.Println("[i] This tool scans web applications for common security vulnerabilities")
	fmt.Println("[i] including XSS, SQL Injection, CSRF, and more.")

	// Get target URL
	target, err := getTargetDetails()
	if err != nil {
		return err
	}

	// Configure scan options
	options, err := configureScanOptions()
	if err != nil {
		return err
	}

	fmt.Printf("\n[+] Starting scan against %s\n", target.URL)
	fmt.Println("[+] Scan configuration:")
	fmt.Printf("    - Payload Level: %d/5\n", options.PayloadLevel)
	fmt.Printf("    - Timeout: %d seconds\n", options.Timeout)
	fmt.Printf("    - Tests Enabled: ")
	enabledTests := []string{}
	if options.EnableXSS {
		enabledTests = append(enabledTests, "XSS")
	}
	if options.EnableSQLInjection {
		enabledTests = append(enabledTests, "SQLi")
	}
	if options.EnableFileInclusion {
		enabledTests = append(enabledTests, "File Inclusion")
	}
	if options.EnableCSRF {
		enabledTests = append(enabledTests, "CSRF")
	}
	if options.EnableMisconfiguration {
		enabledTests = append(enabledTests, "Misconfigurations")
	}
	if options.EnableAuthTesting {
		enabledTests = append(enabledTests, "Auth Weaknesses")
	}
	fmt.Println(strings.Join(enabledTests, ", "))

	// Initialize scanner
	scanner := NewScanner(options)

	// Start scan with progress indicator
	fmt.Println("\n[+] Scanning in progress...")

	scanStartTime := time.Now()
	doneChan := make(chan bool)

	// Simple progress indicator
	go func() {
		symbols := []string{"-", "\\", "|", "/"}
		i := 0
		for {
			select {
			case <-doneChan:
				fmt.Print("\r[+] Scan completed                 \n")
				return
			default:
				fmt.Printf("\r[%s] Scanning... %s elapsed", symbols[i], formatDuration(time.Since(scanStartTime)))
				i = (i + 1) % len(symbols)
				time.Sleep(200 * time.Millisecond)
			}
		}
	}()

	// Run the scan
	report, err := scanner.Scan(target)
	doneChan <- true

	if err != nil {
		return fmt.Errorf("scan error: %v", err)
	}

	// Display results
	displayResults(report)

	// Save report
	err = saveReport(report)
	if err != nil {
		fmt.Printf("[!] Error saving report: %v\n", err)
	}

	return nil
}

// getTargetDetails prompts the user for target details
func getTargetDetails() (ScanTarget, error) {
	reader := bufio.NewReader(os.Stdin)

	target := ScanTarget{
		Headers:   make(map[string]string),
		Cookies:   []string{},
		BasicAuth: BasicAuth{},
	}

	// Get target URL
	fmt.Print("\n[?] Enter target URL (e.g., https://example.com): ")
	urlStr, err := reader.ReadString('\n')
	if err != nil {
		return target, err
	}

	target.URL = strings.TrimSpace(urlStr)

	// Validate URL format
	if !strings.HasPrefix(target.URL, "http://") && !strings.HasPrefix(target.URL, "https://") {
		fmt.Print("[!] URL should start with http:// or https://. Use https:// ? (Y/n): ")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer == "" || answer == "y" || answer == "yes" {
			target.URL = "https://" + target.URL
		} else {
			target.URL = "http://" + target.URL
		}
	}

	// HTTP method
	fmt.Print("[?] HTTP method to use (GET/POST) [default: GET]: ")
	method, _ := reader.ReadString('\n')
	method = strings.TrimSpace(strings.ToUpper(method))

	if method == "" {
		target.Method = "GET"
	} else if method == "GET" || method == "POST" {
		target.Method = method
	} else {
		fmt.Println("[!] Invalid method. Using GET.")
		target.Method = "GET"
	}

	// Custom headers
	fmt.Print("[?] Add custom headers? (y/N): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "y" || answer == "yes" {
		fmt.Println("[i] Enter headers in format 'Name: Value' (empty line to finish):")
		for {
			fmt.Print("    > ")
			header, _ := reader.ReadString('\n')
			header = strings.TrimSpace(header)

			if header == "" {
				break
			}

			parts := strings.SplitN(header, ":", 2)
			if len(parts) != 2 {
				fmt.Println("[!] Invalid header format. Use 'Name: Value'")
				continue
			}

			name := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			target.Headers[name] = value
		}
	}

	// Cookies
	fmt.Print("[?] Add cookies? (y/N): ")
	answer, _ = reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "y" || answer == "yes" {
		fmt.Println("[i] Enter cookies in format 'name=value' (empty line to finish):")
		for {
			fmt.Print("    > ")
			cookie, _ := reader.ReadString('\n')
			cookie = strings.TrimSpace(cookie)

			if cookie == "" {
				break
			}

			target.Cookies = append(target.Cookies, cookie)
		}
	}

	// Basic authentication
	fmt.Print("[?] Use basic authentication? (y/N): ")
	answer, _ = reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "y" || answer == "yes" {
		fmt.Print("[?] Username: ")
		username, _ := reader.ReadString('\n')
		target.BasicAuth.Username = strings.TrimSpace(username)

		fmt.Print("[?] Password: ")
		password, _ := reader.ReadString('\n')
		target.BasicAuth.Password = strings.TrimSpace(password)
	}

	return target, nil
}

// configureScanOptions prompts the user for scan configuration options
func configureScanOptions() (ScanOptions, error) {
	reader := bufio.NewReader(os.Stdin)
	options := DefaultScanOptions()

	fmt.Println("\n[+] Scan Configuration")
	fmt.Println("    ------------------")

	// Payload complexity level
	fmt.Print("[?] Payload complexity level (1-5, higher = more thorough but slower) [default: 3]: ")
	levelStr, _ := reader.ReadString('\n')
	levelStr = strings.TrimSpace(levelStr)

	if levelStr != "" {
		level, err := strconv.Atoi(levelStr)
		if err == nil && level >= 1 && level <= 5 {
			options.PayloadLevel = level
		} else {
			fmt.Println("[!] Invalid level. Using default (3).")
		}
	}

	// Timeout
	fmt.Print("[?] Request timeout in seconds [default: 10]: ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)

	if timeoutStr != "" {
		timeout, err := strconv.Atoi(timeoutStr)
		if err == nil && timeout > 0 {
			options.Timeout = timeout
		} else {
			fmt.Println("[!] Invalid timeout. Using default (10).")
		}
	}

	// Select vulnerability tests
	fmt.Println("\n[+] Select vulnerability tests to run:")

	tests := []struct {
		name        string
		description string
		enabled     *bool
	}{
		{"XSS", "Cross-Site Scripting detection", &options.EnableXSS},
		{"SQLi", "SQL Injection testing", &options.EnableSQLInjection},
		{"File Inclusion", "Local/Remote File Inclusion detection", &options.EnableFileInclusion},
		{"CSRF", "Cross-Site Request Forgery detection", &options.EnableCSRF},
		{"Misconfigurations", "Security misconfigurations detection", &options.EnableMisconfiguration},
		{"Auth Testing", "Authentication weaknesses testing", &options.EnableAuthTesting},
	}

	for _, test := range tests {
		fmt.Printf("[?] Enable %s testing (%s)? (Y/n): ", test.name, test.description)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		*test.enabled = answer == "" || answer == "y" || answer == "yes"
	}

	// Additional options
	fmt.Print("[?] Ignore SSL certificate errors? (y/N): ")
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	options.IgnoreSSLErrors = answer == "y" || answer == "yes"

	// Auth testing configuration if enabled
	if options.EnableAuthTesting {
		fmt.Println("\n[+] Authentication Testing Configuration")
		fmt.Println("    ----------------------------------")

		fmt.Print("[?] Login URL path (e.g., /login): ")
		loginURL, _ := reader.ReadString('\n')
		options.LoginURL = strings.TrimSpace(loginURL)

		fmt.Print("[?] Username field name (e.g., username): ")
		usernameField, _ := reader.ReadString('\n')
		options.UsernameField = strings.TrimSpace(usernameField)

		fmt.Print("[?] Password field name (e.g., password): ")
		passwordField, _ := reader.ReadString('\n')
		options.PasswordField = strings.TrimSpace(passwordField)
	}

	return options, nil
}

// displayResults shows the scan results to the user
func displayResults(report *Report) {
	fmt.Println("\n[+] Scan Results")
	fmt.Println("    ------------")
	fmt.Printf("[i] Target: %s\n", report.Target.URL)
	fmt.Printf("[i] Scan Duration: %s\n", formatDuration(report.EndTime.Sub(report.StartTime)))

	// Count vulnerabilities by severity
	vulnerabilityCounts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}

	vulnFound := false

	for _, result := range report.Results {
		for _, testResult := range result.TestResults {
			vulnerabilityCounts[testResult.Severity]++
			vulnFound = true
		}
	}

	// Display summary count
	fmt.Println("\n[+] Vulnerabilities Summary:")
	fmt.Printf("    - Critical: %d\n", vulnerabilityCounts[SeverityCritical])
	fmt.Printf("    - High:     %d\n", vulnerabilityCounts[SeverityHigh])
	fmt.Printf("    - Medium:   %d\n", vulnerabilityCounts[SeverityMedium])
	fmt.Printf("    - Low:      %d\n", vulnerabilityCounts[SeverityLow])
	fmt.Printf("    - Info:     %d\n", vulnerabilityCounts[SeverityInfo])

	if !vulnFound {
		fmt.Println("\n[+] No vulnerabilities found!")
		return
	}

	// Display detailed findings
	fmt.Println("\n[+] Detailed Findings:")

	// Sort results by severity (critical first)
	severityOrder := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

	for _, severity := range severityOrder {
		for _, result := range report.Results {
			for _, testResult := range result.TestResults {
				if testResult.Severity == severity {
					// Colorize output based on severity
					var severityColor string
					switch severity {
					case SeverityCritical:
						severityColor = "\033[1;31m" // Bold Red
					case SeverityHigh:
						severityColor = "\033[31m" // Red
					case SeverityMedium:
						severityColor = "\033[33m" // Yellow
					case SeverityLow:
						severityColor = "\033[32m" // Green
					default:
						severityColor = "\033[0m" // Reset
					}

					fmt.Printf("\n    %s[%s]\033[0m %s\n", severityColor, severity, testResult.Description)
					fmt.Printf("    URL: %s\n", testResult.URL)

					if testResult.Method != "" {
						fmt.Printf("    Method: %s\n", testResult.Method)
					}

					if testResult.Parameter != "" {
						fmt.Printf("    Parameter: %s\n", testResult.Parameter)
					}

					if testResult.Payload.Value != "" {
						fmt.Printf("    Payload: %s\n", testResult.Payload.Value)
					}
				}
			}
		}
	}

	fmt.Println("\n[i] Report saved to disk with full details.")
}

// saveReport saves the scan report to a file
func saveReport(report *Report) error {
	// Create logs directory if it doesn't exist
	logsDir := filepath.Join("logs", "webvuln")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return err
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	hostname := strings.Replace(strings.Replace(report.Target.URL, "https://", "", 1), "http://", "", 1)
	hostname = strings.Split(hostname, "/")[0] // Get just the hostname part
	filename := filepath.Join(logsDir, fmt.Sprintf("scan_%s_%s.json", hostname, timestamp))

	// Convert report to JSON
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	err = os.WriteFile(filename, reportJSON, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("[+] Report saved to: %s\n", filename)

	// Generate HTML report if requested
	if report.ScanOptions.GenerateHTML {
		htmlFilename := strings.TrimSuffix(filename, ".json") + ".html"
		if err := generateHTMLReport(report, htmlFilename); err != nil {
			return err
		}
		fmt.Printf("[+] HTML report saved to: %s\n", htmlFilename)
	}

	return nil
}

// generateHTMLReport creates an HTML version of the report
func generateHTMLReport(report *Report, filename string) error {
	// Simple HTML template for the report
	// In a real implementation, this would use a proper template
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Scan Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #444; }
        .container { max-width: 1200px; margin: 0 auto; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .vuln-critical { background: #ffdddd; border-left: 5px solid #ff0000; padding: 10px; margin: 10px 0; }
        .vuln-high { background: #ffeeee; border-left: 5px solid #ff5555; padding: 10px; margin: 10px 0; }
        .vuln-medium { background: #ffffdd; border-left: 5px solid #ffaa00; padding: 10px; margin: 10px 0; }
        .vuln-low { background: #eeffee; border-left: 5px solid #00aa00; padding: 10px; margin: 10px 0; }
        .vuln-info { background: #f0f0f0; border-left: 5px solid #aaaaaa; padding: 10px; margin: 10px 0; }
        .details { font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Web Vulnerability Scan Report</h1>
        <p>Generated by GopherStrike Web Vulnerability Scanner</p>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target:</strong> %s</p>
            <p><strong>Scan Date:</strong> %s</p>
            <p><strong>Scan Duration:</strong> %s</p>
        </div>
        
        <h2>Vulnerabilities Found</h2>
`, report.Target.URL, report.Target.URL, report.StartTime.Format("2006-01-02 15:04:05"), formatDuration(report.EndTime.Sub(report.StartTime)))

	// Count vulnerabilities by severity
	vulnerabilityCounts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}

	for _, result := range report.Results {
		for _, testResult := range result.TestResults {
			vulnerabilityCounts[testResult.Severity]++
		}
	}

	// Add vulnerability summary
	htmlContent += fmt.Sprintf(`
        <div class="summary">
            <p><strong>Critical:</strong> %d</p>
            <p><strong>High:</strong> %d</p>
            <p><strong>Medium:</strong> %d</p>
            <p><strong>Low:</strong> %d</p>
            <p><strong>Info:</strong> %d</p>
        </div>
        
        <h2>Detailed Findings</h2>
`, vulnerabilityCounts[SeverityCritical], vulnerabilityCounts[SeverityHigh],
		vulnerabilityCounts[SeverityMedium], vulnerabilityCounts[SeverityLow],
		vulnerabilityCounts[SeverityInfo])

	// Sort results by severity (critical first)
	severityOrder := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

	for _, severity := range severityOrder {
		for _, result := range report.Results {
			for _, testResult := range result.TestResults {
				if testResult.Severity == severity {
					// Get CSS class based on severity
					var severityClass string
					switch severity {
					case SeverityCritical:
						severityClass = "vuln-critical"
					case SeverityHigh:
						severityClass = "vuln-high"
					case SeverityMedium:
						severityClass = "vuln-medium"
					case SeverityLow:
						severityClass = "vuln-low"
					default:
						severityClass = "vuln-info"
					}

					htmlContent += fmt.Sprintf(`
        <div class="%s">
            <h3>%s</h3>
            <p>%s</p>
            <div class="details">
                <p><strong>URL:</strong> %s</p>
`, severityClass, severity, testResult.Description, testResult.URL)

					if testResult.Method != "" {
						htmlContent += fmt.Sprintf("                <p><strong>Method:</strong> %s</p>\n", testResult.Method)
					}

					if testResult.Parameter != "" {
						htmlContent += fmt.Sprintf("                <p><strong>Parameter:</strong> %s</p>\n", testResult.Parameter)
					}

					if testResult.Payload.Value != "" {
						htmlContent += fmt.Sprintf("                <p><strong>Payload:</strong> %s</p>\n", testResult.Payload.Value)
					}

					htmlContent += "            </div>\n        </div>\n"
				}
			}
		}
	}

	// Close HTML
	htmlContent += `
    </div>
</body>
</html>
`

	// Write to file
	err := os.WriteFile(filename, []byte(htmlContent), 0644)
	return err
}

// formatDuration formats a duration as a human-readable string
func formatDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	minutes := seconds / 60
	hours := minutes / 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes%60, seconds%60)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds%60)
	} else {
		return fmt.Sprintf("%ds", seconds)
	}
}
