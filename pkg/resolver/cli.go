// pkg/resolver/cli.go
package resolver

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

// RunHostResolver is the main entry point for the host resolver CLI
func RunHostResolver() error {
	// Print banner
	fmt.Println("\n===================================")
	fmt.Println("      GopherStrike DomainEye")
	fmt.Println("    Host & Subdomain Resolver")
	fmt.Println("===================================")

	// Initialize host resolver with default settings
	resolver := NewHostResolver()

	// Main menu loop
	for {
		printMainMenu()
		choice := getInput("Select an option")

		switch choice {
		case "1": // Resolve single hostname
			resolveSingleHost(resolver)
		case "2": // Resolve multiple hostnames
			resolveMultipleHosts(resolver)
		case "3": // Resolve subdomains
			resolveSubdomains(resolver)
		case "4": // Configure resolver settings
			configureResolverSettings(resolver)
		case "5": // Return to main menu
			fmt.Println("Returning to main menu...")
			return nil
		default:
			fmt.Println("Invalid option, please try again.")
		}
	}
}

// printMainMenu displays the host resolver menu
func printMainMenu() {
	fmt.Println("\nGopherStrike DomainEye - Main Menu")
	fmt.Println("====================================")
	fmt.Println("1. Resolve Single Hostname")
	fmt.Println("2. Resolve Multiple Hostnames")
	fmt.Println("3. Resolve Subdomains")
	fmt.Println("4. Configure Settings")
	fmt.Println("5. Return to Main Menu")
}

// resolveSingleHost resolves a single hostname
func resolveSingleHost(resolver *HostResolver) {
	hostname := getInput("Enter hostname to resolve (e.g., example.com)")
	if hostname == "" {
		fmt.Println("Error: Hostname cannot be empty.")
		return
	}

	fmt.Printf("\nResolving %s...\n", hostname)
	result, err := resolver.ResolveHost(hostname)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	displayResolveResult(result)

	// Option to save
	saveChoice := getInput("Save result to file? (y/n)")
	if strings.ToLower(saveChoice) == "y" {
		saveResultToFile([]ResolveResult{result}, hostname)
	}
}

// resolveMultipleHosts resolves multiple hostnames from a file
func resolveMultipleHosts(resolver *HostResolver) {
	fmt.Println("\n--- Bulk Host Resolution ---")
	fmt.Println("1. Enter hostnames manually")
	fmt.Println("2. Load hostnames from file")
	fmt.Println("3. Go back")

	choice := getInput("Select an option")

	var hostnames []string

	switch choice {
	case "1": // Enter manually
		fmt.Println("Enter one hostname per line. Enter a blank line when done.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("> ")
			hostname, _ := reader.ReadString('\n')
			hostname = strings.TrimSpace(hostname)
			if hostname == "" {
				break
			}
			hostnames = append(hostnames, hostname)
		}

	case "2": // Load from file
		filePath := getInput("Enter path to hostnames file")
		var err error
		hostnames, err = loadHostnamesFromFile(filePath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Loaded %d hostnames from file.\n", len(hostnames))

	case "3": // Go back
		return

	default:
		fmt.Println("Invalid option, returning to main menu.")
		return
	}

	if len(hostnames) == 0 {
		fmt.Println("No hostnames to resolve.")
		return
	}

	// Get concurrency level
	concurrencyStr := getInput("Enter concurrency level (1-50, default: 10)")
	concurrency := 10
	if concurrencyStr != "" {
		val, err := strconv.Atoi(concurrencyStr)
		if err == nil && val > 0 && val <= 50 {
			concurrency = val
		}
	}

	fmt.Printf("\nResolving %d hostnames with %d workers...\n", len(hostnames), concurrency)
	startTime := time.Now()

	results, err := resolver.BulkResolve(hostnames, concurrency)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	duration := time.Since(startTime)
	resolvedCount := 0
	for _, result := range results {
		if result.Resolved {
			resolvedCount++
		}
	}

	fmt.Printf("\nResolution completed in %s\n", duration.Round(time.Millisecond))
	fmt.Printf("Successfully resolved %d out of %d hostnames.\n", resolvedCount, len(hostnames))

	// Display results summary
	displayResolutionSummary(results)

	// Option to save
	saveChoice := getInput("Save results to file? (y/n)")
	if strings.ToLower(saveChoice) == "y" {
		saveResultToFile(results, "bulk_resolution")
	}
}

// resolveSubdomains resolves subdomains for a given domain
func resolveSubdomains(resolver *HostResolver) {
	fmt.Println("\n--- Subdomain Resolution ---")
	domain := getInput("Enter base domain (e.g., example.com)")
	if domain == "" {
		fmt.Println("Error: Domain cannot be empty.")
		return
	}

	if !IsValidDomain(domain) {
		fmt.Println("Error: Invalid domain format.")
		return
	}

	fmt.Println("\n1. Enter subdomains manually")
	fmt.Println("2. Load subdomains from wordlist file")
	fmt.Println("3. Go back")

	choice := getInput("Select an option")

	var subdomains []string

	switch choice {
	case "1": // Enter manually
		fmt.Println("Enter one subdomain per line (without domain part). Enter a blank line when done.")
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("> ")
			subdomain, _ := reader.ReadString('\n')
			subdomain = strings.TrimSpace(subdomain)
			if subdomain == "" {
				break
			}
			subdomains = append(subdomains, subdomain)
		}

	case "2": // Load from file
		filePath := getInput("Enter path to wordlist file")
		var err error
		subdomains, err = loadHostnamesFromFile(filePath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Loaded %d subdomains from file.\n", len(subdomains))

	case "3": // Go back
		return

	default:
		fmt.Println("Invalid option, returning to main menu.")
		return
	}

	if len(subdomains) == 0 {
		fmt.Println("No subdomains to resolve.")
		return
	}

	// Get concurrency level
	concurrencyStr := getInput("Enter concurrency level (1-50, default: 10)")
	concurrency := 10
	if concurrencyStr != "" {
		val, err := strconv.Atoi(concurrencyStr)
		if err == nil && val > 0 && val <= 50 {
			concurrency = val
		}
	}

	fmt.Printf("\nResolving %d subdomains for %s with %d workers...\n", len(subdomains), domain, concurrency)
	startTime := time.Now()

	results, err := resolver.ResolveSubdomainsConcurrent(domain, subdomains, concurrency)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	duration := time.Since(startTime)
	resolvedCount := 0
	for _, result := range results {
		if result.Resolved {
			resolvedCount++
		}
	}

	fmt.Printf("\nResolution completed in %s\n", duration.Round(time.Millisecond))
	fmt.Printf("Successfully resolved %d out of %d subdomains.\n", resolvedCount, len(subdomains))

	// Display resolved subdomains
	displaySubdomainsResults(results)

	// Option to save
	saveChoice := getInput("Save results to file? (y/n)")
	if strings.ToLower(saveChoice) == "y" {
		saveResultToFile(results, fmt.Sprintf("subdomains_%s", domain))
	}
}

// configureResolverSettings allows changing resolver settings
func configureResolverSettings(resolver *HostResolver) {
	fmt.Println("\n--- Resolver Settings ---")
	fmt.Printf("1. DNS Servers: %s\n", formatDNSServers(resolver.DNSServers))
	fmt.Printf("2. Timeout: %s\n", resolver.Timeout)
	fmt.Printf("3. Max Retries: %d\n", resolver.MaxRetries)
	fmt.Printf("4. IPv4 Only: %t\n", resolver.IPv4Only)
	fmt.Printf("5. IPv6 Only: %t\n", resolver.IPv6Only)
	fmt.Printf("6. Clear Cache\n")
	fmt.Printf("7. Return to Main Menu\n")

	choice := getInput("Select a setting to change")

	switch choice {
	case "1": // DNS Servers
		dnsServers := getInput("Enter DNS servers (comma-separated, e.g., 8.8.8.8:53,1.1.1.1:53)")
		if dnsServers == "" {
			resolver.DNSServers = nil
			fmt.Println("Using system default DNS servers.")
		} else {
			resolver.DNSServers = strings.Split(dnsServers, ",")
			fmt.Println("DNS servers updated.")
		}

	case "2": // Timeout
		timeoutStr := getInput("Enter timeout in seconds (1-30)")
		timeout, err := strconv.Atoi(timeoutStr)
		if err == nil && timeout >= 1 && timeout <= 30 {
			resolver.Timeout = time.Duration(timeout) * time.Second
			fmt.Println("Timeout updated.")
		} else {
			fmt.Println("Invalid timeout value, keeping current setting.")
		}

	case "3": // Max Retries
		retriesStr := getInput("Enter maximum retries (0-5)")
		retries, err := strconv.Atoi(retriesStr)
		if err == nil && retries >= 0 && retries <= 5 {
			resolver.MaxRetries = retries
			fmt.Println("Max retries updated.")
		} else {
			fmt.Println("Invalid retry value, keeping current setting.")
		}

	case "4": // IPv4 Only
		ipv4OnlyStr := getInput("Resolve only IPv4 addresses? (y/n)")
		resolver.WithIPv4Only(strings.ToLower(ipv4OnlyStr) == "y")
		fmt.Println("IPv4 Only setting updated.")

	case "5": // IPv6 Only
		ipv6OnlyStr := getInput("Resolve only IPv6 addresses? (y/n)")
		resolver.WithIPv6Only(strings.ToLower(ipv6OnlyStr) == "y")
		fmt.Println("IPv6 Only setting updated.")

	case "6": // Clear Cache
		resolver.ClearCache()
		fmt.Println("Resolution cache cleared.")

	case "7": // Return
		return

	default:
		fmt.Println("Invalid choice, returning to main menu.")
	}
}

// displayResolveResult prints a single resolution result
func displayResolveResult(result ResolveResult) {
	fmt.Println("\n=== Resolution Result ===")
	fmt.Printf("Hostname: %s\n", result.Hostname)
	fmt.Printf("Resolved: %t\n", result.Resolved)

	if len(result.IPv4) > 0 {
		fmt.Println("\nIPv4 Addresses:")
		for _, ip := range result.IPv4 {
			fmt.Printf("- %s\n", ip)
		}
	}

	if len(result.IPv6) > 0 {
		fmt.Println("\nIPv6 Addresses:")
		for _, ip := range result.IPv6 {
			fmt.Printf("- %s\n", ip)
		}
	}

	if result.Error != "" {
		fmt.Printf("\nError: %s\n", result.Error)
	}
}

// displayResolutionSummary prints a summary of multiple resolution results
func displayResolutionSummary(results []ResolveResult) {
	fmt.Println("\n=== Resolution Summary ===")
	fmt.Printf("%-40s %-15s %-7s\n", "HOSTNAME", "STATUS", "IPs")
	fmt.Printf("%s\n", strings.Repeat("-", 70))

	for _, result := range results {
		status := "Resolved"
		if !result.Resolved {
			status = "Failed"
		}

		ipCount := len(result.IPv4) + len(result.IPv6)
		fmt.Printf("%-40s %-15s %-7d\n", truncateString(result.Hostname, 40), status, ipCount)
	}
}

// displaySubdomainsResults prints subdomain resolution results
func displaySubdomainsResults(results []ResolveResult) {
	fmt.Println("\n=== Resolved Subdomains ===")
	fmt.Printf("%-40s %-15s %-15s\n", "SUBDOMAIN", "IPv4", "IPv6")
	fmt.Printf("%s\n", strings.Repeat("-", 75))

	// First show resolved subdomains
	for _, result := range results {
		if result.Resolved {
			ipv4 := "none"
			if len(result.IPv4) > 0 {
				ipv4 = result.IPv4[0]
				if len(result.IPv4) > 1 {
					ipv4 += fmt.Sprintf(" (+%d)", len(result.IPv4)-1)
				}
			}

			ipv6 := "none"
			if len(result.IPv6) > 0 {
				ipv6 = truncateString(result.IPv6[0], 15)
				if len(result.IPv6) > 1 {
					ipv6 += fmt.Sprintf(" (+%d)", len(result.IPv6)-1)
				}
			}

			fmt.Printf("%-40s %-15s %-15s\n", truncateString(result.Hostname, 40), ipv4, ipv6)
		}
	}
}

// saveResultToFile saves resolution results to a file
func saveResultToFile(results []ResolveResult, baseName string) {
	// Create logs directory
	logsDir := filepath.Join("logs", "resolver")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		fmt.Printf("Warning: Failed to create logs directory: %v\n", err)
		return
	}

	// Generate timestamp for the filename
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := filepath.Join(logsDir, fmt.Sprintf("%s_%s.json", baseName, timestamp))

	// Marshal to JSON
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON: %v\n", err)
		return
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("Results saved to %s\n", filename)
}

// loadHostnamesFromFile loads hostnames from a file, one per line
func loadHostnamesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var hostnames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostname := strings.TrimSpace(scanner.Text())
		if hostname != "" && !strings.HasPrefix(hostname, "#") {
			hostnames = append(hostnames, hostname)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return hostnames, nil
}

// getInput reads user input with a prompt
func getInput(prompt string) string {
	fmt.Printf("%s: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// formatDNSServers formats DNS servers list for display
func formatDNSServers(servers []string) string {
	if len(servers) == 0 {
		return "System Default"
	}
	return strings.Join(servers, ", ")
}

// truncateString truncates a string to the given maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
