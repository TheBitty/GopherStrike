// SubTapper.go
package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SubdomainResult represents a single subdomain scan result
type SubdomainResult struct {
	Name       string   `json:"name"`
	IPs        []string `json:"ips,omitempty"` //omitempty means if there are none in this field won't be included in the JSON output.
	Active     bool     `json:"active"`
	TimeMs     int64    `json:"time_ms"`
	Error      string   `json:"error,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
}

type SSLCert struct {
	Issuer     string `json:"issuer"`
	Expiration string `json:"expiration"`
	Valid      bool   `json:"valid"`
}

type GeoLocation struct {
	Country  string `json:"country"`
	City     string `json:"city,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type ScanResult struct {
	Domain     string            `json:"domain"`
	TimeStamp  string            `json:"time_stamp"`
	Duration   float64           `json:"duration_seconds"`
	Results    []SubdomainResult `json:"subdomains"`
	TotalFound int               `json:"total_found"`
	Active     int               `json:"active_count"`
}

// ScanOptions defines options for subdomain scanning
type ScanOptions struct {
	WordlistPath string // Path to wordlist file
	Threads      int    // Number of concurrent goroutines
	CheckHTTP    bool   // Whether to check HTTP status
	CheckSSL     bool   // Whether to check SSL certificates
	Timeout      int    // Timeout in seconds for each check
	ResolveIPs   bool   // Whether to resolve IPs
}

// ScanSubdomains performs subdomain enumeration for a target domain
func ScanSubdomains(domain string, options ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	// Validate the domain
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("empty domain name provided")
	}

	// Check if wordlist exists
	if options.WordlistPath == "" {
		return nil, fmt.Errorf("wordlist path is required")
	}

	if _, err := os.Stat(options.WordlistPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist not found at %s", options.WordlistPath)
	}

	// Set defaults for other options
	if options.Threads < 1 {
		options.Threads = 20
	}
	if options.Timeout < 1 {
		options.Timeout = 5
	}

	// Initialize result
	result := &ScanResult{
		Domain:    domain,
		TimeStamp: time.Now().Format("2006-01-02_15-04-05"),
		Results:   []SubdomainResult{},
	}

	// Load wordlist
	words, err := loadWordlist(options.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	fmt.Printf("Loaded %d subdomain names from %s\n", len(words), options.WordlistPath)

	// Setup concurrency with channels
	wordChan := make(chan string, len(words))
	resultChan := make(chan SubdomainResult, len(words))

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordChan {
				checkSubdomain(word, domain, options, resultChan)
			}
		}()
	}

	// Feed words to workers
	for _, word := range words {
		wordChan <- word
	}
	close(wordChan)

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	fmt.Println("Scanning subdomains (each dot represents 10 checks)...")

	count := 0
	for subResult := range resultChan {
		result.Results = append(result.Results, subResult)

		if subResult.Active {
			result.Active++
		}

		count++
		if count%10 == 0 {
			fmt.Print(".")
		}
		if count%500 == 0 {
			fmt.Printf(" %d/%d\n", count, len(words))
		}
	}

	// Finalize results
	result.TotalFound = len(result.Results)
	result.Duration = time.Since(startTime).Seconds()

	// Save results to file
	if err := saveResults(result); err != nil {
		fmt.Printf("Warning: Failed to save results: %v\n", err)
	}

	fmt.Printf("\nCompleted %d subdomain checks in %.2f seconds\n", len(words), result.Duration)
	fmt.Printf("Found %d active subdomains\n", result.Active)

	return result, nil
}

// checkSubdomain checks if a subdomain exists and gathers information about it
func checkSubdomain(word, domain string, options ScanOptions, resultChan chan<- SubdomainResult) {
	startTime := time.Now()
	fullDomain := fmt.Sprintf("%s.%s", word, domain)

	// Initialize result
	result := SubdomainResult{
		Name:   fullDomain,
		Active: false,
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(options.Timeout)*time.Second)
	defer cancel()

	// Try to resolve
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip", fullDomain)

	if err == nil && len(ips) > 0 {
		result.Active = true

		// Store IPs if requested
		if options.ResolveIPs {
			for _, ip := range ips {
				result.IPs = append(result.IPs, ip.String())
			}
		}

		// Check HTTP status if requested
		if options.CheckHTTP {
			status, err := checkHTTPStatus(fullDomain, options.Timeout)
			if err == nil && status > 0 {
				result.HTTPStatus = status
			}
		}

		// Check SSL if requested - NOT IMPLEMENTED
		// SSL checking requires the crypto/tls package and implementing a checkSSL function
		// We're keeping the ScanOptions.CheckSSL field for future implementation
	} else if err != nil {
		// Store error message, but truncate if too long
		errMsg := err.Error()
		if len(errMsg) > 100 {
			errMsg = errMsg[:97] + "..."
		}
		result.Error = errMsg
	}

	result.TimeMs = time.Since(startTime).Milliseconds()
	resultChan <- result
}

// checkHTTPStatus checks HTTP status of a domain
func checkHTTPStatus(domain string, timeout int) (int, error) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first
	resp, err := client.Get(fmt.Sprintf("https://%s", domain))
	if err == nil {
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	// Fall back to HTTP
	resp, err = client.Get(fmt.Sprintf("http://%s", domain))
	if err == nil {
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	return 0, err
}

// loadWordlist loads a wordlist file
func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}

// saveResults saves the scan results to a JSON file
func saveResults(result *ScanResult) error {
	// Create logs directory
	os.MkdirAll("logs", 0755)

	// Create filename
	filename := filepath.Join("logs", fmt.Sprintf("subdomains_%s_%s.json",
		result.Domain, result.TimeStamp))

	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}

	fmt.Printf("\nResults saved to %s\n", filename)
	return nil
}

// PrintResults displays scan results in a user-friendly format
func PrintResults(result *ScanResult) {
	fmt.Println("\n=================================================")
	fmt.Printf("SUBDOMAIN SCAN RESULTS FOR: %s\n", result.Domain)
	fmt.Println("=================================================")
	fmt.Printf("Scan Time: %s\n", result.TimeStamp)
	fmt.Printf("Duration: %.2f seconds\n", result.Duration)
	fmt.Printf("Total Subdomains Found: %d/%d\n", result.Active, result.TotalFound)

	if result.Active > 0 {
		fmt.Println("\nActive Subdomains:")
		fmt.Println("-----------------")

		for _, sub := range result.Results {
			if sub.Active {
				fmt.Printf("- %s\n", sub.Name)

				if len(sub.IPs) > 0 {
					fmt.Printf("  IPs: %s\n", strings.Join(sub.IPs, ", "))
				}

				if sub.HTTPStatus > 0 {
					fmt.Printf("  HTTP Status: %d\n", sub.HTTPStatus)
				}
			}
		}
	} else {
		fmt.Println("\nNo active subdomains found.")
	}

	fmt.Println("=================================================")
}
