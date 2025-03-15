// pkg/tools/recon/s3scanner/s3scanner.go
package s3scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// S3BucketResult represents the result of an S3 bucket scan
type S3BucketResult struct {
	Bucket         string
	URL            string
	Accessible     bool
	Public         bool
	ListingEnabled bool
	Objects        []string
	Error          string
}

// S3ScanOptions contains options for the S3 scanner
type S3ScanOptions struct {
	Threads      int
	Timeout      int
	CheckListing bool
	OutputFile   string
	Verbose      bool
	WaitTime     int // Time to wait between requests in milliseconds
	WordlistPath string
}

// DefaultS3ScanOptions returns the default scan options
func DefaultS3ScanOptions() S3ScanOptions {
	return S3ScanOptions{
		Threads:      10,
		Timeout:      5,
		CheckListing: true,
		OutputFile:   "logs/recon/s3buckets.txt",
		Verbose:      true,
		WaitTime:     100,
		WordlistPath: "", // Will be set based on user choice
	}
}

// Scanner represents an S3 bucket scanner
type Scanner struct {
	options S3ScanOptions
	results []S3BucketResult
	client  *http.Client
	mutex   sync.Mutex
}

// NewScanner creates a new S3 bucket scanner
func NewScanner(options S3ScanOptions) *Scanner {
	client := &http.Client{
		Timeout: time.Duration(options.Timeout) * time.Second,
		// Skip SSL verification to catch misconfigured buckets
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return &Scanner{
		options: options,
		results: []S3BucketResult{},
		client:  client,
		mutex:   sync.Mutex{},
	}
}

// ScanTarget scans a specific domain for S3 buckets
func (s *Scanner) ScanTarget(target string) ([]S3BucketResult, error) {
	s.results = []S3BucketResult{}

	// Generate bucket names based on target domain
	bucketNames, err := s.generateBucketNames(target)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[+] Starting S3 bucket scan for: %s\n", target)
	fmt.Printf("[+] Generated %d potential bucket names\n", len(bucketNames))

	// Channel for bucket names
	bucketCh := make(chan string, len(bucketNames))
	for _, bucket := range bucketNames {
		bucketCh <- bucket
	}
	close(bucketCh)

	// Wait group for goroutines
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < s.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bucketName := range bucketCh {
				// Check for rate limiting
				if s.options.WaitTime > 0 {
					time.Sleep(time.Duration(s.options.WaitTime) * time.Millisecond)
				}

				result := s.checkBucket(bucketName)
				if result.Accessible {
					s.addResult(result)

					if s.options.Verbose {
						accessInfo := "Private"
						if result.Public {
							accessInfo = "PUBLIC"
						}

						listingInfo := ""
						if result.ListingEnabled {
							listingInfo = " (Directory listing enabled!)"
						}

						fmt.Printf("[+] Found bucket: %s - %s%s\n", result.Bucket, accessInfo, listingInfo)
					}
				}
			}
		}()
	}

	// Wait for completion
	wg.Wait()

	// Save results
	if s.options.OutputFile != "" {
		err = s.saveResults()
		if err != nil {
			fmt.Printf("[!] Error saving results: %v\n", err)
		}
	}

	return s.results, nil
}

// generateBucketNames creates a list of potential bucket names
func (s *Scanner) generateBucketNames(target string) ([]string, error) {
	buckets := []string{}

	// Clean the target (remove http/https, www, etc.)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "www.")

	// Common patterns for bucket names
	patterns := []string{
		"%s",
		"%s-backup",
		"%s-bak",
		"%s-dev",
		"%s-development",
		"%s-staging",
		"%s-prod",
		"%s-production",
		"%s-test",
		"%s-testing",
		"%s-data",
		"%s-assets",
		"%s-media",
		"%s-static",
		"%s-content",
		"%s-uploads",
		"%s-files",
		"%s-archive",
		"%s-internal",
		"%s-public",
		"%s-private",
		"backup-%s",
		"bak-%s",
		"dev-%s",
		"development-%s",
		"staging-%s",
		"prod-%s",
		"production-%s",
		"test-%s",
		"testing-%s",
		"data-%s",
		"assets-%s",
		"media-%s",
		"static-%s",
		"content-%s",
		"uploads-%s",
		"files-%s",
	}

	// Add basic patterns
	for _, pattern := range patterns {
		buckets = append(buckets, fmt.Sprintf(pattern, target))

		// Add variations with domain parts
		parts := strings.Split(target, ".")
		if len(parts) > 1 {
			companyName := parts[0]
			buckets = append(buckets, fmt.Sprintf(pattern, companyName))
		}
	}

	// Add custom wordlist if provided
	if s.options.WordlistPath != "" {
		customNames, err := s.loadWordlist(target)
		if err == nil {
			buckets = append(buckets, customNames...)
		}
	}

	return buckets, nil
}

// loadWordlist loads a custom wordlist and formats with the target
func (s *Scanner) loadWordlist(target string) ([]string, error) {
	file, err := os.Open(s.options.WordlistPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buckets := []string{}

	for scanner.Scan() {
		pattern := scanner.Text()
		if strings.Contains(pattern, "%s") {
			buckets = append(buckets, fmt.Sprintf(pattern, target))
		} else {
			// If no format specifier, append as-is (might be a common name)
			buckets = append(buckets, pattern)
		}
	}

	return buckets, scanner.Err()
}

// checkBucket checks if an S3 bucket exists and is accessible
func (s *Scanner) checkBucket(bucketName string) S3BucketResult {
	result := S3BucketResult{
		Bucket: bucketName,
		URL:    fmt.Sprintf("https://%s.s3.amazonaws.com", bucketName),
	}

	// Check if bucket exists
	resp, err := s.client.Get(result.URL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	// Bucket exists and is accessible
	result.Accessible = resp.StatusCode != 404

	// Check if bucket allows public access
	result.Public = resp.StatusCode == 200

	// Check for directory listing if enabled
	if result.Public && s.options.CheckListing {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyContent := string(bodyBytes)

			// Check for XML listing format
			result.ListingEnabled = strings.Contains(bodyContent, "<ListBucketResult") ||
				strings.Contains(bodyContent, "<Contents>")

			// Extract object keys if listing is enabled
			if result.ListingEnabled {
				result.Objects = extractObjectKeys(bodyContent)
			}
		}
	}

	return result
}

// extractObjectKeys extracts S3 object keys from XML response
func extractObjectKeys(xmlContent string) []string {
	// Basic extraction using string operations
	// A full implementation would use XML parsing, but this simplified version works for demo purposes
	keys := []string{}
	keyStart := "<Key>"
	keyEnd := "</Key>"

	startIndex := 0
	for {
		start := strings.Index(xmlContent[startIndex:], keyStart)
		if start == -1 {
			break
		}
		start += startIndex + len(keyStart)

		end := strings.Index(xmlContent[start:], keyEnd)
		if end == -1 {
			break
		}
		end += start

		if end > start {
			key := xmlContent[start:end]
			keys = append(keys, key)
		}

		startIndex = end + len(keyEnd)
	}

	return keys
}

// addResult adds a result to the results slice
func (s *Scanner) addResult(result S3BucketResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.results = append(s.results, result)
}

// saveResults saves the scan results to a file
func (s *Scanner) saveResults() error {
	// Create directory if it doesn't exist
	dir := s.options.OutputFile[:strings.LastIndex(s.options.OutputFile, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create output file
	file, err := os.Create(s.options.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	file.WriteString("# S3 Bucket Scan Results\n")
	file.WriteString("# Generated by GopherStrike S3Scanner\n")
	file.WriteString("# " + time.Now().Format(time.RFC3339) + "\n\n")

	// Write results
	for _, result := range s.results {
		accessInfo := "Private"
		if result.Public {
			accessInfo = "PUBLIC"
		}

		listingInfo := ""
		if result.ListingEnabled {
			listingInfo = " (Directory listing enabled)"
		}

		file.WriteString(fmt.Sprintf("%s - %s%s\n", result.URL, accessInfo, listingInfo))

		// Write object keys if available
		if len(result.Objects) > 0 {
			file.WriteString("  Objects:\n")
			for _, obj := range result.Objects {
				file.WriteString(fmt.Sprintf("  - %s\n", obj))
			}
			file.WriteString("\n")
		}
	}

	fmt.Printf("[+] Results saved to: %s\n", s.options.OutputFile)
	return nil
}

// RunS3BucketScanner is the main entry point for the S3 bucket scanner
func RunS3BucketScanner() error {
	fmt.Println("\n[+] S3 Bucket Scanner")
	fmt.Println("    ================")

	// Get target domain
	fmt.Print("[?] Enter target domain (e.g., example.com): ")
	var target string
	fmt.Scanln(&target)

	if target == "" {
		return fmt.Errorf("target domain is required")
	}

	// Configure options
	options := DefaultS3ScanOptions()

	// Ask for wordlist
	fmt.Print("[?] Use custom wordlist for bucket names? (y/N): ")
	var useWordlist string
	fmt.Scanln(&useWordlist)

	if strings.ToLower(useWordlist) == "y" {
		fmt.Print("[?] Enter wordlist path: ")
		fmt.Scanln(&options.WordlistPath)
	}

	// Configure threads
	fmt.Print("[?] Number of threads (default: 10): ")
	var threadsStr string
	fmt.Scanln(&threadsStr)

	if threadsStr != "" {
		if threads, err := strconv.Atoi(threadsStr); err == nil && threads > 0 {
			options.Threads = threads
		}
	}

	// Create and run scanner
	scanner := NewScanner(options)
	results, err := scanner.ScanTarget(target)

	if err != nil {
		return err
	}

	// Print summary
	fmt.Printf("\n[+] Scan complete! Found %d accessible S3 buckets\n", len(results))

	publicCount := 0
	listingCount := 0

	for _, result := range results {
		if result.Public {
			publicCount++
		}
		if result.ListingEnabled {
			listingCount++
		}
	}

	fmt.Printf("[+] Public buckets: %d\n", publicCount)
	fmt.Printf("[+] Buckets with directory listing: %d\n", listingCount)

	if options.OutputFile != "" {
		fmt.Printf("[+] Results saved to: %s\n", options.OutputFile)
	}

	return nil
}
