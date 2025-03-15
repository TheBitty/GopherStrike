// pkg/tools/discovery/dirbruteforce/dirbruteforce.go
package dirbruteforce

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StatusCodeInfo represents information about a status code
type StatusCodeInfo struct {
	Code        int
	Description string
	Category    string // success, redirect, clientError, serverError
}

// PathResult represents the result of a path check
type PathResult struct {
	Path          string
	URL           string
	StatusCode    int
	ContentType   string
	ContentLength int64
	ResponseTime  time.Duration
	Interesting   bool
}

// BruteforceOptions contains options for directory bruteforcing
type BruteforceOptions struct {
	Extensions      []string
	WordlistPath    string
	Threads         int
	Timeout         int
	FollowRedirects bool
	StatusCodes     []int // Status codes to consider "found"
	OutputFile      string
	UserAgent       string
	ExcludeLength   []int64 // Content lengths to exclude (to avoid false positives)
	Recursive       bool
	MaxDepth        int
	WaitTime        int // Time to wait between requests in milliseconds
	Cookies         []string
	Headers         map[string]string
}

// DefaultBruteforceOptions returns the default options
func DefaultBruteforceOptions() BruteforceOptions {
	return BruteforceOptions{
		Extensions:      []string{"", ".html", ".php", ".js", ".txt"},
		WordlistPath:    "wordlists/directories-common.txt", // Default wordlist
		Threads:         10,
		Timeout:         10,
		FollowRedirects: true,
		StatusCodes:     []int{200, 201, 202, 203, 204, 301, 302, 307, 401, 403},
		OutputFile:      "logs/discovery/directories.txt",
		UserAgent:       "GopherStrike DirBruteForce/1.0",
		ExcludeLength:   []int64{},
		Recursive:       false,
		MaxDepth:        3,
		WaitTime:        0,
		Cookies:         []string{},
		Headers:         map[string]string{},
	}
}

// DirScanner represents a directory scanner
type DirScanner struct {
	options     BruteforceOptions
	results     []PathResult
	client      *http.Client
	wordlist    []string
	statusCodes map[int]StatusCodeInfo
	mutex       sync.Mutex
}

// NewDirScanner creates a new directory scanner
func NewDirScanner(options BruteforceOptions) (*DirScanner, error) {
	// Configure HTTP client
	httpClient := &http.Client{
		Timeout: time.Duration(options.Timeout) * time.Second,
	}

	// Configure redirect policy
	if !options.FollowRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Load wordlist
	wordlist, err := loadWordlist(options.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %v", err)
	}

	// Initialize status code information
	statusCodes := initStatusCodes()

	return &DirScanner{
		options:     options,
		client:      httpClient,
		wordlist:    wordlist,
		results:     []PathResult{},
		statusCodes: statusCodes,
		mutex:       sync.Mutex{},
	}, nil
}

// loadWordlist loads a wordlist from a file
func loadWordlist(path string) ([]string, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Try relative paths if not found
		altPaths := []string{
			filepath.Join("wordlists", filepath.Base(path)),
			filepath.Join("..", "wordlists", filepath.Base(path)),
			filepath.Join("..", "..", "wordlists", filepath.Base(path)),
		}

		for _, altPath := range altPaths {
			if _, err := os.Stat(altPath); err == nil {
				path = altPath
				break
			}
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// initStatusCodes initializes status code information
func initStatusCodes() map[int]StatusCodeInfo {
	statusCodes := map[int]StatusCodeInfo{
		200: {200, "OK", "success"},
		201: {201, "Created", "success"},
		204: {204, "No Content", "success"},
		301: {301, "Moved Permanently", "redirect"},
		302: {302, "Found", "redirect"},
		307: {307, "Temporary Redirect", "redirect"},
		400: {400, "Bad Request", "clientError"},
		401: {401, "Unauthorized", "clientError"},
		403: {403, "Forbidden", "clientError"},
		404: {404, "Not Found", "clientError"},
		405: {405, "Method Not Allowed", "clientError"},
		500: {500, "Internal Server Error", "serverError"},
		501: {501, "Not Implemented", "serverError"},
		502: {502, "Bad Gateway", "serverError"},
		503: {503, "Service Unavailable", "serverError"},
	}
	return statusCodes
}

// Scan performs directory bruteforcing on a target URL
func (d *DirScanner) Scan(baseURL string) ([]PathResult, error) {
	// Normalize base URL
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	// Clear previous results
	d.results = []PathResult{}

	fmt.Printf("[+] Starting directory bruteforce on: %s\n", baseURL)
	fmt.Printf("[+] Using wordlist: %s (%d words)\n", d.options.WordlistPath, len(d.wordlist))
	fmt.Printf("[+] Using %d threads and %d extensions\n", d.options.Threads, len(d.options.Extensions))

	// Create a context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Generate the paths to check
	paths := d.generatePaths()
	fmt.Printf("[+] Generated %d paths to check\n", len(paths))

	// Create a channel for paths
	pathCh := make(chan string, len(paths))
	for _, path := range paths {
		pathCh <- path
	}
	close(pathCh)

	// Create a wait group for goroutines
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < d.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathCh {
				select {
				case <-ctx.Done():
					return
				default:
					// Check for rate limiting
					if d.options.WaitTime > 0 {
						time.Sleep(time.Duration(d.options.WaitTime) * time.Millisecond)
					}

					// Check the path
					result := d.checkPath(baseURL, path)
					if d.isInterestingResult(result) {
						d.addResult(result)

						// Print the result
						statusInfo, found := d.statusCodes[result.StatusCode]
						statusCategory := "unknown"
						if found {
							statusCategory = statusInfo.Category
						}

						// Format the output based on the status category
						var statusOutput string
						switch statusCategory {
						case "success":
							statusOutput = fmt.Sprintf("\033[32m%d\033[0m", result.StatusCode) // Green
						case "redirect":
							statusOutput = fmt.Sprintf("\033[33m%d\033[0m", result.StatusCode) // Yellow
						case "clientError":
							if result.StatusCode == 403 {
								statusOutput = fmt.Sprintf("\033[35m%d\033[0m", result.StatusCode) // Purple for 403
							} else {
								statusOutput = fmt.Sprintf("\033[31m%d\033[0m", result.StatusCode) // Red
							}
						case "serverError":
							statusOutput = fmt.Sprintf("\033[31;1m%d\033[0m", result.StatusCode) // Bright Red
						default:
							statusOutput = fmt.Sprintf("%d", result.StatusCode)
						}

						fmt.Printf("[%s] %-50s %9d bytes   %6dms\n",
							statusOutput,
							result.Path,
							result.ContentLength,
							result.ResponseTime.Milliseconds())
					}
				}
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Save results
	if d.options.OutputFile != "" {
		err := d.saveResults()
		if err != nil {
			fmt.Printf("[!] Error saving results: %v\n", err)
		}
	}

	return d.results, nil
}

// generatePaths generates paths to check
func (d *DirScanner) generatePaths() []string {
	var paths []string

	for _, word := range d.wordlist {
		// Skip comments and empty lines
		if strings.HasPrefix(word, "#") || word == "" {
			continue
		}

		// Add the word with each extension
		for _, ext := range d.options.Extensions {
			// Handle special case where extension is empty
			if ext == "" {
				paths = append(paths, word)
				continue
			}

			// If the word already has an extension that matches one of our extensions, don't add another
			if hasExtension(word, d.options.Extensions) {
				paths = append(paths, word)
				continue
			}

			// Add extension (ensure it starts with a dot)
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}

			paths = append(paths, word+ext)
		}
	}

	return paths
}

// hasExtension checks if a word already has one of the target extensions
func hasExtension(word string, extensions []string) bool {
	for _, ext := range extensions {
		if ext == "" {
			continue
		}

		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}

		if strings.HasSuffix(word, ext) {
			return true
		}
	}
	return false
}

// checkPath checks a single path and returns the result
func (d *DirScanner) checkPath(baseURL, path string) PathResult {
	url := baseURL + path
	result := PathResult{
		Path: path,
		URL:  url,
	}

	// Create a request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", d.options.UserAgent)
	for key, value := range d.options.Headers {
		req.Header.Set(key, value)
	}

	// Set cookies
	for _, cookie := range d.options.Cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			req.AddCookie(&http.Cookie{
				Name:  parts[0],
				Value: parts[1],
			})
		}
	}

	// Send the request and time it
	startTime := time.Now()
	resp, err := d.client.Do(req)
	responseTime := time.Since(startTime)
	result.ResponseTime = responseTime

	if err != nil {
		return result
	}
	defer resp.Body.Close()

	// Parse the response
	result.StatusCode = resp.StatusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength

	return result
}

// isInterestingResult determines if a result is interesting and should be kept
func (d *DirScanner) isInterestingResult(result PathResult) bool {
	// Check if status code is in the list of "found" codes
	found := false
	for _, code := range d.options.StatusCodes {
		if result.StatusCode == code {
			found = true
			break
		}
	}

	if !found {
		return false
	}

	// Check if content length is in the exclude list
	for _, length := range d.options.ExcludeLength {
		if result.ContentLength == length {
			return false
		}
	}

	return true
}

// addResult adds a result to the results slice
func (d *DirScanner) addResult(result PathResult) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.results = append(d.results, result)
}

// saveResults saves the scan results to a file
func (d *DirScanner) saveResults() error {
	// Create directory if it doesn't exist
	dir := d.options.OutputFile[:strings.LastIndex(d.options.OutputFile, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create output file
	file, err := os.Create(d.options.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	file.WriteString("# Directory Bruteforce Results\n")
	file.WriteString("# Generated by GopherStrike DirBruteForce\n")
	file.WriteString("# " + time.Now().Format(time.RFC3339) + "\n\n")

	// Write results
	file.WriteString("STATUS  PATH                                               SIZE           TIME\n")
	file.WriteString("------  ------------------------------------------------  -------------  ------\n")

	for _, result := range d.results {
		file.WriteString(fmt.Sprintf("%-6d  %-48s  %-13d  %dms\n",
			result.StatusCode,
			result.Path,
			result.ContentLength,
			result.ResponseTime.Milliseconds()))
	}

	fmt.Printf("[+] Results saved to: %s\n", d.options.OutputFile)
	return nil
}

// RunDirBruteforce is the main entry point for the directory bruteforcing tool
func RunDirBruteforce() error {
	fmt.Println("\n[+] Directory Bruteforcing Tool")
	fmt.Println("    ========================")

	// Get target URL
	fmt.Print("[?] Enter target URL (e.g., https://example.com): ")
	var targetURL string
	fmt.Scanln(&targetURL)

	if targetURL == "" {
		return fmt.Errorf("target URL is required")
	}

	// Ensure URL has proper scheme
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	// Configure options
	options := DefaultBruteforceOptions()

	// Ask for wordlist
	fmt.Printf("[?] Enter wordlist path (default: %s): ", options.WordlistPath)
	var wordlistPath string
	fmt.Scanln(&wordlistPath)
	if wordlistPath != "" {
		options.WordlistPath = wordlistPath
	}

	// Ask for extensions
	fmt.Printf("[?] Enter file extensions to check (comma-separated, default: %s): ", strings.Join(options.Extensions, ","))
	var extensionsInput string
	fmt.Scanln(&extensionsInput)
	if extensionsInput != "" {
		options.Extensions = strings.Split(extensionsInput, ",")
		// Trim spaces
		for i, ext := range options.Extensions {
			options.Extensions[i] = strings.TrimSpace(ext)
		}
	}

	// Ask for threads
	fmt.Printf("[?] Enter number of threads (default: %d): ", options.Threads)
	var threads string
	fmt.Scanln(&threads)
	if threads != "" {
		threadsInt, err := strconv.Atoi(threads)
		if err == nil && threadsInt > 0 {
			options.Threads = threadsInt
		}
	}

	// Ask for output file
	fmt.Printf("[?] Save results to file? (default: %s, leave empty for no file): ", options.OutputFile)
	var outputFile string
	fmt.Scanln(&outputFile)
	options.OutputFile = outputFile

	// Create scanner and run scan
	scanner, err := NewDirScanner(options)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	results, err := scanner.Scan(targetURL)
	if err != nil {
		return err
	}

	// Print results summary
	fmt.Printf("\n[+] Scan completed. Found %d interesting paths.\n", len(results))

	// Group results by status code
	statusGroups := make(map[int][]PathResult)
	for _, result := range results {
		statusGroups[result.StatusCode] = append(statusGroups[result.StatusCode], result)
	}

	// Print results by status group
	for statusCode, group := range statusGroups {
		statusInfo := scanner.statusCodes[statusCode]
		var statusCategory string
		if statusInfo.Category != "" {
			statusCategory = statusInfo.Category
		} else {
			statusCategory = "Unknown"
		}

		fmt.Printf("\n=== %s (%d) ===\n", statusCategory, statusCode)
		for _, result := range group {
			fmt.Printf("%-50s [Size: %d]\n", result.Path, result.ContentLength)
		}
	}

	if options.OutputFile != "" {
		fmt.Printf("\n[+] Results saved to: %s\n", options.OutputFile)
	}

	return nil
}
