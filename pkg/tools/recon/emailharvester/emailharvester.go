// pkg/tools/recon/emailharvester/emailharvester.go
package emailharvester

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EmailSource represents a source where an email was found
type EmailSource struct {
	URL  string
	Type string // webpage, api, etc.
}

// EmailResult represents a found email address and its sources
type EmailResult struct {
	Email   string
	Sources []EmailSource
}

// HarvesterOptions contains options for the email harvester
type HarvesterOptions struct {
	MaxDepth          int
	FollowLinks       bool
	Timeout           int
	OutputFile        string
	ExcludedDomains   []string
	IncludeSubdomains bool
	MaxPages          int
	SearchEngines     bool
}

// DefaultHarvesterOptions returns the default harvester options
func DefaultHarvesterOptions() HarvesterOptions {
	return HarvesterOptions{
		MaxDepth:    2,
		FollowLinks: true,
		Timeout:     10,
		OutputFile:  "logs/recon/emails.txt",
		ExcludedDomains: []string{
			"facebook.com", "twitter.com", "linkedin.com",
			"instagram.com", "youtube.com", "google.com",
		},
		IncludeSubdomains: true,
		MaxPages:          100,
		SearchEngines:     true,
	}
}

// EmailHarvester represents an email harvester
type EmailHarvester struct {
	options     HarvesterOptions
	results     map[string]EmailResult // Using map to deduplicate emails
	visitedURLs map[string]bool
	client      *http.Client
	mutex       sync.Mutex
	domain      string
}

// NewEmailHarvester creates a new email harvester
func NewEmailHarvester(options HarvesterOptions) *EmailHarvester {
	client := &http.Client{
		Timeout: time.Duration(options.Timeout) * time.Second,
	}

	return &EmailHarvester{
		options:     options,
		results:     make(map[string]EmailResult),
		visitedURLs: make(map[string]bool),
		client:      client,
		mutex:       sync.Mutex{},
	}
}

// Harvest starts the email harvesting process for a domain
func (h *EmailHarvester) Harvest(domain string) ([]EmailResult, error) {
	h.domain = domain
	h.results = make(map[string]EmailResult)
	h.visitedURLs = make(map[string]bool)

	fmt.Printf("[+] Starting email harvesting for domain: %s\n", domain)

	// Starting points for harvesting
	startingURLs := []string{
		fmt.Sprintf("https://%s", domain),
		fmt.Sprintf("https://www.%s", domain),
	}

	// Add search engine queries if enabled
	if h.options.SearchEngines {
		searchEngineURLs := h.generateSearchEngineURLs(domain)
		startingURLs = append(startingURLs, searchEngineURLs...)
	}

	// Process starting URLs
	var wg sync.WaitGroup
	for _, url := range startingURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			h.processURL(u, 0)
		}(url)
	}

	wg.Wait()

	// Convert results map to slice
	resultSlice := make([]EmailResult, 0, len(h.results))
	for _, result := range h.results {
		resultSlice = append(resultSlice, result)
	}

	// Save results
	if h.options.OutputFile != "" {
		err := h.saveResults(resultSlice)
		if err != nil {
			fmt.Printf("[!] Error saving results: %v\n", err)
		}
	}

	return resultSlice, nil
}

// processURL processes a URL to extract emails and follow links
func (h *EmailHarvester) processURL(url string, depth int) {
	// Check if we've already visited this URL
	h.mutex.Lock()
	if h.visitedURLs[url] {
		h.mutex.Unlock()
		return
	}

	// Mark as visited
	h.visitedURLs[url] = true

	// Check if we've reached the maximum number of pages
	if len(h.visitedURLs) >= h.options.MaxPages {
		h.mutex.Unlock()
		return
	}
	h.mutex.Unlock()

	// Skip excluded domains
	for _, excludedDomain := range h.options.ExcludedDomains {
		if strings.Contains(url, excludedDomain) {
			return
		}
	}

	// Get the page content
	resp, err := h.client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	// Extract emails
	emails := h.extractEmails(string(body))
	source := EmailSource{
		URL:  url,
		Type: "webpage",
	}

	// Add emails to results
	for _, email := range emails {
		// Only include emails that belong to the target domain or subdomains
		if h.shouldIncludeEmail(email) {
			h.addEmailResult(email, source)
		}
	}

	// Follow links if enabled and not at max depth
	if h.options.FollowLinks && depth < h.options.MaxDepth {
		links := h.extractLinks(string(body), url)

		var wg sync.WaitGroup
		for _, link := range links {
			wg.Add(1)
			go func(l string) {
				defer wg.Done()
				// Add a small delay to avoid overwhelming the server
				time.Sleep(200 * time.Millisecond)
				h.processURL(l, depth+1)
			}(link)
		}
		wg.Wait()
	}
}

// shouldIncludeEmail checks if an email should be included in results
func (h *EmailHarvester) shouldIncludeEmail(email string) bool {
	// Extract domain part from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	emailDomain := parts[1]

	// Always include exact domain match
	if emailDomain == h.domain {
		return true
	}

	// Include subdomains if option is enabled
	if h.options.IncludeSubdomains && strings.HasSuffix(emailDomain, "."+h.domain) {
		return true
	}

	return false
}

// extractEmails extracts email addresses from text
func (h *EmailHarvester) extractEmails(text string) []string {
	// Email regex pattern
	pattern := `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
	re := regexp.MustCompile(pattern)

	// Find all matches
	matches := re.FindAllString(text, -1)

	// Deduplicate
	emailMap := make(map[string]bool)
	for _, email := range matches {
		emailMap[strings.ToLower(email)] = true
	}

	// Convert back to slice
	uniqueEmails := make([]string, 0, len(emailMap))
	for email := range emailMap {
		uniqueEmails = append(uniqueEmails, email)
	}

	return uniqueEmails
}

// extractLinks extracts links from HTML
func (h *EmailHarvester) extractLinks(html, baseURL string) []string {
	// Link regex pattern - simple version, a real implementation would use an HTML parser
	pattern := `href=["']([^"']+)["']`
	re := regexp.MustCompile(pattern)

	// Find all matches
	matches := re.FindAllStringSubmatch(html, -1)

	// Process and filter links
	links := make([]string, 0)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		link := match[1]

		// Handle relative URLs
		if !strings.HasPrefix(link, "http") {
			if strings.HasPrefix(link, "/") {
				// Absolute path
				parts := strings.Split(baseURL, "//")
				if len(parts) > 1 {
					domain := strings.Split(parts[1], "/")[0]
					link = fmt.Sprintf("%s//%s%s", parts[0], domain, link)
				}
			} else {
				// Relative path
				if !strings.HasSuffix(baseURL, "/") {
					baseURL += "/"
				}
				link = baseURL + link
			}
		}

		// Only include links to the same domain or subdomains
		if h.isDomainRelevant(link) {
			links = append(links, link)
		}
	}

	return links
}

// isDomainRelevant checks if a URL belongs to the target domain or subdomains
func (h *EmailHarvester) isDomainRelevant(url string) bool {
	// Extract domain from URL
	parts := strings.Split(url, "//")
	if len(parts) < 2 {
		return false
	}

	domainPart := strings.Split(parts[1], "/")[0]

	// Check if it's the target domain
	if domainPart == h.domain || domainPart == "www."+h.domain {
		return true
	}

	// Check if it's a subdomain
	if h.options.IncludeSubdomains && strings.HasSuffix(domainPart, "."+h.domain) {
		return true
	}

	return false
}

// generateSearchEngineURLs creates URLs for search engine queries
func (h *EmailHarvester) generateSearchEngineURLs(domain string) []string {
	urls := []string{}

	// Google search (note: this is simplified and might not work due to Google's anti-scraping measures)
	googleQuery := fmt.Sprintf("https://www.google.com/search?q=%%22%s%%22+email+OR+contact+OR+%%22@%s%%22",
		domain, domain)
	urls = append(urls, googleQuery)

	// Bing search
	bingQuery := fmt.Sprintf("https://www.bing.com/search?q=%%22%s%%22+email+OR+contact+OR+%%22@%s%%22",
		domain, domain)
	urls = append(urls, bingQuery)

	return urls
}

// addEmailResult adds an email to the results
func (h *EmailHarvester) addEmailResult(email string, source EmailSource) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	email = strings.ToLower(email)

	if result, exists := h.results[email]; exists {
		// Check if source already exists
		sourceExists := false
		for _, s := range result.Sources {
			if s.URL == source.URL {
				sourceExists = true
				break
			}
		}

		if !sourceExists {
			result.Sources = append(result.Sources, source)
			h.results[email] = result
		}
	} else {
		// Create new result
		h.results[email] = EmailResult{
			Email:   email,
			Sources: []EmailSource{source},
		}
		fmt.Printf("[+] Found email: %s\n", email)
	}
}

// saveResults saves the harvested emails to a file
func (h *EmailHarvester) saveResults(results []EmailResult) error {
	// Create directory if it doesn't exist
	dir := h.options.OutputFile[:strings.LastIndex(h.options.OutputFile, "/")]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create output file
	file, err := os.Create(h.options.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	file.WriteString("# Email Harvesting Results\n")
	file.WriteString(fmt.Sprintf("# Domain: %s\n", h.domain))
	file.WriteString("# Generated by GopherStrike EmailHarvester\n")
	file.WriteString("# " + time.Now().Format(time.RFC3339) + "\n\n")

	// Write results
	for _, result := range results {
		file.WriteString(fmt.Sprintf("%s\n", result.Email))
		file.WriteString("  Sources:\n")

		for _, source := range result.Sources {
			file.WriteString(fmt.Sprintf("  - %s (%s)\n", source.URL, source.Type))
		}

		file.WriteString("\n")
	}

	fmt.Printf("[+] Results saved to: %s\n", h.options.OutputFile)
	return nil
}

// RunEmailHarvester is the main entry point for the email harvester
func RunEmailHarvester() error {
	fmt.Println("\n[+] Email Harvester")
	fmt.Println("    ==============")

	// Get target domain
	fmt.Print("[?] Enter target domain (e.g., example.com): ")
	var domain string
	fmt.Scanln(&domain)

	if domain == "" {
		return fmt.Errorf("target domain is required")
	}

	// Configure options
	options := DefaultHarvesterOptions()

	// Configure max depth
	fmt.Print("[?] Maximum crawl depth (default: 2): ")
	var depthStr string
	fmt.Scanln(&depthStr)

	if depthStr != "" {
		if depth, err := strconv.Atoi(depthStr); err == nil && depth > 0 {
			options.MaxDepth = depth
		}
	}

	// Configure subdomain inclusion
	fmt.Print("[?] Include subdomains? (Y/n): ")
	var includeSubdomains string
	fmt.Scanln(&includeSubdomains)

	if strings.ToLower(includeSubdomains) == "n" {
		options.IncludeSubdomains = false
	}

	// Configure search engines
	fmt.Print("[?] Use search engines for discovery? (Y/n): ")
	var useSearchEngines string
	fmt.Scanln(&useSearchEngines)

	if strings.ToLower(useSearchEngines) == "n" {
		options.SearchEngines = false
	}

	// Create and run harvester
	harvester := NewEmailHarvester(options)
	results, err := harvester.Harvest(domain)

	if err != nil {
		return err
	}

	// Print summary
	fmt.Printf("\n[+] Harvesting complete! Found %d email addresses\n", len(results))

	if options.OutputFile != "" {
		fmt.Printf("[+] Results saved to: %s\n", options.OutputFile)
	}

	return nil
}
