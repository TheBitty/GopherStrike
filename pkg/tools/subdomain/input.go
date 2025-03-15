// pkg/subdomain/input.go
package subdomain

import (
	"GopherStrike/pkg/tools"
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// getDefaultThreadCount returns the optimal default thread count based on system resources
func getDefaultThreadCount() int {
	// Use number of CPU cores with a minimum of 4 and maximum of 20
	numCPU := runtime.NumCPU()
	if numCPU < 4 {
		return 4
	}
	if numCPU > 20 {
		return 20
	}
	return numCPU
}

// GetDomainInput gets and validates the target domain from user input
func GetDomainInput() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Enter target domain (e.g., example.com): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("error reading domain: %v", err)
		}

		// Clean the domain input
		domain := CleanDomain(input)
		if domain == "" {
			fmt.Println("Error: Invalid domain provided. Please enter a valid domain name.")
			continue
		}

		// Basic domain format validation
		if !ValidateDomainFormat(domain) {
			fmt.Println("Error: Invalid domain format. Please enter a valid domain name.")
			continue
		}

		// Check if domain exists (not mandatory, can be skipped)
		fmt.Printf("Checking if domain %s exists... ", domain)

		// Set a timeout for the validation
		domainCheckChan := make(chan bool)
		go func() {
			domainCheckChan <- ValidateDomain(domain)
		}()

		select {
		case exists := <-domainCheckChan:
			if exists {
				fmt.Printf("✓ Domain exists.\n")
			} else {
				fmt.Printf("⚠ Unable to verify domain.\n")
				fmt.Print("Continue anyway? (y/n): ")
				continueAnyway, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(continueAnyway)) != "y" {
					continue
				}
			}
		case <-time.After(3 * time.Second):
			fmt.Printf("⚠ Verification timed out.\n")
			fmt.Print("Continue anyway? (y/n): ")
			continueAnyway, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(continueAnyway)) != "y" {
				continue
			}
		}

		return domain, nil
	}
}

// GetWordlistPath gets the wordlist path from user input
func GetWordlistPath() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\nWordlist:")
	fmt.Println("=========")
	fmt.Println("You must provide your own wordlist file.")
	fmt.Println("Examples:")
	fmt.Println("- Kali Linux SecLists: /usr/share/seclists/Discovery/DNS/")
	fmt.Println("- OWASP Amass: /usr/share/amass/wordlists/")
	fmt.Println("- Custom wordlists: ~/wordlists/subdomains.txt")

	for {
		fmt.Print("\nEnter full path to wordlist: ")
		wordlistPath, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("error reading path: %v", err)
		}

		wordlistPath = strings.TrimSpace(wordlistPath)
		if wordlistPath == "" {
			fmt.Println("Error: Wordlist path cannot be empty.")
			continue
		}

		// Expand home directory if using ~
		expandedPath, err := ExpandHomeDir(wordlistPath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		wordlistPath = expandedPath

		// Check if the file exists
		if !FileExists(wordlistPath) {
			fmt.Printf("Error: Wordlist not found at: %s\n", wordlistPath)
			continue
		}

		// Check if it's a directory
		if DirectoryExists(wordlistPath) {
			fmt.Println("Error: The provided path is a directory, not a file.")
			continue
		}

		// Get file size
		fileSize, err := GetFileSize(wordlistPath)
		if err != nil {
			fmt.Printf("Error: Cannot get file size: %v\n", err)
			continue
		}
		fmt.Printf("Wordlist size: %s\n", FormatSize(fileSize))

		// Check if the file is readable and count lines
		file, err := os.Open(wordlistPath)
		if err != nil {
			fmt.Printf("Error: Cannot open wordlist file: %v\n", err)
			continue
		}

		// Count lines and check first line - efficiently
		lineCount := 0
		firstLine := ""

		// Use larger buffer for faster reading
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)

		// For larger files, we'll sample to estimate
		if fileSize > 10*1024*1024 { // > 10MB
			fmt.Println("Large wordlist detected, estimating line count...")

			// Read first 1000 lines to get an average line length
			sampleLines := 0
			for scanner.Scan() {
				if sampleLines == 0 {
					firstLine = scanner.Text()
				}
				lineCount++
				sampleLines++
				if sampleLines >= 1000 {
					break
				}
			}

			if scanner.Err() != nil {
				fmt.Printf("Warning: Error scanning file: %v\n", scanner.Err())
			}

			// If we have at least one line, estimate total
			if sampleLines > 0 {
				avgLineLength := float64(fileSize) / float64(sampleLines)
				estimatedLines := int(float64(fileSize) / avgLineLength)
				fmt.Printf("Estimated wordlist entries: ~%d (based on sampling)\n", estimatedLines)
			}
		} else {
			// For smaller files, count exact number of lines
			for scanner.Scan() {
				if lineCount == 0 {
					firstLine = scanner.Text()
				}
				lineCount++
			}

			if scanner.Err() != nil {
				fmt.Printf("Warning: Error scanning file: %v\n", scanner.Err())
			}

			fmt.Printf("Wordlist has %d entries\n", lineCount)
		}

		file.Close()

		// Validate basic content
		if lineCount == 0 {
			fmt.Println("Error: Wordlist file is empty. Please provide a file with subdomain entries.")
			continue
		}

		if firstLine != "" {
			fmt.Printf("First entry: %s\n", firstLine)
		}

		// Ask for confirmation
		fmt.Print("Use this wordlist? (y/n): ")
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			continue
		}

		return wordlistPath, nil
	}
}

// CustomizeOptions allows the user to customize scan options
func CustomizeOptions(options tools.ScanOptions) (tools.ScanOptions, error) {
	reader := bufio.NewReader(os.Stdin)

	// Set optimal defaults
	if options.Threads == 0 {
		options.Threads = getDefaultThreadCount()
	}

	fmt.Print("\nCustomize scan options? (y/n): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return options, fmt.Errorf("error reading input: %v", err)
	}

	if strings.ToLower(strings.TrimSpace(input)) != "y" {
		return options, nil
	}

	// Thread count
	for {
		fmt.Printf("Thread count (1-100, default: %d): ", options.Threads)
		input, err = reader.ReadString('\n')
		if err != nil {
			return options, fmt.Errorf("error reading input: %v", err)
		}

		input = strings.TrimSpace(input)
		if input == "" {
			break // Keep default
		}

		threads, err := strconv.Atoi(input)
		if err != nil {
			fmt.Println("Error: Invalid number. Please enter a number between 1 and 100.")
			continue
		}

		if threads < 1 || threads > 100 {
			fmt.Println("Error: Thread count must be between 1 and 100.")
			continue
		}

		options.Threads = threads
		break
	}

	// HTTP check
	fmt.Printf("Check HTTP connectivity? (y/n, default: %t): ", options.CheckHTTP)
	input, err = reader.ReadString('\n')
	if err != nil {
		return options, fmt.Errorf("error reading input: %v", err)
	}

	input = strings.TrimSpace(input)
	if input != "" {
		options.CheckHTTP = strings.ToLower(input) == "y"
	}

	// SSL check
	fmt.Printf("Check SSL/TLS? (y/n, default: %t): ", options.CheckSSL)
	input, err = reader.ReadString('\n')
	if err != nil {
		return options, fmt.Errorf("error reading input: %v", err)
	}

	input = strings.TrimSpace(input)
	if input != "" {
		options.CheckSSL = strings.ToLower(input) == "y"
	}

	// Timeout
	for {
		fmt.Printf("Connection timeout in seconds (1-60, default: %d): ", options.Timeout)
		input, err = reader.ReadString('\n')
		if err != nil {
			return options, fmt.Errorf("error reading input: %v", err)
		}

		input = strings.TrimSpace(input)
		if input == "" {
			break // Keep default
		}

		timeout, err := strconv.Atoi(input)
		if err != nil {
			fmt.Println("Error: Invalid number. Please enter a number between 1 and 60.")
			continue
		}

		if timeout < 1 || timeout > 60 {
			fmt.Println("Error: Timeout must be between 1 and 60 seconds.")
			continue
		}

		options.Timeout = timeout
		break
	}

	// Resolve IPs
	fmt.Printf("Resolve IP addresses? (y/n, default: %t): ", options.ResolveIPs)
	input, err = reader.ReadString('\n')
	if err != nil {
		return options, fmt.Errorf("error reading input: %v", err)
	}

	input = strings.TrimSpace(input)
	if input != "" {
		options.ResolveIPs = strings.ToLower(input) == "y"
	}

	return options, nil
}
