// Package subdomain pkg/subdomain/utils.go
package subdomain

import (
	"sync"
)

var (
	_ sync.RWMutex
)

// CleanDomain removes http/https and any trailing slashes from the domain

// ValidateDomainFormat checks if a domain name format is valid

// ValidateDomain checks if a domain name is valid and exists

// FormatSize formats a file size in bytes to a human-readable string

// GenerateProgressBar creates a simple ASCII progress bar

// FileExists checks if a file exists and is not a directory

// DirectoryExists checks if a directory exists

// EnsureDirectory ensures a directory exists, creating it if necessary

// GetFileSize returns the size of a file in bytes

// ExpandHomeDir expands the tilde in a file path to the user's home directory

// getDefaultThreadCount returns the optimal default thread count based on system resources

// GetDomainInput gets and validates the target domain from user input

// GetWordlistPath gets the wordlist path from user input

// CustomizeOptions allows user to customize scanning options

// ScanOptions defines options for subdomain scanning
type ScanOptions struct {
	WordlistPath string // Path to a wordlist file
	Threads      int    // Number of concurrent goroutines
	CheckHTTP    bool   // Whether to check HTTP status
	CheckSSL     bool   // Whether to check SSL certificates
	Timeout      int    // Timeout in seconds for each check
	ResolveIPs   bool   // Whether to resolve IPs
}
