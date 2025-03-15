// pkg/tools/subdomain/utils.go
package subdomain

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// Cache for domain validation to prevent redundant lookups
	domainCache     = make(map[string]bool)
	domainCacheLock sync.RWMutex

	// Precompiled regex patterns for better performance
	domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// CleanDomain removes http/https and any trailing slashes from the domain
func CleanDomain(input string) string {
	// Convert to lowercase for consistency
	domain := strings.ToLower(input)

	// Remove http:// or https:// prefixes
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Remove trailing slash
	domain = strings.TrimSuffix(domain, "/")

	// Remove any www. prefix
	domain = strings.TrimPrefix(domain, "www.")

	// Remove any paths, query parameters, etc.
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port number if specified
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove any whitespace
	domain = strings.TrimSpace(domain)

	return domain
}

// ValidateDomainFormat checks if a domain name format is valid
func ValidateDomainFormat(domain string) bool {
	// Basic validation
	if domain == "" {
		return false
	}

	// Check domain name format using precompiled regex
	return domainRegex.MatchString(domain)
}

// ValidateDomain checks if a domain name is valid and exists
func ValidateDomain(domain string) bool {
	// Format validation first (fast)
	if !ValidateDomainFormat(domain) {
		return false
	}

	// Check cache first
	domainCacheLock.RLock()
	if result, found := domainCache[domain]; found {
		domainCacheLock.RUnlock()
		return result
	}
	domainCacheLock.RUnlock()

	// Try to resolve the domain with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var resolver net.Resolver
	_, err := resolver.LookupHost(ctx, domain)

	// Cache the result
	result := err == nil
	domainCacheLock.Lock()
	domainCache[domain] = result
	domainCacheLock.Unlock()

	return result
}

// FormatSize formats a file size in bytes to a human-readable string
func FormatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.2f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

// GenerateProgressBar creates a simple ASCII progress bar
func GenerateProgressBar(progress, total int, width int) string {
	if total <= 0 {
		return "[----------] Unknown progress"
	}

	percent := float64(progress) / float64(total)
	completeWidth := int(percent * float64(width))

	bar := "["
	for i := 0; i < width; i++ {
		if i < completeWidth {
			bar += "="
		} else if i == completeWidth {
			bar += ">"
		} else {
			bar += " "
		}
	}
	bar += "]"

	return fmt.Sprintf("%s %.1f%% (%d/%d)", bar, percent*100, progress, total)
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirectoryExists checks if a directory exists
func DirectoryExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// EnsureDirectory ensures a directory exists, creating it if necessary
func EnsureDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filename string) (int64, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// ExpandHomeDir expands the tilde in a file path to the user's home directory
func ExpandHomeDir(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return strings.Replace(path, "~/", home+"/", 1), nil
}
