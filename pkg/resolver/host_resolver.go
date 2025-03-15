// pkg/resolver/host_resolver.go
package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ResolveResult represents the result of a DNS resolution
type ResolveResult struct {
	Hostname string   `json:"hostname"`
	IPv4     []string `json:"ipv4,omitempty"`
	IPv6     []string `json:"ipv6,omitempty"`
	Error    string   `json:"error,omitempty"`
	Resolved bool     `json:"resolved"`
}

// HostResolver provides methods for resolving hostnames and discovering subdomains
type HostResolver struct {
	// Optional custom DNS resolvers (empty means use system defaults)
	DNSServers []string
	// Timeout for DNS queries
	Timeout time.Duration
	// Maximum number of retries for failed queries
	MaxRetries int
	// Delay between retries
	RetryDelay time.Duration
	// Whether to resolve only IPv4 addresses
	IPv4Only bool
	// Whether to resolve only IPv6 addresses
	IPv6Only bool
	// Cache resolved entries to avoid repeated queries
	cache     map[string]ResolveResult
	cacheLock sync.RWMutex
}

// NewHostResolver creates a new host resolver with default settings
func NewHostResolver() *HostResolver {
	return &HostResolver{
		Timeout:    5 * time.Second,
		MaxRetries: 2,
		RetryDelay: 500 * time.Millisecond,
		cache:      make(map[string]ResolveResult),
	}
}

// WithDNSServers sets custom DNS servers
func (r *HostResolver) WithDNSServers(servers []string) *HostResolver {
	r.DNSServers = servers
	return r
}

// WithTimeout sets the timeout for DNS queries
func (r *HostResolver) WithTimeout(timeout time.Duration) *HostResolver {
	r.Timeout = timeout
	return r
}

// WithRetries sets the maximum number of retries for failed queries
func (r *HostResolver) WithRetries(retries int) *HostResolver {
	r.MaxRetries = retries
	return r
}

// WithIPv4Only configures resolver to only return IPv4 addresses
func (r *HostResolver) WithIPv4Only(ipv4Only bool) *HostResolver {
	r.IPv4Only = ipv4Only
	r.IPv6Only = false // can't be both
	return r
}

// WithIPv6Only configures resolver to only return IPv6 addresses
func (r *HostResolver) WithIPv6Only(ipv6Only bool) *HostResolver {
	r.IPv6Only = ipv6Only
	r.IPv4Only = false // can't be both
	return r
}

// ClearCache clears the resolution cache
func (r *HostResolver) ClearCache() {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()
	r.cache = make(map[string]ResolveResult)
}

// ResolveHost resolves a hostname to IP addresses
func (r *HostResolver) ResolveHost(hostname string) (ResolveResult, error) {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return ResolveResult{Error: "empty hostname", Resolved: false}, fmt.Errorf("empty hostname")
	}

	// Check cache first
	r.cacheLock.RLock()
	if result, found := r.cache[hostname]; found {
		r.cacheLock.RUnlock()
		return result, nil
	}
	r.cacheLock.RUnlock()

	result := ResolveResult{
		Hostname: hostname,
		Resolved: false,
	}

	// Create custom resolver if DNS servers are specified
	var resolver *net.Resolver
	if len(r.DNSServers) > 0 {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Use the first DNS server in the list
				d := net.Dialer{Timeout: r.Timeout}
				return d.DialContext(ctx, "udp", r.DNSServers[0])
			},
		}
	} else {
		resolver = &net.Resolver{}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	// Perform lookups with retries
	var err error
	var ipv4Addrs, ipv6Addrs []string

	if !r.IPv6Only {
		ipv4Addrs, err = r.lookupIPv4WithRetry(ctx, resolver, hostname)
		if err != nil && len(ipv4Addrs) == 0 {
			result.Error = fmt.Sprintf("IPv4 lookup error: %v", err)
		} else {
			result.IPv4 = ipv4Addrs
		}
	}

	if !r.IPv4Only {
		ipv6Addrs, err = r.lookupIPv6WithRetry(ctx, resolver, hostname)
		if err != nil && len(ipv6Addrs) == 0 {
			if result.Error != "" {
				result.Error += "; "
			}
			result.Error += fmt.Sprintf("IPv6 lookup error: %v", err)
		} else {
			result.IPv6 = ipv6Addrs
		}
	}

	// Consider resolved if we found any IP addresses
	result.Resolved = len(result.IPv4) > 0 || len(result.IPv6) > 0

	// Store in cache
	r.cacheLock.Lock()
	r.cache[hostname] = result
	r.cacheLock.Unlock()

	return result, nil
}

// ResolveSubdomains discovers and resolves subdomains for a given domain
func (r *HostResolver) ResolveSubdomains(domain string, subdomains []string) ([]ResolveResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	results := make([]ResolveResult, 0, len(subdomains))

	// Try to resolve each subdomain
	for _, sub := range subdomains {
		// Skip empty subdomains
		if sub == "" {
			continue
		}

		// Create full hostname
		hostname := sub
		if !strings.HasSuffix(hostname, domain) {
			hostname = fmt.Sprintf("%s.%s", sub, domain)
		}

		// Resolve the hostname
		result, _ := r.ResolveHost(hostname)
		results = append(results, result)
	}

	return results, nil
}

// ResolveSubdomainsConcurrent resolves subdomains concurrently with a specified number of workers
func (r *HostResolver) ResolveSubdomainsConcurrent(domain string, subdomains []string, workers int) ([]ResolveResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	if workers <= 0 {
		workers = 10 // Default to 10 workers
	}

	total := len(subdomains)
	if total == 0 {
		return []ResolveResult{}, nil
	}

	// Create channels for work distribution and collection
	jobs := make(chan string, total)
	results := make(chan ResolveResult, total)
	var wg sync.WaitGroup

	// Start workers
	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				// Create full hostname
				hostname := sub
				if !strings.HasSuffix(hostname, domain) {
					hostname = fmt.Sprintf("%s.%s", sub, domain)
				}

				// Resolve the hostname
				result, _ := r.ResolveHost(hostname)
				results <- result
			}
		}()
	}

	// Send jobs to workers
	for _, sub := range subdomains {
		if sub != "" { // Skip empty subdomains
			jobs <- sub
		}
	}
	close(jobs)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	resolveResults := make([]ResolveResult, 0, total)
	for result := range results {
		resolveResults = append(resolveResults, result)
	}

	return resolveResults, nil
}

// BulkResolve resolves multiple hostnames in parallel
func (r *HostResolver) BulkResolve(hostnames []string, workers int) ([]ResolveResult, error) {
	if workers <= 0 {
		workers = 10 // Default to 10 workers
	}

	total := len(hostnames)
	if total == 0 {
		return []ResolveResult{}, nil
	}

	// Create channels for work distribution and collection
	jobs := make(chan string, total)
	results := make(chan ResolveResult, total)
	var wg sync.WaitGroup

	// Start workers
	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for hostname := range jobs {
				result, _ := r.ResolveHost(hostname)
				results <- result
			}
		}()
	}

	// Send jobs to workers
	for _, hostname := range hostnames {
		if hostname != "" {
			jobs <- hostname
		}
	}
	close(jobs)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	resolveResults := make([]ResolveResult, 0, total)
	for result := range results {
		resolveResults = append(resolveResults, result)
	}

	return resolveResults, nil
}

// lookupIPv4WithRetry performs IPv4 lookups with retries
func (r *HostResolver) lookupIPv4WithRetry(ctx context.Context, resolver *net.Resolver, hostname string) ([]string, error) {
	var ips []string
	var lastErr error

	for attempt := 0; attempt <= r.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(r.RetryDelay)
		}

		// Lookup IPv4 addresses
		addrs, err := resolver.LookupIP(ctx, "ip4", hostname)
		if err == nil {
			// Convert net.IP to strings
			for _, ip := range addrs {
				ips = append(ips, ip.String())
			}
			return ips, nil
		}
		lastErr = err
	}

	return ips, lastErr
}

// lookupIPv6WithRetry performs IPv6 lookups with retries
func (r *HostResolver) lookupIPv6WithRetry(ctx context.Context, resolver *net.Resolver, hostname string) ([]string, error) {
	var ips []string
	var lastErr error

	for attempt := 0; attempt <= r.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(r.RetryDelay)
		}

		// Lookup IPv6 addresses
		addrs, err := resolver.LookupIP(ctx, "ip6", hostname)
		if err == nil {
			// Convert net.IP to strings
			for _, ip := range addrs {
				ips = append(ips, ip.String())
			}
			return ips, nil
		}
		lastErr = err
	}

	return ips, lastErr
}

// IsIPv4 checks if a string is a valid IPv4 address
func IsIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// IsIPv6 checks if a string is a valid IPv6 address
func IsIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// IsValidDomain checks if a string is a valid domain name
func IsValidDomain(domain string) bool {
	// Simple regex-free validation for domain names
	if domain == "" || len(domain) > 255 {
		return false
	}

	// Check each label
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		// First character must be alphanumeric
		if !isAlphaNumeric(rune(label[0])) {
			return false
		}

		// Last character must be alphanumeric
		if !isAlphaNumeric(rune(label[len(label)-1])) {
			return false
		}

		// Middle characters can be alphanumeric or hyphens
		for _, ch := range label[1 : len(label)-1] {
			if !isAlphaNumeric(ch) && ch != '-' {
				return false
			}
		}
	}

	// Must have at least one dot and the last label must be all letters
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	// Simple check for TLD - should be at least 2 characters and all alpha
	tld := parts[len(parts)-1]
	if len(tld) < 2 {
		return false
	}
	for _, ch := range tld {
		if ch < 'a' || ch > 'z' {
			return false
		}
	}

	return true
}

// isAlphaNumeric checks if a character is a letter or a digit
func isAlphaNumeric(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}
