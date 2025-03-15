package subdomain

import (
	"fmt"
	"time"
)

// ScanConfig defines all configuration options for subdomain scanning
type ScanConfig struct {
	// Target domain to scan
	Domain string

	// Wordlist options
	WordlistPath     string
	WordlistContents []string // Optional: pre-loaded wordlist
	UseInMemory      bool     // Whether to use in-memory wordlist

	// Scan behavior
	Threads            int           // Number of concurrent goroutines
	Timeout            time.Duration // Timeout for each request
	MaxRetries         int           // Maximum retries for failed requests
	RetryDelay         time.Duration // Delay between retries
	ScanDepth          int           // How many subdomain levels to scan (1 = first level only)
	FollowWildcards    bool          // Whether to follow wildcard DNS records
	IgnoreWildcardDNS  bool          // Whether to detect and skip wildcard DNS
	WildcardThreshold  int           // Threshold for wildcard detection
	PermutateWordlists bool          // Generate permutations of words

	// Resolution options
	ResolveIPs       bool          // Whether to resolve IP addresses
	DNSServers       []string      // Custom DNS servers to use
	DNSTimeout       time.Duration // DNS resolution timeout
	DNSRetries       int           // Number of DNS retries
	UseTrustedDNS    bool          // Whether to use trusted DNS resolvers
	ValidateResults  bool          // Double-check results with multiple resolvers
	IPv4Only         bool          // Only resolve IPv4 addresses
	IPv6Only         bool          // Only resolve IPv6 addresses
	PreferredIPProto string        // Preferred IP protocol (ipv4 or ipv6)

	// HTTP options
	CheckHTTP       bool              // Whether to check HTTP status
	HTTPTimeout     time.Duration     // HTTP request timeout
	HTTPRetries     int               // Number of HTTP retries
	FollowRedirects bool              // Whether to follow HTTP redirects
	MaxRedirects    int               // Maximum number of redirects to follow
	UserAgent       string            // User-Agent header for HTTP requests
	HTTPHeaders     map[string]string // Additional HTTP headers
	HTTPMethods     []string          // HTTP methods to use

	// SSL/TLS options
	CheckSSL          bool          // Whether to check SSL certificates
	SSLTimeout        time.Duration // SSL handshake timeout
	VerifyCertificate bool          // Whether to verify certificate validity
	ExtractCertHosts  bool          // Extract hostnames from SSL certificates

	// Output options
	OutputType      string   // Output format (json, csv, text)
	OutputFile      string   // Output file path
	VerboseOutput   bool     // Whether to output detailed information
	QuietMode       bool     // Suppress all output except results
	IncludeDead     bool     // Include dead subdomains in output
	FilterByStatus  []int    // Filter results by HTTP status
	FilterByKeyword []string // Filter results by keyword in response

	// Rate limiting
	RequestsPerSecond int           // Maximum number of requests per second
	RateLimitPause    time.Duration // Pause between rate limit hits

	// Advanced options
	EnableAutoTuning   bool   // Auto-tune settings based on target
	ProxyURL           string // Proxy URL for all requests
	EnableCaching      bool   // Cache results
	CacheDir           string // Directory for cache files
	ReportProgressFreq int    // How often to report progress (in seconds)
}

// NewDefaultConfig returns a ScanConfig with sensible defaults
func NewDefaultConfig() *ScanConfig {
	return &ScanConfig{
		Threads:            10,
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		RetryDelay:         1 * time.Second,
		ScanDepth:          1,
		ResolveIPs:         true,
		CheckHTTP:          true,
		HTTPTimeout:        5 * time.Second,
		HTTPRetries:        1,
		FollowRedirects:    true,
		MaxRedirects:       3,
		UserAgent:          "GopherStrike/1.0",
		OutputType:         "json",
		VerboseOutput:      false,
		RequestsPerSecond:  0, // 0 means no limit
		ReportProgressFreq: 5,
		IgnoreWildcardDNS:  true,
		ValidateResults:    true,
		HTTPMethods:        []string{"GET"},
		EnableCaching:      true,
	}
}

// Validate checks if the configuration is valid
func (c *ScanConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}

	if c.WordlistPath == "" && len(c.WordlistContents) == 0 {
		return fmt.Errorf("wordlist path or contents are required")
	}

	if c.Threads < 1 {
		return fmt.Errorf("threads must be >= 1")
	}

	if c.IPv4Only && c.IPv6Only {
		return fmt.Errorf("cannot set both IPv4Only and IPv6Only")
	}

	if c.PreferredIPProto != "" && c.PreferredIPProto != "ipv4" && c.PreferredIPProto != "ipv6" {
		return fmt.Errorf("preferredIPProto must be either 'ipv4' or 'ipv6'")
	}

	return nil
}

// WithWordlist sets the wordlist path
func (c *ScanConfig) WithWordlist(path string) *ScanConfig {
	c.WordlistPath = path
	return c
}

// WithThreads sets the number of threads
func (c *ScanConfig) WithThreads(threads int) *ScanConfig {
	c.Threads = threads
	return c
}

// WithTimeout sets the timeout for each request
func (c *ScanConfig) WithTimeout(timeout time.Duration) *ScanConfig {
	c.Timeout = timeout
	return c
}

// WithHTTPCheck enables/disables HTTP checking
func (c *ScanConfig) WithHTTPCheck(check bool) *ScanConfig {
	c.CheckHTTP = check
	return c
}

// WithSSLCheck enables/disables SSL checking
func (c *ScanConfig) WithSSLCheck(check bool) *ScanConfig {
	c.CheckSSL = check
	return c
}

// WithResolveIPs enables/disables IP resolution
func (c *ScanConfig) WithResolveIPs(resolve bool) *ScanConfig {
	c.ResolveIPs = resolve
	return c
}

// WithOutputFile sets the output file path
func (c *ScanConfig) WithOutputFile(path string) *ScanConfig {
	c.OutputFile = path
	return c
}

// WithOutputType sets the output format
func (c *ScanConfig) WithOutputType(format string) *ScanConfig {
	c.OutputType = format
	return c
}

// WithVerboseOutput enables/disables verbose output
func (c *ScanConfig) WithVerboseOutput(verbose bool) *ScanConfig {
	c.VerboseOutput = verbose
	return c
}

// WithCustomDNSServers sets custom DNS servers
func (c *ScanConfig) WithCustomDNSServers(servers []string) *ScanConfig {
	c.DNSServers = servers
	return c
}

// WithUserAgent sets the User-Agent header
func (c *ScanConfig) WithUserAgent(userAgent string) *ScanConfig {
	c.UserAgent = userAgent
	return c
}

// WithHTTPHeaders sets additional HTTP headers
func (c *ScanConfig) WithHTTPHeaders(headers map[string]string) *ScanConfig {
	c.HTTPHeaders = headers
	return c
}

// WithRateLimit sets the maximum number of requests per second
func (c *ScanConfig) WithRateLimit(rps int) *ScanConfig {
	c.RequestsPerSecond = rps
	return c
}

// WithProxy sets a proxy URL for all requests
func (c *ScanConfig) WithProxy(proxyURL string) *ScanConfig {
	c.ProxyURL = proxyURL
	return c
}

// WithDepth sets how many subdomain levels to scan
func (c *ScanConfig) WithDepth(depth int) *ScanConfig {
	c.ScanDepth = depth
	return c
}

// DefaultConfig defines default settings for the subdomain scanner
var DefaultConfig = struct {
	// Default thread count if not specified
	ThreadCount int

	// Default timeout in seconds
	Timeout int

	// Default output formats
	OutputFormats []string

	// Default verification timeout
	DomainVerificationTimeoutSecs int

	// Maximum thread count
	MaxThreads int

	// Default log directory
	LogsDirectory string
}{
	ThreadCount:                   10,
	Timeout:                       5,
	OutputFormats:                 []string{FormatText, FormatJSON},
	DomainVerificationTimeoutSecs: 3,
	MaxThreads:                    100,
	LogsDirectory:                 "logs/subdomains",
}
