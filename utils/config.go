package utils

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Configuration represents the application's configuration
type Configuration struct {
	Logging LoggingConfig `yaml:"logging"`
	Tools   ToolsConfig   `yaml:"tools"`
}

// LoggingConfig represents logging-specific configuration
type LoggingConfig struct {
	Level     string `yaml:"level"`
	File      string `yaml:"file"`
	ColorMode string `yaml:"color_mode"` // auto, always, never
}

// ToolsConfig represents all tool-specific configurations
type ToolsConfig struct {
	PortScanner       PortScannerConfig       `yaml:"port_scanner"`
	SubdomainScanner  SubdomainScannerConfig  `yaml:"subdomain_scanner"`
	WebVulnScanner    WebVulnScannerConfig    `yaml:"web_vuln_scanner"`
	DirBruteforcer    DirBruteforcerConfig    `yaml:"dir_bruteforcer"`
	EmailHarvester    EmailHarvesterConfig    `yaml:"email_harvester"`
	S3Scanner         S3ScannerConfig         `yaml:"s3_scanner"`
	ReportingTools    ReportingToolsConfig    `yaml:"reporting_tools"`
	HostResolver      HostResolverConfig      `yaml:"host_resolver"`
	DependencyChecker DependencyCheckerConfig `yaml:"dependency_checker"`
}

// PortScannerConfig represents port scanner configuration
type PortScannerConfig struct {
	DefaultTimeout string `yaml:"default_timeout"`
	Threads        int    `yaml:"threads"`
	DefaultRange   string `yaml:"default_range"`
}

// SubdomainScannerConfig represents subdomain scanner configuration
type SubdomainScannerConfig struct {
	Wordlist string `yaml:"wordlist"`
	Threads  int    `yaml:"threads"`
	Timeout  string `yaml:"timeout"`
}

// WebVulnScannerConfig represents web vulnerability scanner configuration
type WebVulnScannerConfig struct {
	Threads        int    `yaml:"threads"`
	Timeout        string `yaml:"timeout"`
	CheckXSS       bool   `yaml:"check_xss"`
	CheckSQLi      bool   `yaml:"check_sqli"`
	CheckCookies   bool   `yaml:"check_cookies"`
	CheckHeaders   bool   `yaml:"check_headers"`
	DefaultDepth   int    `yaml:"default_depth"`
	RequestDelay   string `yaml:"request_delay"`
	UserAgent      string `yaml:"user_agent"`
	FollowRedirect bool   `yaml:"follow_redirect"`
}

// DirBruteforcerConfig represents directory bruteforcer configuration
type DirBruteforcerConfig struct {
	Wordlist   string `yaml:"wordlist"`
	Threads    int    `yaml:"threads"`
	Extensions string `yaml:"extensions"`
}

// EmailHarvesterConfig represents email harvester configuration
type EmailHarvesterConfig struct {
	Timeout     string `yaml:"timeout"`
	MaxResults  int    `yaml:"max_results"`
	SearchDepth int    `yaml:"search_depth"`
}

// S3ScannerConfig represents S3 scanner configuration
type S3ScannerConfig struct {
	Timeout            string `yaml:"timeout"`
	MaxBuckets         int    `yaml:"max_buckets"`
	PermutationDepth   int    `yaml:"permutation_depth"`
	CheckPermissions   bool   `yaml:"check_permissions"`
	BruteforceWordlist string `yaml:"bruteforce_wordlist"`
}

// ReportingToolsConfig represents reporting tools configuration
type ReportingToolsConfig struct {
	OutputDir     string `yaml:"output_dir"`
	DefaultFormat string `yaml:"default_format"`
}

// HostResolverConfig represents host resolver configuration
type HostResolverConfig struct {
	Threads       int    `yaml:"threads"`
	Timeout       string `yaml:"timeout"`
	DNSServers    string `yaml:"dns_servers"`
	ResolverCache bool   `yaml:"resolver_cache"`
}

// DependencyCheckerConfig represents dependency checker configuration
type DependencyCheckerConfig struct {
	AutoInstall          bool `yaml:"auto_install"`
	SkipNonCritical      bool `yaml:"skip_non_critical"`
	VerboseDependencyLog bool `yaml:"verbose_dependency_log"`
}

// Global configuration instance
var Config = DefaultConfig()

// DefaultConfig returns a configuration with default values
func DefaultConfig() Configuration {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	defaultLogFile := filepath.Join(homeDir, ".gopherstrike", "logs", "gopherstrike.log")
	defaultWordlist := filepath.Join(homeDir, ".gopherstrike", "wordlists", "subdomains.txt")

	return Configuration{
		Logging: LoggingConfig{
			Level:     "info",
			File:      defaultLogFile,
			ColorMode: "auto",
		},
		Tools: ToolsConfig{
			PortScanner: PortScannerConfig{
				DefaultTimeout: "2s",
				Threads:        100,
				DefaultRange:   "1-1024",
			},
			SubdomainScanner: SubdomainScannerConfig{
				Wordlist: defaultWordlist,
				Threads:  50,
				Timeout:  "5s",
			},
			WebVulnScanner: WebVulnScannerConfig{
				Threads:        10,
				Timeout:        "10s",
				CheckXSS:       true,
				CheckSQLi:      true,
				CheckCookies:   true,
				CheckHeaders:   true,
				DefaultDepth:   2,
				RequestDelay:   "100ms",
				UserAgent:      "GopherStrike Web Scanner",
				FollowRedirect: true,
			},
			DirBruteforcer: DirBruteforcerConfig{
				Wordlist:   "dirbuster-medium.txt",
				Threads:    50,
				Extensions: "php,html,js",
			},
			EmailHarvester: EmailHarvesterConfig{
				Timeout:     "30s",
				MaxResults:  100,
				SearchDepth: 2,
			},
			S3Scanner: S3ScannerConfig{
				Timeout:            "10s",
				MaxBuckets:         100,
				PermutationDepth:   2,
				CheckPermissions:   true,
				BruteforceWordlist: "s3-buckets.txt",
			},
			ReportingTools: ReportingToolsConfig{
				OutputDir:     "reports",
				DefaultFormat: "html",
			},
			HostResolver: HostResolverConfig{
				Threads:       50,
				Timeout:       "5s",
				DNSServers:    "8.8.8.8,1.1.1.1",
				ResolverCache: true,
			},
			DependencyChecker: DependencyCheckerConfig{
				AutoInstall:          false,
				SkipNonCritical:      false,
				VerboseDependencyLog: false,
			},
		},
	}
}

// LoadConfig loads the configuration from a file and command-line flags
func LoadConfig() error {
	// Define command-line flags
	configFile := flag.String("config", "", "Path to configuration file")
	logLevel := flag.String("log-level", "", "Log level (debug, info, warn, error)")
	verbose := flag.Bool("verbose", false, "Enable verbose output (same as --log-level=debug)")
	help := flag.Bool("help", false, "Show help")

	// Parse command-line flags
	flag.Parse()

	// Show help if requested
	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// Load default configuration
	Config = DefaultConfig()

	// Create directories for config file if they don't exist
	homeDir, err := os.UserHomeDir()
	if err == nil {
		configDir := filepath.Join(homeDir, ".gopherstrike")
		os.MkdirAll(configDir, 0755)
		os.MkdirAll(filepath.Join(configDir, "logs"), 0755)
		os.MkdirAll(filepath.Join(configDir, "wordlists"), 0755)

		// If no config file specified, check for default config location
		if *configFile == "" {
			defaultConfigPath := filepath.Join(configDir, "config.yaml")
			if _, err := os.Stat(defaultConfigPath); err == nil {
				*configFile = defaultConfigPath
			}
		}
	}

	// Load configuration from file if specified
	if *configFile != "" {
		if err := loadConfigFromFile(*configFile); err != nil {
			return fmt.Errorf("failed to load config file: %v", err)
		}
	}

	// Override with command-line flags
	if *verbose {
		Config.Logging.Level = "debug"
	} else if *logLevel != "" {
		Config.Logging.Level = *logLevel
	}

	return nil
}

// loadConfigFromFile loads configuration from the specified YAML file
func loadConfigFromFile(filePath string) error {
	// Expand ~ to home directory
	if strings.HasPrefix(filePath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			filePath = filepath.Join(homeDir, filePath[2:])
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &Config)
}

// GetConfigValue returns a configuration value as a string based on the path
// Example: GetConfigValue("logging.level") returns Config.Logging.Level
func GetConfigValue(path string) string {
	switch {
	case path == "logging.level":
		return Config.Logging.Level
	case path == "logging.file":
		return Config.Logging.File
	case path == "logging.color_mode":
		return Config.Logging.ColorMode

	case path == "tools.port_scanner.default_timeout":
		return Config.Tools.PortScanner.DefaultTimeout
	case path == "tools.port_scanner.threads":
		return fmt.Sprintf("%d", Config.Tools.PortScanner.Threads)
	case path == "tools.port_scanner.default_range":
		return Config.Tools.PortScanner.DefaultRange

	case path == "tools.subdomain_scanner.wordlist":
		return Config.Tools.SubdomainScanner.Wordlist
	case path == "tools.subdomain_scanner.threads":
		return fmt.Sprintf("%d", Config.Tools.SubdomainScanner.Threads)
	case path == "tools.subdomain_scanner.timeout":
		return Config.Tools.SubdomainScanner.Timeout

	// Add more cases as needed for other config paths

	default:
		return ""
	}
}
