// pkg/tools/osint/serverinfo.go
package osint

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ProductInfo is a mapping of product name to version and EOL date
type ProductInfo struct {
	Name       string
	Version    string
	EOLDate    time.Time
	IsEOL      bool
	UpdateInfo string
}

var (
	// Regular expressions for banner parsing
	// Apache regex
	apacheRegex = regexp.MustCompile(`Apache(?:/(\d+\.\d+(?:\.\d+)?))?`)

	// Nginx regex
	nginxRegex = regexp.MustCompile(`nginx(?:/(\d+\.\d+(?:\.\d+)?))?`)

	// IIS regex
	iisRegex = regexp.MustCompile(`Microsoft-IIS/(\d+\.\d+)`)

	// OpenSSH regex
	opensshRegex = regexp.MustCompile(`OpenSSH(?:_|/| )(\d+\.\d+(?:p\d+)?)`)

	// Various OS regexes
	ubuntuRegex  = regexp.MustCompile(`Ubuntu[/-](\d+\.\d+)`)
	centosRegex  = regexp.MustCompile(`CentOS(?:/| )(\d+(?:\.\d+)?)`)
	debianRegex  = regexp.MustCompile(`Debian (?:GNU/Linux )?(\d+(?:\.\d+)?)`)
	windowsRegex = regexp.MustCompile(`(Windows) (?:NT )?(\d+\.\d+)`)
)

// GatherServerInfo collects server information from a target
func GatherServerInfo(target string, ports []int) (*ServerInfo, error) {
	// Initialize server info
	serverInfo := &ServerInfo{
		IPAddress: target,
		Ports:     make([]int, 0),
		Services:  make(map[int]string),
		Headers:   make(map[string]string),
		Banners:   make(map[int]string),
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	// Try to resolve hostname if IP is provided
	if net.ParseIP(target) != nil {
		hostname, err := lookupHostname(target)
		if err == nil && hostname != "" {
			serverInfo.Hostname = hostname
		}
	} else {
		// Target is a hostname, resolve IP
		ips, err := net.LookupIP(target)
		if err == nil && len(ips) > 0 {
			serverInfo.IPAddress = ips[0].String()
			serverInfo.Hostname = target
		}
	}

	// If no ports provided, use common ones
	if len(ports) == 0 {
		ports = []int{21, 22, 25, 80, 443, 8080, 8443}
	}

	// Check for HTTP(S) service on common web ports
	httpPorts := filterPorts(ports, []int{80, 443, 8080, 8443})
	if len(httpPorts) > 0 {
		gatherHTTPInfo(serverInfo, httpPorts)
	}

	// Gather banner information for other ports
	otherPorts := filterExcludedPorts(ports, httpPorts)
	for _, port := range otherPorts {
		banner, service := getBanner(serverInfo.IPAddress, port)
		if banner != "" {
			serverInfo.Banners[port] = banner
			serverInfo.Services[port] = service
			serverInfo.Ports = append(serverInfo.Ports, port)

			// Try to identify OS/product from banner
			processServiceBanner(serverInfo, port, banner)
		}
	}

	// Detect operating system if not already detected
	if serverInfo.OS == "" {
		detectOS(serverInfo)
	}

	// Check for EOL status and updates
	checkEOLStatus(serverInfo)

	return serverInfo, nil
}

// gatherHTTPInfo collects information from HTTP headers
func gatherHTTPInfo(serverInfo *ServerInfo, ports []int) {
	for _, port := range ports {
		// Determine protocol (HTTP or HTTPS)
		protocol := "http"
		if port == 443 || port == 8443 {
			protocol = "https"
		}

		// Create URL with proper handling of IPv6 addresses
		var url string
		ip := net.ParseIP(serverInfo.IPAddress)
		if ip != nil && ip.To4() == nil { // This is an IPv6 address
			url = fmt.Sprintf("%s://[%s]:%d", protocol, serverInfo.IPAddress, port)
		} else {
			url = fmt.Sprintf("%s://%s:%d", protocol, serverInfo.IPAddress, port)
		}

		// Make HTTP request with timeout
		client := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects
				return http.ErrUseLastResponse
			},
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		// Add common user agent
		req.Header.Set("User-Agent", "Mozilla/5.0 GopherStrike OSINT Scanner")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		// Store port in serverInfo
		serverInfo.Ports = append(serverInfo.Ports, port)
		serverInfo.Services[port] = "HTTP"

		// Process headers
		for name, values := range resp.Header {
			if len(values) > 0 {
				serverInfo.Headers[name] = values[0]

				// Extract server info from specific headers
				switch strings.ToLower(name) {
				case "server":
					processServerHeader(serverInfo, values[0])
				case "x-powered-by":
					processPoweredByHeader(serverInfo, values[0])
				}
			}
		}

		// Close response body
		resp.Body.Close()
	}
}

// getBanner attempts to get a service banner from a port
func getBanner(host string, port int) (string, string) {
	// Connect with timeout
	// Use net.JoinHostPort to properly handle IPv6 addresses
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Try to read banner
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", ""
	}

	// Clean banner
	banner = strings.TrimSpace(banner)

	// Identify service based on port and banner
	service := identifyService(port, banner)

	return banner, service
}

// identifyService identifies a service based on port and banner
func identifyService(port int, banner string) string {
	// Common port to service mapping
	commonServices := map[int]string{
		21:   "FTP",
		22:   "SSH",
		25:   "SMTP",
		80:   "HTTP",
		443:  "HTTPS",
		3306: "MySQL",
		5432: "PostgreSQL",
		6379: "Redis",
		8080: "HTTP",
		8443: "HTTPS",
		9200: "Elasticsearch",
	}

	// Check if port is in common services
	if service, found := commonServices[port]; found {
		return service
	}

	// Try to identify from banner
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "ssh") {
		return "SSH"
	} else if strings.Contains(bannerLower, "ftp") {
		return "FTP"
	} else if strings.Contains(bannerLower, "smtp") {
		return "SMTP"
	} else if strings.Contains(bannerLower, "http") {
		return "HTTP"
	} else if strings.Contains(bannerLower, "mysql") {
		return "MySQL"
	} else if strings.Contains(bannerLower, "postgresql") {
		return "PostgreSQL"
	}

	// Default unknown
	return "Unknown"
}

// processServerHeader extracts server information from the Server header
func processServerHeader(serverInfo *ServerInfo, header string) {
	// Check for Apache
	if matches := apacheRegex.FindStringSubmatch(header); len(matches) > 1 {
		serverInfo.ProductName = "Apache HTTP Server"
		if matches[1] != "" {
			serverInfo.ProductVersion = matches[1]
		}
	}

	// Check for Nginx
	if matches := nginxRegex.FindStringSubmatch(header); len(matches) > 1 {
		serverInfo.ProductName = "Nginx"
		if matches[1] != "" {
			serverInfo.ProductVersion = matches[1]
		}
	}

	// Check for IIS
	if matches := iisRegex.FindStringSubmatch(header); len(matches) > 1 {
		serverInfo.ProductName = "Microsoft IIS"
		serverInfo.ProductVersion = matches[1]
		serverInfo.OS = "Windows"
	}

	// Try to extract OS info
	if matches := ubuntuRegex.FindStringSubmatch(header); len(matches) > 1 {
		serverInfo.OS = "Ubuntu"
		serverInfo.OSVersion = matches[1]
	} else if matches := centosRegex.FindStringSubmatch(header); len(matches) > 1 {
		serverInfo.OS = "CentOS"
		serverInfo.OSVersion = matches[1]
	} else if matches := debianRegex.FindStringSubmatch(header); len(matches) > 1 {
		serverInfo.OS = "Debian"
		serverInfo.OSVersion = matches[1]
	} else if matches := windowsRegex.FindStringSubmatch(header); len(matches) > 1 {
		serverInfo.OS = matches[1]
		serverInfo.OSVersion = matches[2]
	}
}

// processPoweredByHeader extracts information from X-Powered-By header
func processPoweredByHeader(serverInfo *ServerInfo, header string) {
	// Extract PHP version
	phpRegex := regexp.MustCompile(`PHP/(\d+\.\d+(?:\.\d+)?)`)
	if matches := phpRegex.FindStringSubmatch(header); len(matches) > 1 {
		// Store as additional product if main product is already set
		if serverInfo.ProductName != "" && serverInfo.ProductName != "PHP" {
			serverInfo.ProductName += " with PHP " + matches[1]
		} else {
			serverInfo.ProductName = "PHP"
			serverInfo.ProductVersion = matches[1]
		}
	}

	// Extract ASP.NET version
	aspNetRegex := regexp.MustCompile(`ASP\.NET(?:[/ ](\d+\.\d+(?:\.\d+)?))?`)
	if matches := aspNetRegex.FindStringSubmatch(header); len(matches) > 0 {
		// Store as additional product if main product is already set
		if serverInfo.ProductName != "" && !strings.Contains(serverInfo.ProductName, "ASP.NET") {
			serverInfo.ProductName += " with ASP.NET"
			if matches[1] != "" {
				serverInfo.ProductName += " " + matches[1]
			}
		} else {
			serverInfo.ProductName = "ASP.NET"
			if matches[1] != "" {
				serverInfo.ProductVersion = matches[1]
			}
		}
		// ASP.NET implies Windows
		serverInfo.OS = "Windows"
	}
}

// processServiceBanner extracts information from service banners
func processServiceBanner(serverInfo *ServerInfo, port int, banner string) {
	// Extract SSH version
	if port == 22 || strings.HasPrefix(strings.ToLower(banner), "ssh") {
		if matches := opensshRegex.FindStringSubmatch(banner); len(matches) > 1 {
			// Store as main product if not already set
			if serverInfo.ProductName == "" {
				serverInfo.ProductName = "OpenSSH"
				serverInfo.ProductVersion = matches[1]
			}
		}

		// Try to extract OS from SSH banner
		if serverInfo.OS == "" {
			if strings.Contains(banner, "Ubuntu") {
				serverInfo.OS = "Ubuntu"
			} else if strings.Contains(banner, "Debian") {
				serverInfo.OS = "Debian"
			} else if strings.Contains(banner, "CentOS") {
				serverInfo.OS = "CentOS"
			} else if strings.Contains(banner, "Windows") {
				serverInfo.OS = "Windows"
			}
		}
	}
}

// detectOS attempts to determine the OS if it wasn't identified from headers
func detectOS(serverInfo *ServerInfo) {
	// Use product information to make educated guesses
	if serverInfo.ProductName != "" {
		productLower := strings.ToLower(serverInfo.ProductName)

		if strings.Contains(productLower, "microsoft") ||
			strings.Contains(productLower, "iis") ||
			strings.Contains(productLower, "windows") {
			serverInfo.OS = "Windows"
		} else if strings.Contains(productLower, "apache") {
			// Apache often implies Unix/Linux
			serverInfo.OS = "Linux"
		}
	}

	// If still unknown, check open ports for clues
	if serverInfo.OS == "" {
		// Port 3389 often indicates Windows (RDP)
		for _, port := range serverInfo.Ports {
			if port == 3389 {
				serverInfo.OS = "Windows"
				break
			}
		}
	}
}

// checkEOLStatus checks if the identified products/OS are EOL
func checkEOLStatus(serverInfo *ServerInfo) {
	// Check OS EOL status
	if serverInfo.OS != "" && serverInfo.OSVersion != "" {
		eolDate, isEOL := getOSEOLInfo(serverInfo.OS, serverInfo.OSVersion)
		if !eolDate.IsZero() {
			serverInfo.EOLDate = eolDate
			serverInfo.UpdateAvailable = isEOL
		}
	}

	// Check product EOL status
	if serverInfo.ProductName != "" && serverInfo.ProductVersion != "" {
		eolDate, isEOL := getProductEOLInfo(serverInfo.ProductName, serverInfo.ProductVersion)
		// Only update if we found EOL info or if OS EOL was not set
		if !eolDate.IsZero() || serverInfo.EOLDate.IsZero() {
			serverInfo.EOLDate = eolDate
			serverInfo.UpdateAvailable = isEOL
		}
	}
}

// getOSEOLInfo returns EOL information for an OS version
func getOSEOLInfo(os, version string) (time.Time, bool) {
	// Common EOL dates for major OS versions
	// In a production app, this would be more comprehensive and up-to-date
	osEOLDates := map[string]map[string]string{
		"Ubuntu": {
			"16.04": "2021-04-30",
			"18.04": "2023-04-30",
			"20.04": "2025-04-30",
			"22.04": "2027-04-30",
		},
		"Debian": {
			"8":  "2020-06-30",
			"9":  "2022-06-30",
			"10": "2024-06-30",
			"11": "2026-06-30",
		},
		"CentOS": {
			"6": "2020-11-30",
			"7": "2024-06-30",
			"8": "2021-12-31", // CentOS 8 early EOL
		},
		"Windows": {
			"6.1":  "2020-01-14", // Windows 7
			"6.3":  "2023-01-10", // Windows 8.1
			"10.0": "2025-10-14", // Windows 10
		},
	}

	// Normalize OS name
	osNorm := strings.ToLower(os)
	if strings.Contains(osNorm, "ubuntu") {
		os = "Ubuntu"
	} else if strings.Contains(osNorm, "debian") {
		os = "Debian"
	} else if strings.Contains(osNorm, "centos") {
		os = "CentOS"
	} else if strings.Contains(osNorm, "windows") {
		os = "Windows"
	}

	// Get EOL date from map
	if versionMap, found := osEOLDates[os]; found {
		// For Ubuntu, only check major.minor version
		if os == "Ubuntu" && strings.Count(version, ".") > 1 {
			parts := strings.Split(version, ".")
			version = parts[0] + "." + parts[1]
		}

		// For CentOS, only check major version
		if os == "CentOS" && strings.Contains(version, ".") {
			version = strings.Split(version, ".")[0]
		}

		if eolDateStr, found := versionMap[version]; found {
			eolDate, err := time.Parse("2006-01-02", eolDateStr)
			if err == nil {
				// Check if it's EOL
				isEOL := time.Now().After(eolDate)
				return eolDate, isEOL
			}
		}
	}

	return time.Time{}, false
}

// getProductEOLInfo returns EOL information for a product version
func getProductEOLInfo(product, version string) (time.Time, bool) {
	// Common EOL dates for major products
	productEOLDates := map[string]map[string]string{
		"Apache HTTP Server": {
			"2.2": "2017-12-31",
			"2.4": "2025-12-31", // Estimated
		},
		"Nginx": {
			"1.16": "2020-04-28",
			"1.18": "2021-04-21",
			"1.20": "2022-04-12",
		},
		"PHP": {
			"5.6": "2018-12-31",
			"7.0": "2019-01-10",
			"7.1": "2019-12-01",
			"7.2": "2020-11-30",
			"7.3": "2021-12-06",
			"7.4": "2022-11-28",
			"8.0": "2023-11-26",
			"8.1": "2024-11-25",
		},
		"Microsoft IIS": {
			"7.5": "2020-01-14", // IIS 7.5 (Windows 7)
			"8.0": "2016-01-12", // IIS 8.0 (Windows 8)
			"8.5": "2023-01-10", // IIS 8.5 (Windows 8.1)
			"10":  "2025-10-14", // IIS 10 (Windows 10)
		},
		"OpenSSH": {
			"7.9": "2019-10-19",
			"8.0": "2020-05-27",
			"8.1": "2020-05-27",
			"8.2": "2020-05-27",
			"8.3": "2021-09-26",
			"8.4": "2021-09-26",
			"8.5": "2021-09-26",
			"8.6": "2022-04-11",
			"8.7": "2022-04-11",
			"8.8": "2022-04-11",
			"8.9": "2023-03-01",
			"9.0": "2023-03-01",
			"9.1": "2023-10-01",
			"9.2": "2023-10-01",
			"9.3": "2023-10-01",
		},
	}

	// Normalize product name
	productNorm := strings.ToLower(product)
	if strings.Contains(productNorm, "apache") {
		product = "Apache HTTP Server"
	} else if strings.Contains(productNorm, "nginx") {
		product = "Nginx"
	} else if strings.Contains(productNorm, "php") {
		product = "PHP"
	} else if strings.Contains(productNorm, "iis") {
		product = "Microsoft IIS"
	} else if strings.Contains(productNorm, "openssh") {
		product = "OpenSSH"
	}

	// Simplify version to major.minor for comparison
	versionParts := strings.Split(version, ".")
	simplifiedVersion := version
	if len(versionParts) >= 2 {
		simplifiedVersion = versionParts[0] + "." + versionParts[1]
	}

	// Get EOL date from map
	if versionMap, found := productEOLDates[product]; found {
		if eolDateStr, found := versionMap[simplifiedVersion]; found {
			eolDate, err := time.Parse("2006-01-02", eolDateStr)
			if err == nil {
				// Check if it's EOL
				isEOL := time.Now().After(eolDate)
				return eolDate, isEOL
			}
		}
	}

	return time.Time{}, false
}

// lookupHostname attempts to resolve an IP address to a hostname
func lookupHostname(ipAddr string) (string, error) {
	hostnames, err := net.LookupAddr(ipAddr)
	if err != nil || len(hostnames) == 0 {
		return "", err
	}

	// Clean up hostname (remove trailing dot)
	hostname := strings.TrimSuffix(hostnames[0], ".")
	return hostname, nil
}

// filterPorts returns only ports present in the allowlist
func filterPorts(ports []int, allowlist []int) []int {
	// Convert allowlist to map for O(1) lookup
	allowMap := make(map[int]bool)
	for _, port := range allowlist {
		allowMap[port] = true
	}

	// Filter ports
	filtered := make([]int, 0)
	for _, port := range ports {
		if allowMap[port] {
			filtered = append(filtered, port)
		}
	}

	return filtered
}

// filterExcludedPorts returns ports not in the exclude list
func filterExcludedPorts(ports []int, excludeList []int) []int {
	// Convert exclude list to map for O(1) lookup
	excludeMap := make(map[int]bool)
	for _, port := range excludeList {
		excludeMap[port] = true
	}

	// Filter out excluded ports
	filtered := make([]int, 0)
	for _, port := range ports {
		if !excludeMap[port] {
			filtered = append(filtered, port)
		}
	}

	return filtered
}
