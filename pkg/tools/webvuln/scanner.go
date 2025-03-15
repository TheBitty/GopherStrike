// pkg/tools/webvuln/scanner.go
package webvuln

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Scanner represents the web vulnerability scanner
type Scanner struct {
	client      *http.Client
	payloads    *PayloadManager
	ScanOptions ScanOptions
	UserAgent   string
	Results     []ScanResult
	mutex       sync.Mutex
}

// NewScanner creates a new web vulnerability scanner
func NewScanner(options ScanOptions) *Scanner {
	// Set up HTTP client with reasonable defaults
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: options.IgnoreSSLErrors,
		},
		MaxIdleConns:    30,
		IdleConnTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(options.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= options.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", options.MaxRedirects)
			}
			return nil
		},
	}

	return &Scanner{
		client:      client,
		payloads:    NewPayloadManager(options.PayloadLevel),
		ScanOptions: options,
		UserAgent:   "GopherStrike WebVulnScanner/1.0",
		Results:     make([]ScanResult, 0),
		mutex:       sync.Mutex{},
	}
}

// Scan performs a full vulnerability scan on the target
func (s *Scanner) Scan(target ScanTarget) (*Report, error) {
	startTime := time.Now()

	// Validate target URL
	_, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	// Reset results for new scan
	s.Results = make([]ScanResult, 0)

	var wg sync.WaitGroup

	// Run tests based on enabled options
	if s.ScanOptions.EnableXSS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.testXSS(target)
		}()
	}

	if s.ScanOptions.EnableSQLInjection {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.testSQLInjection(target)
		}()
	}

	if s.ScanOptions.EnableFileInclusion {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.testFileInclusion(target)
		}()
	}

	if s.ScanOptions.EnableCSRF {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.testCSRF(target)
		}()
	}

	if s.ScanOptions.EnableMisconfiguration {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.testMisconfigurations(target)
		}()
	}

	if s.ScanOptions.EnableAuthTesting {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.testAuthWeaknesses(target)
		}()
	}

	// Wait for all tests to complete
	wg.Wait()

	// Generate report
	report := &Report{
		Target:      target,
		ScanOptions: s.ScanOptions,
		Results:     s.Results,
		StartTime:   startTime,
		EndTime:     time.Now(),
	}

	return report, nil
}

// sendRequest sends an HTTP request and returns the response
func (s *Scanner) sendRequest(target ScanTarget, method, path string, headers map[string]string, body string) (*http.Response, error) {
	// Construct URL
	targetURL := target.URL
	if path != "" {
		// Check if path is absolute or relative
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			targetURL = path
		} else {
			// Handle trailing slash in target URL and leading slash in path
			if strings.HasSuffix(targetURL, "/") && strings.HasPrefix(path, "/") {
				targetURL = targetURL + path[1:]
			} else if !strings.HasSuffix(targetURL, "/") && !strings.HasPrefix(path, "/") {
				targetURL = targetURL + "/" + path
			} else {
				targetURL = targetURL + path
			}
		}
	}

	// Create request
	req, err := http.NewRequest(method, targetURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Set default headers
	req.Header.Set("User-Agent", s.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	// Set target-specific headers
	for key, value := range target.Headers {
		req.Header.Set(key, value)
	}

	// Set additional headers passed to this request
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Set cookies
	for _, cookie := range target.Cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			req.AddCookie(&http.Cookie{
				Name:  parts[0],
				Value: parts[1],
			})
		}
	}

	// Set authentication if provided
	if target.BasicAuth.Username != "" {
		req.SetBasicAuth(target.BasicAuth.Username, target.BasicAuth.Password)
	}

	// Send request
	return s.client.Do(req)
}

// addResult adds a scan result to the results list thread-safely
func (s *Scanner) addResult(result ScanResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.Results = append(s.Results, result)
}

// testXSS tests for Cross-Site Scripting vulnerabilities
func (s *Scanner) testXSS(target ScanTarget) {
	payloads := s.payloads.GetPayloads(VulnTypeXSS)
	result := ScanResult{
		VulnerabilityType: VulnTypeXSS,
		TestResults:       make([]TestResult, 0),
	}

	// Test URL parameters for reflection
	if targetURL, err := url.Parse(target.URL); err == nil {
		params := targetURL.Query()

		// Add a test parameter if none exist
		if len(params) == 0 {
			params.Add("test", "value")
		}

		// Test each parameter
		for paramName := range params {
			for _, payload := range payloads {
				// Create a copy of the parameters and modify the test parameter
				testParams := url.Values{}
				for k, v := range params {
					testParams[k] = v
				}
				testParams.Set(paramName, payload.Value)

				// Construct test URL
				testURL := *targetURL
				testURL.RawQuery = testParams.Encode()

				// Send request
				resp, err := s.sendRequest(target, "GET", testURL.String(), nil, "")
				if err != nil {
					continue
				}

				// Check if the payload is reflected in the response
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}

				bodyStr := string(body)
				if strings.Contains(bodyStr, payload.Value) {
					result.TestResults = append(result.TestResults, TestResult{
						Payload:     payload,
						URL:         testURL.String(),
						Method:      "GET",
						Parameter:   paramName,
						Description: fmt.Sprintf("Potential XSS: Payload reflected in response for parameter '%s'", paramName),
						Severity:    SeverityHigh,
					})
				}
			}
		}
	}

	// Test form fields if form scanning is enabled
	if s.ScanOptions.ScanForms {
		// Form scanning would be implemented here
		// This would involve finding forms, testing each input field, etc.
	}

	if len(result.TestResults) > 0 {
		s.addResult(result)
	}
}

// testSQLInjection tests for SQL Injection vulnerabilities
func (s *Scanner) testSQLInjection(target ScanTarget) {
	payloads := s.payloads.GetPayloads(VulnTypeSQLInjection)
	result := ScanResult{
		VulnerabilityType: VulnTypeSQLInjection,
		TestResults:       make([]TestResult, 0),
	}

	// Test URL parameters
	if targetURL, err := url.Parse(target.URL); err == nil {
		params := targetURL.Query()

		// Add a test parameter if none exist
		if len(params) == 0 {
			params.Add("id", "1")
		}

		// Test each parameter
		for paramName := range params {
			normalValue := params.Get(paramName)

			// Get baseline response
			baselineResp, err := s.sendRequest(target, "GET", "", nil, "")
			if err != nil {
				continue
			}
			baselineBody, err := io.ReadAll(baselineResp.Body)
			baselineResp.Body.Close()
			if err != nil {
				continue
			}
			baselineContent := string(baselineBody)

			// Test with SQL injection payloads
			for _, payload := range payloads {
				// Create a copy of the parameters and modify the test parameter
				testParams := url.Values{}
				for k, v := range params {
					testParams[k] = v
				}
				testParams.Set(paramName, payload.Value)

				// Construct test URL
				testURL := *targetURL
				testURL.RawQuery = testParams.Encode()

				// Send request
				resp, err := s.sendRequest(target, "GET", testURL.String(), nil, "")
				if err != nil {
					continue
				}

				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}

				bodyStr := string(body)

				// Check for SQL error patterns
				sqlErrorPatterns := []string{
					"SQL syntax", "mysql_fetch_array", "ORA-", "Oracle Error",
					"Microsoft SQL Server", "PostgreSQL", "SQLite3::", "SQLITE_ERROR",
					"Warning: mysql", "ODBC SQL Server Driver", "syntax error",
				}

				for _, pattern := range sqlErrorPatterns {
					if strings.Contains(bodyStr, pattern) {
						result.TestResults = append(result.TestResults, TestResult{
							Payload:     payload,
							URL:         testURL.String(),
							Method:      "GET",
							Parameter:   paramName,
							Description: fmt.Sprintf("Potential SQL Injection: Error pattern '%s' detected", pattern),
							Severity:    SeverityCritical,
						})
						break
					}
				}

				// Check for significant differences in response (could indicate blind SQLi)
				// Using float calculations to avoid truncation warnings
				baselineLen := float64(len(baselineContent))
				responseLen := float64(len(bodyStr))
				if resp.StatusCode != baselineResp.StatusCode &&
					(responseLen < baselineLen*0.8 || responseLen > baselineLen*1.2) {
					result.TestResults = append(result.TestResults, TestResult{
						Payload:     payload,
						URL:         testURL.String(),
						Method:      "GET",
						Parameter:   paramName,
						Description: "Potential Blind SQL Injection: Response significantly different from baseline",
						Severity:    SeverityHigh,
					})
				}

				// Reset parameter to original value
				params.Set(paramName, normalValue)
			}
		}
	}

	if len(result.TestResults) > 0 {
		s.addResult(result)
	}
}

// testFileInclusion tests for File Inclusion vulnerabilities
func (s *Scanner) testFileInclusion(target ScanTarget) {
	payloads := s.payloads.GetPayloads(VulnTypeFileInclusion)
	result := ScanResult{
		VulnerabilityType: VulnTypeFileInclusion,
		TestResults:       make([]TestResult, 0),
	}

	// Test URL parameters
	if targetURL, err := url.Parse(target.URL); err == nil {
		params := targetURL.Query()

		// Add a test parameter if none exist
		if len(params) == 0 {
			params.Add("page", "index")
		}

		// Check for parameters that might be vulnerable to LFI/RFI
		suspectParams := []string{"page", "file", "path", "include", "require", "doc", "document", "img", "src"}

		// Test each parameter
		for paramName := range params {
			// Prioritize suspicious parameter names
			isSuspect := false
			for _, suspect := range suspectParams {
				if strings.Contains(strings.ToLower(paramName), suspect) {
					isSuspect = true
					break
				}
			}

			if !isSuspect && !s.ScanOptions.TestAllParams {
				continue
			}

			// Test with file inclusion payloads
			for _, payload := range payloads {
				// Create a copy of the parameters and modify the test parameter
				testParams := url.Values{}
				for k, v := range params {
					testParams[k] = v
				}
				testParams.Set(paramName, payload.Value)

				// Construct test URL
				testURL := *targetURL
				testURL.RawQuery = testParams.Encode()

				// Send request
				resp, err := s.sendRequest(target, "GET", testURL.String(), nil, "")
				if err != nil {
					continue
				}

				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}

				bodyStr := string(body)

				// Check for file content patterns
				fileContentPatterns := map[string][]string{
					"../../../../../etc/passwd":            {"root:", "nobody:", "/bin/", "/home/"},
					"/etc/passwd":                          {"root:", "nobody:", "/bin/", "/home/"},
					"..\\..\\..\\..\\..\\windows\\win.ini": {"[extensions]", "[fonts]", "[mci extensions]"},
				}

				if patterns, exists := fileContentPatterns[payload.Value]; exists {
					for _, pattern := range patterns {
						if strings.Contains(bodyStr, pattern) {
							result.TestResults = append(result.TestResults, TestResult{
								Payload:     payload,
								URL:         testURL.String(),
								Method:      "GET",
								Parameter:   paramName,
								Description: fmt.Sprintf("File Inclusion Vulnerability: Found pattern '%s' in response", pattern),
								Severity:    SeverityCritical,
							})
							break
						}
					}
				}
			}
		}
	}

	if len(result.TestResults) > 0 {
		s.addResult(result)
	}
}

// testCSRF tests for CSRF vulnerabilities
func (s *Scanner) testCSRF(target ScanTarget) {
	result := ScanResult{
		VulnerabilityType: VulnTypeCSRF,
		TestResults:       make([]TestResult, 0),
	}

	// Get an initial response to check for CSRF protections
	resp, err := s.sendRequest(target, "GET", "", nil, "")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check for CSRF tokens in forms
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyStr := string(body)

	// Basic check: look for form without CSRF token
	if strings.Contains(bodyStr, "<form") &&
		!strings.Contains(strings.ToLower(bodyStr), "csrf") &&
		!strings.Contains(strings.ToLower(bodyStr), "token") {
		result.TestResults = append(result.TestResults, TestResult{
			URL:         target.URL,
			Method:      "GET",
			Description: "Potential CSRF vulnerability: Form found without CSRF token",
			Severity:    SeverityMedium,
		})
	}

	// Check for CSRF protection headers
	csrfHeaders := []string{
		"X-CSRF-Token",
		"X-CSRFToken",
		"X-XSRF-TOKEN",
		"CSRF-Token",
	}

	hasCSRFHeader := false
	for _, header := range csrfHeaders {
		if _, exists := resp.Header[header]; exists {
			hasCSRFHeader = true
			break
		}
	}

	if !hasCSRFHeader && len(result.TestResults) == 0 {
		// Send request with modified Origin/Referer to test CSRF protection
		headers := map[string]string{
			"Origin":  "https://attacker.example.com",
			"Referer": "https://attacker.example.com",
		}

		testResp, err := s.sendRequest(target, "GET", "", headers, "")
		if err == nil {
			defer testResp.Body.Close()

			// If the server accepts requests with modified Origin/Referer, it might be vulnerable
			if testResp.StatusCode == 200 {
				result.TestResults = append(result.TestResults, TestResult{
					URL:         target.URL,
					Method:      "GET",
					Description: "Potential CSRF vulnerability: Server accepts requests with modified Origin/Referer headers",
					Severity:    SeverityMedium,
				})
			}
		}
	}

	if len(result.TestResults) > 0 {
		s.addResult(result)
	}
}

// testMisconfigurations tests for security misconfigurations
func (s *Scanner) testMisconfigurations(target ScanTarget) {
	payloads := s.payloads.GetPayloads(VulnTypeMisconfiguration)
	result := ScanResult{
		VulnerabilityType: VulnTypeMisconfiguration,
		TestResults:       make([]TestResult, 0),
	}

	// Check security headers
	resp, err := s.sendRequest(target, "GET", "", nil, "")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check for missing security headers
	securityHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "",
		"Content-Security-Policy":   "",
		"X-XSS-Protection":          "",
		"Strict-Transport-Security": "",
	}

	for header, recommended := range securityHeaders {
		headerValue := resp.Header.Get(header)
		if headerValue == "" {
			result.TestResults = append(result.TestResults, TestResult{
				URL:         target.URL,
				Method:      "GET",
				Description: fmt.Sprintf("Missing security header: %s", header),
				Severity:    SeverityMedium,
			})
		} else if recommended != "" && !strings.Contains(headerValue, recommended) {
			result.TestResults = append(result.TestResults, TestResult{
				URL:         target.URL,
				Method:      "GET",
				Description: fmt.Sprintf("Misconfigured security header: %s (Value: %s, Recommended: %s)", header, headerValue, recommended),
				Severity:    SeverityLow,
			})
		}
	}

	// Check for misconfigurations in common paths
	for _, payload := range payloads {
		// Only test paths - skip header checks which we already did
		if !strings.HasPrefix(payload.Value, "/") && !strings.Contains(payload.Value, ":") {
			continue
		}

		resp, err := s.sendRequest(target, "GET", payload.Value, nil, "")
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Check for successful responses to sensitive paths
		if resp.StatusCode == 200 && len(body) > 0 {
			result.TestResults = append(result.TestResults, TestResult{
				Payload:     payload,
				URL:         target.URL + payload.Value,
				Method:      "GET",
				Description: fmt.Sprintf("Potential security misconfiguration: %s", payload.Description),
				Severity:    SeverityHigh,
			})
		}
	}

	if len(result.TestResults) > 0 {
		s.addResult(result)
	}
}

// testAuthWeaknesses tests for authentication weaknesses
func (s *Scanner) testAuthWeaknesses(target ScanTarget) {
	// Only proceed if login testing is explicitly enabled and login URL is provided
	if !s.ScanOptions.EnableAuthTesting || s.ScanOptions.LoginURL == "" {
		return
	}

	payloads := s.payloads.GetPayloads(VulnTypeAuthWeak)
	result := ScanResult{
		VulnerabilityType: VulnTypeAuthWeak,
		TestResults:       make([]TestResult, 0),
	}

	// Test for weak credentials if username and password fields are provided
	if s.ScanOptions.UsernameField != "" && s.ScanOptions.PasswordField != "" {
		for _, payload := range payloads {
			// Skip special test cases in basic credential testing
			if !strings.Contains(payload.Value, ":") {
				continue
			}

			// Split credential payload
			parts := strings.SplitN(payload.Value, ":", 2)
			if len(parts) != 2 {
				continue
			}

			username, password := parts[0], parts[1]

			// Create form data
			formData := url.Values{}
			formData.Set(s.ScanOptions.UsernameField, username)
			formData.Set(s.ScanOptions.PasswordField, password)

			// Send login request
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}

			resp, err := s.sendRequest(target, "POST", s.ScanOptions.LoginURL, headers, formData.Encode())
			if err != nil {
				continue
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			bodyStr := string(body)

			// Check for successful login
			loginSuccess := false

			// Check for redirect to dashboard or admin area
			if resp.StatusCode == 302 {
				location := resp.Header.Get("Location")
				if location != "" && (strings.Contains(location, "dashboard") ||
					strings.Contains(location, "admin") ||
					strings.Contains(location, "account")) {
					loginSuccess = true
				}
			}

			// Check response body for success indicators
			successIndicators := []string{
				"welcome", "dashboard", "logged in", "success", "account", "profile",
			}

			for _, indicator := range successIndicators {
				if strings.Contains(strings.ToLower(bodyStr), indicator) {
					loginSuccess = true
					break
				}
			}

			// Check for absence of login form or error messages
			if !strings.Contains(strings.ToLower(bodyStr), "login") &&
				!strings.Contains(strings.ToLower(bodyStr), "password") &&
				!strings.Contains(strings.ToLower(bodyStr), "error") &&
				!strings.Contains(strings.ToLower(bodyStr), "invalid") {
				loginSuccess = true
			}

			if loginSuccess {
				result.TestResults = append(result.TestResults, TestResult{
					Payload:     payload,
					URL:         target.URL + s.ScanOptions.LoginURL,
					Method:      "POST",
					Description: fmt.Sprintf("Weak credentials vulnerability: Successful login with %s:%s", username, password),
					Severity:    SeverityCritical,
				})
			}
		}
	}

	// Test for brute force protection
	if s.ScanOptions.BruteForceTest {
		// Implement brute force protection test here
		// This would involve sending multiple login attempts with incorrect credentials
		// and checking if the account gets locked or if there are rate limits
	}

	if len(result.TestResults) > 0 {
		s.addResult(result)
	}
}
