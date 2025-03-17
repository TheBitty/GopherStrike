// Package testing pkg/testing/framework.go
package testing

import (
	"net/http"
	"net/http/httptest"
	_ "os"
	"time"
)

// TestServer represents a test server for integration testing
type TestServer struct {
	Server         *httptest.Server
	ResponseMap    map[string]TestResponse
	RequestLog     []TestRequest
	RequestHandler func(w http.ResponseWriter, r *http.Request)
}

// TestResponse represents a predefined response for the test server
type TestResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// TestRequest represents a logged request to the test server
type TestRequest struct {
	Method  string
	Path    string
	Headers map[string][]string
	Body    []byte
}

// NewTestServer creates a new test server with default settings

// Close closes the test server
func (ts *TestServer) Close() {
	if ts.Server != nil {
		ts.Server.Close()
	}
}

// AddResponse adds a predefined response for a path
func (ts *TestServer) AddResponse(path string, statusCode int, body string, headers map[string]string) {
	ts.ResponseMap[path] = TestResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}
}

// URL returns the URL of the test server
func (ts *TestServer) URL() string {
	return ts.Server.URL
}

// MockVulnerabilityService implements a mock vulnerability database
type MockVulnerabilityService struct {
	Vulnerabilities map[string][]string // Maps vulnerability IDs to CVEs
	Updates         int                 // Number of times the database was updated
	LastUpdateTime  time.Time           // Last time the database was updated
}

// NewMockVulnerabilityService creates a new mock vulnerability service

// AddVulnerability adds a vulnerability to the mock service
func (m *MockVulnerabilityService) AddVulnerability(id string, cves []string) {
	m.Vulnerabilities[id] = cves
}

// UpdateDatabase simulates updating the vulnerability database
func (m *MockVulnerabilityService) UpdateDatabase() error {
	m.Updates++
	m.LastUpdateTime = time.Now()
	return nil
}

// GetVulnerability returns info about a specific vulnerability
func (m *MockVulnerabilityService) GetVulnerability(id string) ([]string, bool) {
	cves, found := m.Vulnerabilities[id]
	return cves, found
}

// CreateTempDir creates a temporary directory for testing

// CreateTempFile creates a temporary file with the given content

// CleanupTemp removes a temp directory and all its contents

// GetFreePort finds an available port for testing

// RunWithTimeout runs a function with a timeout
