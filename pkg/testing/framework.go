// pkg/testing/framework.go
package testing

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
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
func NewTestServer() *TestServer {
	ts := &TestServer{
		ResponseMap: make(map[string]TestResponse),
		RequestLog:  make([]TestRequest, 0),
	}

	ts.RequestHandler = func(w http.ResponseWriter, r *http.Request) {
		// Log the request
		path := r.URL.Path
		ts.RequestLog = append(ts.RequestLog, TestRequest{
			Method:  r.Method,
			Path:    path,
			Headers: r.Header,
			// Body is not captured for simplicity, but could be added
		})

		// Check if we have a predefined response for this path
		if response, ok := ts.ResponseMap[path]; ok {
			// Set headers
			for key, value := range response.Headers {
				w.Header().Set(key, value)
			}
			// Set status code
			w.WriteHeader(response.StatusCode)
			// Write body
			_, err := w.Write([]byte(response.Body))
			if err != nil {
				log.Printf("Error writing response: %v", err)
			}
			return
		}

		// Default response
		w.WriteHeader(http.StatusNotFound)
		_, respErr := w.Write([]byte("Not found"))
		if respErr != nil {
			log.Printf("Error writing response: %v", respErr)
		}
	}

	// Create the test server
	ts.Server = httptest.NewServer(http.HandlerFunc(ts.RequestHandler))
	return ts
}

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
func NewMockVulnerabilityService() *MockVulnerabilityService {
	return &MockVulnerabilityService{
		Vulnerabilities: make(map[string][]string),
		LastUpdateTime:  time.Now(),
	}
}

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
func CreateTempDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return dir
}

// CreateTempFile creates a temporary file with the given content
func CreateTempFile(t *testing.T, dir, prefix, content string) string {
	t.Helper()
	f, err := os.CreateTemp(dir, prefix)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer f.Close()

	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	return f.Name()
}

// CleanupTemp removes a temp directory and all its contents
func CleanupTemp(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Logf("Warning: Failed to clean up %s: %v", path, err)
	}
}

// GetFreePort finds an available port for testing
func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// RunWithTimeout runs a function with a timeout
func RunWithTimeout(t *testing.T, timeout time.Duration, f func() error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- f()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return fmt.Errorf("operation timed out after %v", timeout)
	}
}
