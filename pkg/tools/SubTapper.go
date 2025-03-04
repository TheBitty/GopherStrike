// Package tools here we go IDK why I don't steal someone's else's code
// SubTapper.go
package tools

// SubdomainResult represents a single subdomain scan result
type SubdomainResult struct {
	Name   string   `json:"name"`
	IPs    []string `json:"ips,omitempty"`
	Active bool     `json:"active"`
	TimeMs int64    `json:"time_ms"`
}
