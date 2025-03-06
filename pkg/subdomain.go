package pkg

import (
	"GopherStrike/pkg/tools"
)

// RunSubdomainScannerWithCheck executes the subdomain scanner
func RunSubdomainScannerWithCheck() error {
	// Call the actual implementation from tools' package
	return tools.RunSubdomainScan()
}
