package pkg

import (
	"GopherStrike/pkg/tools/subdomain"
)

// RunSubdomainScannerWithCheck executes the subdomain scanner
func RunSubdomainScannerWithCheck() error {
	return subdomain.RunScanner()
}
