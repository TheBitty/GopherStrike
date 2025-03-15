// Package pkg pkg/weblink.go
package pkg

import (
	"GopherStrike/pkg/tools/webvuln"
	"fmt"
)

// RunWebVulnScanner runs the web vulnerability scanner
func RunWebVulnScanner() error {
	fmt.Println("\n== GopherStrike Web Vulnerability Scanner ==")
	return webvuln.RunWebVulnScanner()
}
