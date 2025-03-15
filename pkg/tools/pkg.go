// Package tools pkg/tools/pkg.go
package tools

import (
	"fmt"
	"os"
	"path/filepath"

	"GopherStrike/pkg/tools/discovery/dirbruteforce"
	"GopherStrike/pkg/tools/recon/emailharvester"
	"GopherStrike/pkg/tools/recon/s3scanner"
	"GopherStrike/pkg/tools/reporting"
)

// RunReportingTools runs the report generation tools
func RunReportingTools() error {
	fmt.Println("\n[+] Report Generation Tools")
	fmt.Println("    =====================")

	// Create reports directory if it doesn't exist
	if err := os.MkdirAll("reports", 0755); err != nil {
		fmt.Printf("[-] Error creating reports directory: %v\n", err)
		return err
	}

	// Run the reporting module
	if err := reporting.RunReportingModule(); err != nil {
		fmt.Printf("[-] Error running reporting module: %v\n", err)
		return err
	}

	return nil
}

// RunS3Scanner runs the S3 bucket scanner tool
func RunS3Scanner() error {
	fmt.Println("\n[+] S3 Bucket Scanner")
	fmt.Println("    ===============")

	// Create logs directory for S3 scanner
	logDir := filepath.Join("logs", "s3scanner")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("[-] Error creating log directory: %v\n", err)
		return err
	}

	// Run the S3 bucket scanner
	if err := s3scanner.RunS3BucketScanner(); err != nil {
		fmt.Printf("[-] Error running S3 bucket scanner: %v\n", err)
		return err
	}

	return nil
}

// RunEmailHarvester runs the email harvester tool
func RunEmailHarvester() error {
	fmt.Println("\n[+] Email Harvester")
	fmt.Println("    ==============")

	// Create logs directory for email harvester
	logDir := filepath.Join("logs", "emailharvester")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("[-] Error creating log directory: %v\n", err)
		return err
	}

	// Run the email harvester
	if err := emailharvester.RunEmailHarvester(); err != nil {
		fmt.Printf("[-] Error running email harvester: %v\n", err)
		return err
	}

	return nil
}

// RunDirBruteforcer runs the directory bruteforcing tool
func RunDirBruteforcer() error {
	fmt.Println("\n[+] Directory Bruteforcing Tool")
	fmt.Println("    ========================")

	// Create logs directory for directory bruteforcer
	logDir := filepath.Join("logs", "dirbruteforce")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("[-] Error creating log directory: %v\n", err)
		return err
	}

	// Run the directory bruteforcer
	if err := dirbruteforce.RunDirBruteforce(); err != nil {
		fmt.Printf("[-] Error running directory bruteforcer: %v\n", err)
		return err
	}

	return nil
}
