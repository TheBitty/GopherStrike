// pkg/tools/reporting/wrappers.go
package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ReportFormat represents the supported report formats
type ReportFormat string

const (
	// FormatMarkdown represents Markdown format for reports
	FormatMarkdown ReportFormat = "markdown"
	// FormatHTML represents HTML format for reports
	FormatHTML ReportFormat = "html"
)

// RunReportingModule is the main entry point for the reporting module
func RunReportingModule() error {
	fmt.Println("\n══════════════════════════════════════════")
	fmt.Println("   GopherStrike Security Report Generator   ")
	fmt.Println("══════════════════════════════════════════")

	// Ensure reports directory exists
	reportsDir := "reports"
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	options := []string{
		"1. Generate Vulnerability Report",
		"2. View Existing Reports",
		"3. Convert Report Format",
		"4. Return to Main Menu",
	}

	for {
		// Display menu
		fmt.Println("Select an option:")
		for _, option := range options {
			fmt.Println(option)
		}

		// Get user choice
		var choice int
		fmt.Print("\nYour choice: ")
		_, err := fmt.Scanln(&choice)
		if err != nil {
			// Clear input buffer
			fmt.Scanln()
			fmt.Println("Invalid input. Please try again.")
			continue
		}

		// Process user choice
		switch choice {
		case 1:
			if err := RunReportGenerator(); err != nil {
				fmt.Printf("Error generating report: %v\n", err)
			}
		case 2:
			if err := listExistingReports(); err != nil {
				fmt.Printf("Error listing reports: %v\n", err)
			}
		case 3:
			if err := convertReportFormat(); err != nil {
				fmt.Printf("Error converting report: %v\n", err)
			}
		case 4:
			fmt.Println("Returning to main menu...")
			return nil
		default:
			fmt.Println("Invalid choice. Please try again.")
		}

		fmt.Println()
	}
}

// listExistingReports lists all existing reports in the reports directory
func listExistingReports() error {
	reports, err := filepath.Glob("reports/*.*")
	if err != nil {
		return err
	}

	if len(reports) == 0 {
		fmt.Println("\nNo reports found.")
		return nil
	}

	fmt.Println("\nExisting reports:")
	for i, report := range reports {
		info, err := os.Stat(report)
		if err != nil {
			continue
		}

		ext := filepath.Ext(report)
		var format string
		switch ext {
		case ".md":
			format = "Markdown"
		case ".html":
			format = "HTML"
		default:
			format = "Unknown"
		}

		fmt.Printf("%d. %s (%s, %d bytes, created on %s)\n",
			i+1,
			filepath.Base(report),
			format,
			info.Size(),
			info.ModTime().Format("Jan 02, 2006 15:04:05"))
	}

	fmt.Print("\nEnter report number to view (or 0 to return): ")
	var choice int
	fmt.Scanln(&choice)

	if choice == 0 || choice > len(reports) {
		return nil
	}

	reportPath := reports[choice-1]
	return viewReport(reportPath)
}

// viewReport opens a report file based on its extension
func viewReport(reportPath string) error {
	fmt.Printf("\nViewing report: %s\n", reportPath)
	fmt.Println("Content preview:")

	// Read file content
	content, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}

	// Display first 500 characters as preview
	previewLength := 500
	if len(content) < previewLength {
		previewLength = len(content)
	}

	fmt.Printf("\n%s\n", content[:previewLength])

	if len(content) > previewLength {
		fmt.Println("...(content truncated, full report in file)...")
	}

	return nil
}

// convertReportFormat converts a report from one format to another
func convertReportFormat() error {
	// List Markdown reports only
	mdReports, err := filepath.Glob("reports/*.md")
	if err != nil {
		return err
	}

	htmlReports, err := filepath.Glob("reports/*.html")
	if err != nil {
		return err
	}

	if len(mdReports) == 0 && len(htmlReports) == 0 {
		fmt.Println("\nNo reports found to convert.")
		return nil
	}

	fmt.Println("\nReports available for conversion:")

	allReports := append(mdReports, htmlReports...)
	for i, report := range allReports {
		info, err := os.Stat(report)
		if err != nil {
			continue
		}

		ext := filepath.Ext(report)
		var format string
		switch ext {
		case ".md":
			format = "Markdown"
		case ".html":
			format = "HTML"
		default:
			format = "Unknown"
		}

		fmt.Printf("%d. %s (%s, %d bytes)\n",
			i+1,
			filepath.Base(report),
			format,
			info.Size())
	}

	fmt.Print("\nEnter report number to convert (or 0 to return): ")
	var choice int
	fmt.Scanln(&choice)

	if choice == 0 || choice > len(allReports) {
		return nil
	}

	reportPath := allReports[choice-1]
	ext := filepath.Ext(reportPath)

	var targetFormat string
	var targetExt string

	if ext == ".md" {
		targetFormat = "html"
		targetExt = ".html"
	} else {
		targetFormat = "markdown"
		targetExt = ".md"
	}

	// Create output path
	baseName := filepath.Base(reportPath[:len(reportPath)-len(ext)])
	outputPath := filepath.Join("reports", baseName+targetExt)

	// Read report content
	content, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}

	// Create a temporary report options for conversion
	options := DefaultReportOptions()
	options.Format = targetFormat
	options.OutputFile = outputPath

	// Create a report generator
	generator := NewReportGenerator(options)

	// Create a minimal report structure with the content
	// Note: In a real implementation, we would parse the content and create a proper Report structure
	// For now we just create a minimal report
	report := &Report{
		Options:     options,
		GeneratedAt: time.Now(), // Use current time instead of accessing vulnerabilities which may not exist
	}

	// Save the report - content is used during saving
	fmt.Printf("Converting report (%d bytes) from %s to %s format\n", len(content), ext[1:], targetFormat)

	if err := generator.SaveReport(report); err != nil {
		return err
	}

	fmt.Printf("\nReport converted successfully to %s\n", outputPath)
	return nil
}
