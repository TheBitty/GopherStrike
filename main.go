package main

import (
	"GopherStrike/pkg" // Import the pkg package to access exported functions
	"GopherStrike/pkg/tools"
	"GopherStrike/utils"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gdamore/tcell/v2"
)

// displayBanner prints the GopherStrike ASCII art banner
func displayBanner() {
	// Use the utils.GetBanner function to get the main banner
	fmt.Println(utils.GetBanner("main"))
}

// displayToolBanner prints the ASCII art banner for a specific tool
func displayToolBanner(tool string) {
	banner := utils.GetBanner(tool)
	if banner != "" {
		fmt.Println(banner)
	}
}

// mainMenu displays and handles the main application menu
func mainMenu() {
	for {
		// Display the menu
		displayBanner() // Display the main banner
		utils.Info("Welcome to GopherStrike - A comprehensive security toolkit")
		fmt.Println("\nAvailable Tools:")
		fmt.Println("===================================================================================================")
		fmt.Println("1. Port Scanner")
		fmt.Println("2. Subdomain Scanner")
		fmt.Println("3. OSINT & Vulnerability Tool")
		fmt.Println("4. Web Application Security Scanner")
		fmt.Println("5. S3 Bucket Scanner")
		fmt.Println("6. Email Harvester")
		fmt.Println("7. Directory Bruteforcer")
		fmt.Println("8. Report Generator")
		fmt.Println("9. Host & Subdomain Resolver")
		fmt.Println("10. Check Dependencies")
		fmt.Println("11. Exit")

		// Get user input
		fmt.Printf("\n%s: ", "Enter your choice")
		var choice int
		_, err := fmt.Scanf("%d", &choice)

		if err != nil {
			utils.Error("Invalid choice: %v", err)
			fmt.Println("Invalid choice. Please try again.")
			utils.ClearScreen()
			continue
		}

		// Execute the selected tool
		if !executeToolChoice(choice) {
			// Exit the loop if user selected exit
			break
		}

		// Clear the screen before showing the menu again
		utils.ClearScreen()
	}
}

// executeToolChoice handles the execution of the selected tool
// Returns false if the program should exit, true otherwise
func executeToolChoice(choice int) bool {
	switch choice {
	case 1:
		executeTool("portscanner", func() error {
			return pkg.RunNmapScannerWithPrivCheck()
		})
	case 2:
		executeTool("subdomainscanner", func() error {
			return pkg.RunSubdomainScannerWithCheck()
		})
	case 3:
		executeTool("osint", func() error {
			return pkg.RunOSINTTool()
		})
	case 4:
		executeTool("webvuln", func() error {
			return pkg.RunWebVulnScanner()
		})
	case 5:
		executeTool("s3scanner", func() error {
			return tools.RunS3Scanner()
		})
	case 6:
		executeTool("emailharvester", func() error {
			return tools.RunEmailHarvester()
		})
	case 7:
		executeTool("dirbruteforcer", func() error {
			return tools.RunDirBruteforcer()
		})
	case 8:
		executeTool("reportgenerator", func() error {
			return tools.RunReportingTools()
		})
	case 9:
		executeTool("hostresolver", func() error {
			return pkg.RunHostResolver()
		})
	case 10:
		executeTool("dependencycheck", func() error {
			pkg.PrintDependencyStatus()
			return nil
		})
	case 11:
		fmt.Println("Exiting GopherStrike. Goodbye!")
		return false
	default:
		fmt.Println("Invalid choice. Please try again.")
	}

	return true
}

// executeTool runs a tool with proper error handling and ESC key waiting
func executeTool(toolName string, toolFunc func() error) {
	utils.ClearScreen()
	displayToolBanner(toolName)

	// Log the tool execution
	utils.Debug("Executing tool: %s", toolName)

	// Show a minimal instruction
	fmt.Println("\nPress Ctrl+C at any time to return to main menu")

	// Start the interrupt listener (now only for Ctrl+C)
	interruptCh := utils.StartInterruptListener()

	// Run the tool in a separate goroutine
	resultCh := make(chan error, 1)
	toolDone := make(chan struct{})
	go func() {
		err := toolFunc()
		resultCh <- err
		close(toolDone)
	}()

	// Wait for either the tool to complete or an interrupt
	var err error
	interrupted := false
	select {
	case err = <-resultCh:
		// Tool completed normally
		if err != nil {
			utils.Error("Tool %s failed: %v", toolName, err)
		} else {
			utils.Debug("Tool %s completed successfully", toolName)
		}
	case <-interruptCh:
		// Tool was interrupted by Ctrl+C
		interrupted = true
		utils.Warn("Tool %s interrupted by user", toolName)
		// Wait for the tool to actually finish (after being killed)
		<-toolDone
	}

	// Stop the interrupt listener
	utils.StopInterruptListener()

	// Display error message if there was an error (and not interrupted)
	if err != nil && !interrupted {
		fmt.Println("\nError:", err)
	}

	// Brief message if interrupted
	if interrupted {
		fmt.Println("\nReturning to main menu...")
		// Brief pause
		time.Sleep(500 * time.Millisecond)
		return
	}

	// Wait for ESC key to return to main menu
	fmt.Println("\nPress ESC to return to main menu...")
	utils.WaitForKeyPress(tcell.KeyEscape)
}

// main is the entry point for the application
func main() {
	utils.ClearScreen() // clears the screen for the UI

	// Initialize configuration
	if err := utils.LoadConfig(); err != nil {
		fmt.Printf("Warning: Failed to load configuration: %v\n", err)
		fmt.Println("Using default configuration settings.")
	}

	// Initialize logger
	if err := utils.InitLogger(); err != nil {
		fmt.Printf("Warning: Failed to initialize logger: %v\n", err)
	}

	// Log startup information
	utils.Info("GopherStrike starting up...")
	utils.Debug("Configuration loaded successfully")

	// Create required directories based on configuration
	setupDirectories()

	// Use the text-based menu directly
	mainMenu()

	// Clean up resources
	utils.Info("GopherStrike shutting down...")
	utils.CloseLogger()
}

// setupDirectories creates necessary directories for logs and other data
func setupDirectories() {
	// Ensure logs directory exists
	logsDir := "logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		utils.Error("Failed to create logs directory: %v", err)
	}

	// Create tool-specific log directories
	toolDirs := []string{
		"osint", "resolver", "webvuln", "portscan",
		"subdomain", "s3", "email", "dirb", "reports",
	}

	for _, dir := range toolDirs {
		toolDir := filepath.Join(logsDir, dir)
		if err := os.MkdirAll(toolDir, 0755); err != nil {
			utils.Error("Failed to create %s logs directory: %v", dir, err)
		}
	}

	// Create reports directory if specified in config
	reportsDir := utils.Config.Tools.ReportingTools.OutputDir
	if reportsDir != "" {
		if err := os.MkdirAll(reportsDir, 0755); err != nil {
			utils.Error("Failed to create reports directory: %v", err)
		}
	}
}
