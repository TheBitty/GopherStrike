package main

import (
	"GopherStrike/pkg" // Import the pkg package to access exported functions
	"GopherStrike/pkg/tools"
	"GopherStrike/utils"
	"fmt"
	"os"

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

	// Run the tool and collect any error
	err := toolFunc()

	// Display error message if there was an error
	if err != nil {
		fmt.Println("\nError:", err)
	}

	// Only after the tool has finished running, wait for ESC key
	fmt.Println("\nPress ESC to return to main menu...")
	utils.WaitForKeyPress(tcell.KeyEscape)
}

// main is the entry point for the application
func main() {
	utils.ClearScreen() // clears the screen for the UI

	// Check for logs directory at startup
	if err := os.MkdirAll("logs", 0755); err != nil {
		fmt.Printf("Warning: Failed to create logs directory: %v\n", err)
	}

	// Create OSINT logs directory
	if err := os.MkdirAll("logs/osint", 0755); err != nil {
		fmt.Printf("Warning: Failed to create OSINT logs directory: %v\n", err)
	}

	// Create resolver logs directory
	if err := os.MkdirAll("logs/resolver", 0755); err != nil {
		fmt.Printf("Warning: Failed to create resolver logs directory: %v\n", err)
	}

	// Create webvuln logs directory
	if err := os.MkdirAll("logs/webvuln", 0755); err != nil {
		fmt.Printf("Warning: Failed to create webvuln logs directory: %v\n", err)
	}

	// Use the text-based menu directly
	mainMenu()
}
