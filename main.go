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
		mainMenu()
		return
	}

	switch choice {
	case 1:
		utils.ClearScreen()
		displayToolBanner("portscanner")
		// Use the properly exported function from the pkg package
		err := pkg.RunNmapScannerWithPrivCheck()
		if err != nil {
			fmt.Println("Error:", err)
			fmt.Println("\nPress ESC to return to main menu...")
			utils.WaitForKeyPress(tcell.KeyEscape)
			utils.ClearScreen()
			mainMenu()
			return
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu() // Return to main menu after tool completes
	case 2:
		utils.ClearScreen()
		displayToolBanner("subdomainscanner")
		// Run subdomain scanner
		if err := pkg.RunSubdomainScannerWithCheck(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 3:
		utils.ClearScreen()
		displayToolBanner("osint")
		// Run OSINT tool
		if err := pkg.RunOSINTTool(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 4:
		utils.ClearScreen()
		displayToolBanner("webvuln")
		// Call the web vulnerability scanner
		if err := pkg.RunWebVulnScanner(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 5:
		utils.ClearScreen()
		displayToolBanner("s3scanner")
		// Call the S3 bucket scanner
		if err := tools.RunS3Scanner(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 6:
		utils.ClearScreen()
		displayToolBanner("emailharvester")
		// Call the email harvester
		if err := tools.RunEmailHarvester(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 7:
		utils.ClearScreen()
		displayToolBanner("dirbruteforcer")
		// Call the directory bruteforcer
		if err := tools.RunDirBruteforcer(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 8:
		utils.ClearScreen()
		displayToolBanner("reportgenerator")
		// Call the report generator
		if err := tools.RunReportingTools(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 9:
		utils.ClearScreen()
		displayToolBanner("hostresolver")
		// Run host & subdomain resolver
		if err := pkg.RunHostResolver(); err != nil {
			fmt.Println("Error:", err)
		}
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 10:
		utils.ClearScreen()
		displayToolBanner("dependencycheck")
		// Run dependency check
		pkg.PrintDependencyStatus()
		// Wait for ESC key to return to main menu
		fmt.Println("\nPress ESC to return to main menu...")
		utils.WaitForKeyPress(tcell.KeyEscape)
		utils.ClearScreen()
		mainMenu()
	case 11:
		fmt.Println("Exiting GopherStrike. Goodbye!")
		os.Exit(0)
	default:
		fmt.Println("Invalid choice. Please try again.")
		utils.ClearScreen()
		mainMenu()
	}
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
