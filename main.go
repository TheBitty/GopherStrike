package main

import (
	"GopherStrike/pkg" // Import the pkg package to access exported functions
	"GopherStrike/pkg/tools"
	"GopherStrike/utils"
	"fmt"
	"os"
)

// displayBanner prints the GopherStrike ASCII art banner
func displayBanner() {
	banner := `
    ██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗██████╗ ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ██╔════╝ ██╔═══██╗██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ██║  ███╗██║   ██║██████╔╝███████║█████╗  ██████╔╝███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
    ██║   ██║██║   ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ╚██████╔╝╚██████╔╝██║     ██║  ██║███████╗██║  ██║███████║   ██║   ██║  ██║██║██║  ██╗███████╗
     ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
    `
	fmt.Println(banner)
}

// mainMenu displays and handles the main application menu
func mainMenu() {
	displayBanner() // this will have to get changed around
	fmt.Println("\nAvailable Tools:")
	fmt.Println("================")
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
	fmt.Scanln() // Consume the newline

	if err != nil {
		fmt.Println("Invalid choice. Please try again.")
		utils.ClearScreen()
		mainMenu()
		return
	}

	switch choice {
	case 1:
		// Use the properly exported function from the pkg package
		if err := pkg.RunNmapScannerWithPrivCheck(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln() // Ignoring error here is fine for user interaction
		utils.ClearScreen()
		mainMenu() // Return to main menu after tool completes
	case 2:
		// Run subdomain scanner
		if err := pkg.RunSubdomainScannerWithCheck(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 3:
		// Run OSINT tool
		if err := pkg.RunOSINTTool(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 4:
		// Call the web vulnerability scanner
		if err := pkg.RunWebVulnScanner(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 5:
		// Call the S3 bucket scanner
		if err := tools.RunS3Scanner(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 6:
		// Call the email harvester
		if err := tools.RunEmailHarvester(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 7:
		// Call the directory bruteforcer
		if err := tools.RunDirBruteforcer(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 8:
		// Call the report generator
		if err := tools.RunReportingTools(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 9:
		// Run host & subdomain resolver
		if err := pkg.RunHostResolver(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
		utils.ClearScreen()
		mainMenu()
	case 10:
		// Run dependency check
		pkg.PrintDependencyStatus()
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln()
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
