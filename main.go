package main

import (
	"GopherStrike/utils"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

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

func mainMenu() {
	displayBanner()
	fmt.Println("\nAvailable Tools:")
	fmt.Println("================")
	fmt.Println("1. Port Scanner")
	fmt.Println("2. Exit")

	var choice string
	fmt.Print("\nSelect a tool: ")
	if _, err := fmt.Scanln(&choice); err != nil {
		fmt.Println("Error reading input:", err)
		utils.ClearScreen()
		mainMenu()
		return
	}

	switch choice {
	case "1":
		if err := runNmapScannerWithPrivCheck(); err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("\nPress Enter to continue...")
		fmt.Scanln() // Ignoring error here is fine
		utils.ClearScreen()
		mainMenu() // Return to main menu after tool completes
	case "2":
		fmt.Println("Exiting GopherStrike. Goodbye!")
		os.Exit(0)
	default:
		fmt.Println("Invalid choice, please try again")
		utils.ClearScreen()
		mainMenu()
	}
}

func main() {
	utils.ClearScreen() // clears the screen for the UI
	mainMenu()
}
