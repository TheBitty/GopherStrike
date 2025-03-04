// Package pkg nmapScannerLogic.go
package pkg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func checkRoot() bool {
	// On Unix-like systems, root has UID 0
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		return false
	}
	return true
}

func runNmapScannerWithPrivCheck() error {
	if !checkRoot() {
		if runtime.GOOS == "darwin" {
			// Get the path to the Python in the virtual environment
			venvPythonPath := "./.venv/bin/python3"
			_, err := os.Stat(venvPythonPath)
			if err == nil {
				// Virtual env Python exists, use it
				scriptPath, err := filepath.Abs("pkg/tools/NmapScript.py")
				if err != nil {
					return fmt.Errorf("error getting script path: %w", err)
				}

				// Get IP target first since osascript won't pass stdin
				fmt.Print("Enter target IP: ")
				var targetIP string
				fmt.Scanln(&targetIP)

				// Get port range
				fmt.Println("\nSelect port range:")
				fmt.Println("1. Common ports (1-1024)")
				fmt.Println("2. Extended range (1-5000)")
				fmt.Println("3. Full range (1-65535)")
				fmt.Println("4. Custom range")
				fmt.Print("\nEnter choice (1-4): ")
				var portChoice string
				fmt.Scanln(&portChoice)

				var portArgs string
				if portChoice == "4" {
					fmt.Print("Enter start port: ")
					var startPort string
					fmt.Scanln(&startPort)

					fmt.Print("Enter end port: ")
					var endPort string
					fmt.Scanln(&endPort)

					portArgs = fmt.Sprintf("--port-range %s %s", startPort, endPort)
				} else {
					portArgs = fmt.Sprintf("--port-choice %s", portChoice)
				}

				fmt.Println("Launching with admin privileges using virtual environment...")
				absVenvPath, _ := filepath.Abs(venvPythonPath)
				// Create logs directory in advance to avoid permission issues
				os.MkdirAll("logs", 0755)

				cmd := exec.Command("osascript", "-e",
					fmt.Sprintf(`do shell script "%s %s --target %s %s" with administrator privileges`,
						absVenvPath, scriptPath, targetIP, portArgs))
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr

				if err := cmd.Run(); err != nil {
					return fmt.Errorf("error running with admin privileges: %w", err)
				}

				// Show the scan results after the scan completes
				summaryFile := fmt.Sprintf("logs/lastscan_%s.txt", targetIP)
				if _, err := os.Stat(summaryFile); err == nil {
					fmt.Println("\nScan Results:")
					fmt.Println("=============")

					data, err := os.ReadFile(summaryFile)
					if err != nil {
						fmt.Printf("Error reading scan results: %v\n", err)
					} else {
						fmt.Println(string(data))
					}
				}

				return nil
			}

			// Fallback to system Python if venv not found
			scriptPath, err := filepath.Abs("pkg/tools/NmapScript.py")
			if err != nil {
				return fmt.Errorf("error getting absolute path: %w", err)
			}

			fmt.Println("Launching with admin privileges...")
			cmd := exec.Command("osascript", "-e", fmt.Sprintf(`do shell script "python3 %s" with administrator privileges`, scriptPath))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			err = cmd.Run()
			if err != nil {
				// Provide specific advice for common errors
				if strings.Contains(err.Error(), "No module named") {
					fmt.Println("\nMissing Python dependencies. Please install them with:")
					fmt.Println("sudo pip3 install python-nmap scapy")
					return fmt.Errorf("missing dependencies: %w", err)
				}
				return fmt.Errorf("error running with admin privileges: %w", err)
			}
			return nil
		} else if runtime.GOOS == "linux" {
			// Try pkexec first on Linux
			if _, err := exec.LookPath("pkexec"); err == nil {
				scriptPath, err := filepath.Abs("pkg/tools/NmapScript.py")
				if err != nil {
					return fmt.Errorf("error getting absolute path: %w", err)
				}

				venvPythonPath := "./.venv/bin/python3"
				pythonPath := "python3"
				if _, err := os.Stat(venvPythonPath); err == nil {
					absVenvPath, _ := filepath.Abs(venvPythonPath)
					pythonPath = absVenvPath
				}

				fmt.Println("Launching with admin privileges...")
				cmd := exec.Command("pkexec", pythonPath, scriptPath)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Stdin = os.Stdin

				if err := cmd.Run(); err != nil {
					return fmt.Errorf("error running with pkexec: %w", err)
				}
				return nil
			}

			// Fallback to terminal sudo method
			fmt.Println("Please run from terminal: sudo go run main.go")
			return fmt.Errorf("cannot elevate privileges in this environment")
		} else {
			// Other OS implementations...
			fmt.Println("Please run from terminal: sudo go run main.go")
			return fmt.Errorf("cannot elevate privileges in this environment")
		}
	}

	// We have root already, check for venv first
	venvPythonPath := "./.venv/bin/python3"
	pythonToUse := "python3"

	if _, err := os.Stat(venvPythonPath); err == nil {
		absVenvPath, _ := filepath.Abs(venvPythonPath)
		pythonToUse = absVenvPath
		fmt.Println("Using Python from virtual environment")
	}

	// Create logs directory in advance to avoid permission issues
	os.MkdirAll("logs", 0755)

	// Get working directory to ensure correct path resolution
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting working directory: %w", err)
	}

	// For Darwin/macOS, use a temporary script to run with sudo
	if runtime.GOOS == "darwin" {
		// Create a temporary script that will run the Python script with the correct environment
		tempScript := filepath.Join(workDir, "run_scanner.sh")
		scriptContent := fmt.Sprintf(`#!/bin/bash
cd "%s"
%s "%s" "$@"
`, workDir, pythonToUse, "pkg/tools/NmapScript.py")

		if err := os.WriteFile(tempScript, []byte(scriptContent), 0755); err != nil {
			return fmt.Errorf("error creating temporary script: %w", err)
		}
		defer func(name string) {
			err := os.Remove(name)
			if err != nil {

			}
		}(tempScript)

		// Run the script with sudo
		cmd := exec.Command("sudo", tempScript)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error running port scanner: %w", err)
		}
	} else {
		// For other platforms, run directly
		cmd := exec.Command(pythonToUse, "pkg/tools/NmapScript.py")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error running port scanner: %w", err)
		}
	}

	return nil
}
