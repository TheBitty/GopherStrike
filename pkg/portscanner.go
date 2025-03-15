package pkg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// RunNmapScannerWithPrivCheck runs the existing Python nmap scanner script
// Returns nil for exit code 2 (admin privileges required) to prevent menu exit
func RunNmapScannerWithPrivCheck() error {
	// Path to the existing Python script
	scriptPath := filepath.Join("pkg", "tools", "NmapScript.py")

	// Check if the script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("nmap script not found at %s", scriptPath)
	}

	// Determine Python command based on OS
	pythonCmd := "python3"
	if runtime.GOOS == "windows" {
		pythonCmd = "python"
	}

	// Create the command that runs your Python script
	cmd := exec.Command(pythonCmd, scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Run the command (your Python script)
	err := cmd.Run()

	// Special handling for exit code 2 (admin privileges required)
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
		fmt.Println("\nAdmin privileges required for full port scanning functionality.")
		fmt.Println("Some features may be limited without proper permissions.")
		return nil // Don't propagate this as an error so we can return to menu
	}

	return err
}
