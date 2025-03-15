package pkg

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

	// Check for python-nmap dependency
	if err := checkNmapDependency(); err != nil {
		return err
	}

	// Determine Python command based on OS and environment
	pythonCmd, err := findPythonInterpreter()
	if err != nil {
		return fmt.Errorf("could not find Python interpreter: %v", err)
	}

	// Create the command that runs your Python script
	cmd := exec.Command(pythonCmd, scriptPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Use a process group to ensure we can terminate all child processes
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Start the command
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nmap scanner: %v", err)
	}

	// Create a channel for signal propagation
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for the command to complete or for a signal
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for command completion or signal
	var cmdErr error
	select {
	case cmdErr = <-done:
		// Command completed normally
		signal.Stop(sigChan)
	case <-sigChan:
		// Received interrupt signal, kill the process group
		fmt.Println("\nScan interrupted by user. Exiting...")

		// Kill the process group
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
			// On Unix systems, negative PID means kill process group
			if runtime.GOOS != "windows" {
				syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				// Windows doesn't have process groups in the same way
				cmd.Process.Kill()
			}
		} else {
			// Fallback to just killing the process
			cmd.Process.Kill()
		}

		// Wait for process to exit
		cmdErr = <-done

		// Return a special error for interruption
		return fmt.Errorf("scan interrupted")
	}

	// Special handling for exit code 2 (admin privileges required)
	if exitErr, ok := cmdErr.(*exec.ExitError); ok {
		exitCode := exitErr.ExitCode()

		if exitCode == 2 {
			fmt.Println("\nAdmin privileges required for full port scanning functionality.")
			fmt.Println("Some features may be limited without proper permissions.")
			return nil // Don't propagate this as an error so we can return to menu
		} else if strings.Contains(exitErr.Error(), "No module named 'nmap'") {
			fmt.Println("\nError: Python module 'nmap' not found.")
			fmt.Println("Please install it with: pip install python-nmap")
			fmt.Println("\nWould you like to install it now? (y/n)")

			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))

			if response == "y" || response == "yes" {
				return installPythonNmap()
			}
		}
	}

	return cmdErr
}

// findPythonInterpreter locates a suitable Python interpreter
func findPythonInterpreter() (string, error) {
	// Check for active virtual environment
	if venvPath := os.Getenv("VIRTUAL_ENV"); venvPath != "" {
		// We're in an active virtual environment
		var pythonPath string
		if runtime.GOOS == "windows" {
			pythonPath = filepath.Join(venvPath, "Scripts", "python.exe")
		} else {
			pythonPath = filepath.Join(venvPath, "bin", "python")
		}

		if _, err := os.Stat(pythonPath); err == nil {
			return pythonPath, nil
		}
	}

	// Check for project's virtual environment
	venvPaths := []string{".venv", "venv", "env"}
	for _, venv := range venvPaths {
		var pythonBin string
		if runtime.GOOS == "windows" {
			pythonBin = filepath.Join(venv, "Scripts", "python.exe")
		} else {
			pythonBin = filepath.Join(venv, "bin", "python")
		}

		if absPath, err := filepath.Abs(pythonBin); err == nil {
			if _, err := os.Stat(absPath); err == nil {
				return absPath, nil
			}
		}
	}

	// Check for system Python interpreters
	pythonCommands := []string{"python3", "python"}
	for _, cmd := range pythonCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			return cmd, nil
		}
	}

	return "", fmt.Errorf("no Python interpreter found")
}

// checkNmapDependency checks if the python-nmap module is installed
func checkNmapDependency() error {
	// Find Python interpreter
	pythonCmd, err := findPythonInterpreter()
	if err != nil {
		return fmt.Errorf("Python interpreter not found: %v", err)
	}

	// Create a temporary check script
	tempFile, err := os.CreateTemp("", "check_nmap_*.py")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write a Python script that checks for the nmap module
	script := `
try:
    import nmap
    print("MODULE_FOUND")
except ImportError:
    print("MODULE_MISSING")
`
	if _, err := tempFile.Write([]byte(script)); err != nil {
		return fmt.Errorf("failed to write to temporary file: %v", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %v", err)
	}

	// Run the check script
	cmd := exec.Command(pythonCmd, tempFile.Name())
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to run dependency check: %v", err)
	}

	if strings.Contains(string(output), "MODULE_MISSING") {
		return fmt.Errorf("Python module 'nmap' not found. Please install it with: pip install python-nmap")
	}

	return nil
}

// installPythonNmap installs the python-nmap module
func installPythonNmap() error {
	fmt.Println("Installing python-nmap module...")

	// Find Python interpreter
	pythonCmd, err := findPythonInterpreter()
	if err != nil {
		return fmt.Errorf("Python interpreter not found: %v", err)
	}

	// Determine if we're in a virtual environment
	isVenv := os.Getenv("VIRTUAL_ENV") != "" ||
		strings.Contains(pythonCmd, ".venv") ||
		strings.Contains(pythonCmd, "venv") ||
		strings.Contains(pythonCmd, "env")

	// Determine pip command
	pipCmd := "pip3"
	if runtime.GOOS == "windows" {
		pipCmd = "pip"
	}

	// If in virtual environment, use that pip
	if isVenv {
		if runtime.GOOS == "windows" {
			pipCmd = strings.Replace(pythonCmd, "python.exe", "pip.exe", 1)
		} else {
			pipCmd = strings.Replace(pythonCmd, "python", "pip", 1)
		}
	}

	// Install the module
	cmd := exec.Command(pipCmd, "install", "python-nmap")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

	if err != nil {
		return fmt.Errorf("failed to install python-nmap: %v", err)
	}

	fmt.Println("✅ python-nmap installed successfully. Please run the port scanner again.")
	return nil
}
