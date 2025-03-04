// Package pkg provides network scanning functionality and tools for the GopherStrike framework
package pkg

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// PythonEnvInfo stores information about the Python environment
type PythonEnvInfo struct {
	Interpreter string
	Version     string
	Path        string
	IsVenv      bool
}

// DependencyCheck verifies that all required dependencies are installed
// Returns a map of missing dependencies and installation instructions
func DependencyCheck() map[string]string {
	missing := make(map[string]string)

	// Get Python environment info
	pythonInfo := detectPythonEnvironment()

	// Only check for Python if no interpreter was found
	if pythonInfo.Interpreter == "" {
		if runtime.GOOS == "darwin" {
			missing["python3"] = "Install with: brew install python3"
		} else if runtime.GOOS == "linux" {
			missing["python3"] = "Install with: sudo apt install python3 python3-pip"
		} else if runtime.GOOS == "windows" {
			missing["python3"] = "Download and install from https://www.python.org/downloads/"
		}
	} else {
		fmt.Printf("Found Python: %s (version %s)\n", pythonInfo.Path, pythonInfo.Version)
		if pythonInfo.IsVenv {
			fmt.Println("Running in a virtual environment")
		}
	}

	// Check nmap
	if !checkCommandExists("nmap") {
		if runtime.GOOS == "darwin" {
			missing["nmap"] = "Install with: brew install nmap"
		} else if runtime.GOOS == "linux" {
			missing["nmap"] = "Install with: sudo apt install nmap"
		} else if runtime.GOOS == "windows" {
			missing["nmap"] = "Download and install from https://nmap.org/download.html"
		}
	}

	// Check Python modules using multiple methods if Python is installed
	if pythonInfo.Interpreter != "" {
		// Try both module import check and pip list check for thoroughness

		// Method 1: Direct import attempt
		requiredModules := []string{"nmap", "scapy"}
		for _, module := range requiredModules {
			// Create a temporary check script
			scriptPath := createModuleCheckScript(module)
			if scriptPath != "" {
				// Run the check with the detected Python interpreter
				cmd := exec.Command(pythonInfo.Interpreter, scriptPath)
				output, err := cmd.Output()

				if err == nil && strings.Contains(string(output), "MODULE_FOUND") {
					// Module found via import check
					continue
				}

				// Clean up temp file
				err = os.Remove(scriptPath)
				if err != nil {
					return nil
				}
			}

			// Method 2: Check using pip list
			if pythonInfo.IsVenv {
				// Use the venv's pip
				pipPath := getPipPath(pythonInfo)
				if pipPath != "" {
					if checkModuleInPip(pipPath, module) {
						continue
					}
				}
			} else {
				// Try system pip
				pipCommands := []string{"pip3", "pip"}
				for _, pipCmd := range pipCommands {
					if checkCommandExists(pipCmd) {
						if checkModuleInPip(pipCmd, module) {
							continue
						}
						break
					}
				}
			}

			// If we get here, module is missing
			missing[module] = fmt.Sprintf("Install with: pip3 install %s", module)
		}
	}

	return missing
}

// detectPythonEnvironment checks for Python installations and virtual environments
func detectPythonEnvironment() PythonEnvInfo {
	info := PythonEnvInfo{}

	// Check for active virtual environment
	if venvPath := os.Getenv("VIRTUAL_ENV"); venvPath != "" {
		// We're in an active virtual environment
		info.IsVenv = true

		// Determine interpreter path based on OS
		if runtime.GOOS == "windows" {
			info.Path = filepath.Join(venvPath, "Scripts", "python.exe")
		} else {
			info.Path = filepath.Join(venvPath, "bin", "python")
		}

		if _, err := os.Stat(info.Path); err == nil {
			info.Interpreter = info.Path
			info.Version = getPythonVersion(info.Interpreter)
			return info
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
				info.Path = absPath
				info.Interpreter = absPath
				info.IsVenv = true
				info.Version = getPythonVersion(info.Interpreter)
				return info
			}
		}
	}

	// Check for system Python interpreters
	pythonCommands := []string{"python3", "python"}
	for _, cmd := range pythonCommands {
		if path, err := exec.LookPath(cmd); err == nil {
			info.Interpreter = cmd
			info.Path = path
			info.Version = getPythonVersion(cmd)
			return info
		}
	}

	// No Python found
	return info
}

// getPythonVersion gets the version of a Python interpreter
func getPythonVersion(pythonCmd string) string {
	cmd := exec.Command(pythonCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	// Output format is typically "Python X.Y.Z"
	version := strings.TrimSpace(string(output))
	if strings.Contains(version, " ") {
		parts := strings.Split(version, " ")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	return version
}

// getPipPath gets the pip executable path for a Python environment
func getPipPath(pythonInfo PythonEnvInfo) string {
	if pythonInfo.IsVenv {
		// Virtual environment pip
		pipPath := ""
		if runtime.GOOS == "windows" {
			pipPath = strings.Replace(pythonInfo.Path, "python.exe", "pip.exe", 1)
		} else {
			pipPath = strings.Replace(pythonInfo.Path, "python", "pip", 1)
		}

		if _, err := os.Stat(pipPath); err == nil {
			return pipPath
		}
	}

	// System pip
	pipCommands := []string{"pip3", "pip"}
	for _, cmd := range pipCommands {
		if path, err := exec.LookPath(cmd); err == nil {
			return path
		}
	}

	return ""
}

// checkModuleInPip checks if a module is installed according to pip
func checkModuleInPip(pipCmd string, moduleName string) bool {
	cmd := exec.Command(pipCmd, "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Handle special module name differences between import and pip
	pipModuleName := moduleName
	if moduleName == "nmap" {
		pipModuleName = "python-nmap"
	}

	return strings.Contains(string(output), pipModuleName)
}

// createModuleCheckScript creates a temporary Python script to check for a module
func createModuleCheckScript(moduleName string) string {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "check_module_*.py")
	if err != nil {
		return ""
	}

	// Write a Python script that checks for the module
	script := fmt.Sprintf(`
try:
    import %s
    print("MODULE_FOUND")
except ImportError:
    print("MODULE_MISSING")
`, moduleName)

	if _, err := tmpFile.Write([]byte(script)); err != nil {
		err := os.Remove(tmpFile.Name())
		if err != nil {
			return ""
		}
		return ""
	}

	if err := tmpFile.Close(); err != nil {
		err := os.Remove(tmpFile.Name())
		if err != nil {
			return ""
		}
		return ""
	}

	return tmpFile.Name()
}

// checkCommandExists verifies if a command is available in the PATH
func checkCommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// CreateVirtualEnv creates a Python virtual environment if one doesn't exist
func CreateVirtualEnv() error {
	// Check if virtual environment already exists
	if _, err := os.Stat(".venv"); err == nil {
		fmt.Println("Virtual environment already exists")
		return nil
	}

	// Get Python environment info
	pythonInfo := detectPythonEnvironment()
	if pythonInfo.Interpreter == "" {
		return fmt.Errorf("python is not installed")
	}

	fmt.Printf("Creating virtual environment using %s (%s)...\n",
		pythonInfo.Interpreter, pythonInfo.Version)

	// Create virtual environment
	createCmd := exec.Command(pythonInfo.Interpreter, "-m", "venv", ".venv")
	output, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create virtual environment: %w\nOutput: %s",
			err, string(output))
	}

	// Determine pip command based on OS
	var pipCmd string
	if runtime.GOOS == "windows" {
		pipCmd = ".venv\\Scripts\\pip"
	} else {
		pipCmd = "./.venv/bin/pip"
	}

	fmt.Println("Installing required packages...")

	// Upgrade pip first
	upgradePipCmd := exec.Command(pipCmd, "install", "--upgrade", "pip")
	err = upgradePipCmd.Run()
	if err != nil {
		return err
	} // Ignore errors

	// Install required packages
	installCmd := exec.Command(pipCmd, "install", "python-nmap", "scapy")
	output, err = installCmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to install packages: %w\nOutput: %s", err, string(output))
	}

	fmt.Println("✅ Virtual environment created and dependencies installed")
	fmt.Println("To activate the virtual environment:")

	if runtime.GOOS == "windows" {
		fmt.Println("  .venv\\Scripts\\activate")
	} else {
		fmt.Println("  source .venv/bin/activate")
	}

	return nil
}

// PrintDependencyStatus checks for dependencies and prints their status
func PrintDependencyStatus() {
	fmt.Println("\nChecking dependencies...")
	missing := DependencyCheck()

	if len(missing) == 0 {
		fmt.Println("✅ All dependencies are satisfied!")
	} else {
		fmt.Println("\n❌ Missing dependencies:")
		for dep, instruction := range missing {
			fmt.Printf("  - %s: %s\n", dep, instruction)
		}

		// Special note for macOS users about Python modules
		if runtime.GOOS == "darwin" && (missing["nmap"] != "" || missing["scapy"] != "") {
			fmt.Println("\nNote for macOS users: If your scanner is working despite these warnings,")
			fmt.Println("you may have the modules installed in a different Python environment.")
			fmt.Println("The scanner may be using a different Python interpreter than this checker.")
		}

		fmt.Println("\nWould you like to attempt automatic installation? (y/n)")
		var response string
		fmt.Scanln(&response)

		if strings.ToLower(response) == "y" {
			fmt.Println("Attempting to install dependencies...")

			// Try to create virtual environment first
			if err := CreateVirtualEnv(); err != nil {
				fmt.Printf("Error creating virtual environment: %v\n", err)
			}

			// Check if we still have missing dependencies
			stillMissing := DependencyCheck()
			if len(stillMissing) == 0 {
				fmt.Println("✅ All dependencies installed successfully!")
			} else {
				fmt.Println("⚠️ Some dependencies could not be installed automatically.")
				fmt.Println("Please install the following manually:")
				for dep, instruction := range stillMissing {
					fmt.Printf("  - %s: %s\n", dep, instruction)
				}

				// Add option to continue anyway
				if (len(stillMissing) == 1 && stillMissing["nmap"] == "") ||
					(len(stillMissing) == 1 && stillMissing["scapy"] == "") {
					fmt.Println("\nWould you like to continue anyway? Your scanner might work if")
					fmt.Println("the dependencies are installed in a different Python environment. (y/n)")
					fmt.Scanln(&response)
					if strings.ToLower(response) == "y" {
						fmt.Println("Continuing...")
						return
					}
				}
			}
		}
	}
}
