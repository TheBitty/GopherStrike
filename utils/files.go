package utils

import (
	"os"
	"os/exec"
	"runtime"
)

// ClearScreen clears the terminal screen based on the OS
func ClearScreen() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls") // Windows
	default:
		cmd = exec.Command("clear") // Linux/macOS
	}
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		return
	}
}

func exitMenu() {
	ClearScreen()

}
