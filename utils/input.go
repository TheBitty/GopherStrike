// utils/input.go
package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
)

// WaitForKeyPress waits for a specific key press
func WaitForKeyPress(key tcell.Key) {
	screen, err := tcell.NewScreen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating screen: %v\n", err)
		return
	}

	if err = screen.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing screen: %v\n", err)
		return
	}

	defer screen.Fini()

	// Display instruction
	message := "Press ESC to return to main menu..."
	for i, r := range message {
		screen.SetContent(i, 0, r, nil, tcell.StyleDefault)
	}
	screen.Show()

	for {
		ev := screen.PollEvent()
		switch ev := ev.(type) {
		case *tcell.EventKey:
			if ev.Key() == key {
				return
			}
		}
	}
}

// CheckForEscape checks if the ESC key is pressed
// Returns true if ESC was pressed, false if timeout occurred
func CheckForEscape(timeout time.Duration) bool {
	screen, err := tcell.NewScreen()
	if err != nil {
		return false
	}

	if err = screen.Init(); err != nil {
		return false
	}

	defer screen.Fini()

	// Create a timer for timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// Channel for key events
	keyChan := make(chan tcell.Key)

	// Start goroutine to listen for key events
	go func() {
		for {
			ev := screen.PollEvent()
			switch ev := ev.(type) {
			case *tcell.EventKey:
				keyChan <- ev.Key()
				return
			}
		}
	}()

	// Wait for either a key press or timeout
	select {
	case key := <-keyChan:
		return key == tcell.KeyEscape
	case <-timer.C:
		return false
	}
}
