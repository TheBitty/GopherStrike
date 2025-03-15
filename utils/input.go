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

	// Get screen dimensions
	width, height := screen.Size()

	// Display instruction centered at the bottom of the screen
	message := "Press ESC to return to main menu..."
	xPos := (width - len(message)) / 2
	if xPos < 0 {
		xPos = 0
	}
	yPos := height - 2 // Position near the bottom

	// Clear the line first
	for i := 0; i < width; i++ {
		screen.SetContent(i, yPos, ' ', nil, tcell.StyleDefault)
	}

	// Write the message
	for i, r := range message {
		if xPos+i < width {
			screen.SetContent(xPos+i, yPos, r, nil, tcell.StyleDefault.Foreground(tcell.ColorYellow).Bold(true))
		}
	}
	screen.Show()

	// Set up a ticker to refresh the screen occasionally
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// Create a channel for events
	quit := make(chan struct{})

	// Handle events in a separate goroutine
	go func() {
		for {
			select {
			case <-ticker.C:
				// Just refresh the screen periodically
				screen.Show()
			case <-quit:
				return
			}
		}
	}()

	// Main event loop
	for {
		ev := screen.PollEvent()
		switch ev := ev.(type) {
		case *tcell.EventKey:
			if ev.Key() == key {
				close(quit)
				return
			} else if ev.Key() == tcell.KeyCtrlC {
				// Also handle Ctrl+C gracefully
				close(quit)
				return
			}
		case *tcell.EventResize:
			// Handle window resize
			screen.Sync()
			width, height = screen.Size()
			xPos = (width - len(message)) / 2
			if xPos < 0 {
				xPos = 0
			}
			yPos = height - 2

			// Redraw message
			for i := 0; i < width; i++ {
				screen.SetContent(i, yPos, ' ', nil, tcell.StyleDefault)
			}
			for i, r := range message {
				if xPos+i < width {
					screen.SetContent(xPos+i, yPos, r, nil, tcell.StyleDefault.Foreground(tcell.ColorYellow).Bold(true))
				}
			}
			screen.Show()
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
