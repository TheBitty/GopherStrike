// utils/input.go
package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
)

// Global variables to manage interrupt handling
var (
	interruptCh    chan struct{} // Channel to signal interruption
	interruptMu    sync.Mutex    // Mutex to protect access to interrupt channel
	isListening    bool          // Flag to track if listener is active
	listenerDoneCh chan struct{} // Channel to signal listener completion
)

// WaitForKeyPress waits for a specific key press
func WaitForKeyPress(key tcell.Key) {
	// Try to create a screen
	screen, err := tcell.NewScreen()
	if err != nil {
		// Screen creation failed - fall back to basic console input
		fmt.Fprintf(os.Stderr, "Warning: Could not create screen: %v\n", err)
		fmt.Println("Press ENTER to continue...")

		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')
		return
	}

	// Try to initialize the screen
	if err = screen.Init(); err != nil {
		// Screen initialization failed - fall back to basic console input
		fmt.Fprintf(os.Stderr, "Warning: Could not initialize screen: %v\n", err)
		fmt.Println("Press ENTER to continue...")

		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')
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
			} else if ev.Key() == tcell.KeyEnter {
				// Also allow Enter to continue
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
	// Try to create a screen
	screen, err := tcell.NewScreen()
	if err != nil {
		// Screen creation failed, return false to indicate no ESC press
		return false
	}

	// Try to initialize the screen
	if err = screen.Init(); err != nil {
		// Screen initialization failed, return false to indicate no ESC press
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

// StartInterruptListener starts listening for Ctrl+C to interrupt running tools
// Returns a channel that will be closed when an interrupt is detected
func StartInterruptListener() chan struct{} {
	interruptMu.Lock()
	defer interruptMu.Unlock()

	// Create a new interrupt channel
	interruptCh = make(chan struct{})
	listenerDoneCh = make(chan struct{})

	// Set the flag
	isListening = true

	// Listen for OS signals (Ctrl+C) only - no screen or keyboard handling
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)

	// Start a goroutine to listen for OS signals
	go func() {
		// Wait for OS signal
		<-osSignals
		signal.Stop(osSignals)

		// Signal the interrupt
		interruptMu.Lock()
		if interruptCh != nil {
			close(interruptCh)
			interruptCh = nil
		}
		isListening = false
		interruptMu.Unlock()

		// Signal that we're done listening
		close(listenerDoneCh)
	}()

	return interruptCh
}

// StopInterruptListener stops the interrupt listener if it's running
func StopInterruptListener() {
	interruptMu.Lock()
	defer interruptMu.Unlock()

	if !isListening {
		return
	}

	// Reset the flag
	isListening = false

	// Clean up the channel
	if interruptCh != nil {
		close(interruptCh)
		interruptCh = nil
	}

	// Wait for the listener to finish
	if listenerDoneCh != nil {
		<-listenerDoneCh
		listenerDoneCh = nil
	}
}
