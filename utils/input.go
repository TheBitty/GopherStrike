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

// StartInterruptListener starts listening for ESC key or Ctrl+C to interrupt running tools
// Returns a channel that will be closed when an interrupt is detected
func StartInterruptListener() chan struct{} {
	interruptMu.Lock()
	defer interruptMu.Unlock()

	// Create a new interrupt channel if needed
	if interruptCh == nil || isListening {
		interruptCh = make(chan struct{})
		listenerDoneCh = make(chan struct{})
	}

	// Already listening, just return the existing channel
	if isListening {
		return interruptCh
	}

	// Set the flag
	isListening = true

	// Listen for OS signals (Ctrl+C)
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)

	// Start a goroutine to listen for ESC key
	go func() {
		// Create a screen for keyboard events
		screen, err := tcell.NewScreen()
		if err != nil {
			// If screen creation fails, we'll only listen for OS signals
			fmt.Fprintf(os.Stderr, "Warning: Could not create keyboard listener: %v\n", err)
			fmt.Println("Only Ctrl+C will work for interrupting tools.")

			// Just wait for OS signal
			<-osSignals

			// Signal the interrupt if channel is still open
			interruptMu.Lock()
			if interruptCh != nil {
				close(interruptCh)
				interruptCh = nil
			}
			interruptMu.Unlock()

			// Signal that we're done listening
			close(listenerDoneCh)
			return
		}

		if err = screen.Init(); err != nil {
			// If screen initialization fails, we'll only listen for OS signals
			fmt.Fprintf(os.Stderr, "Warning: Could not initialize keyboard listener: %v\n", err)
			fmt.Println("Only Ctrl+C will work for interrupting tools.")

			// Just wait for OS signal
			<-osSignals

			// Signal the interrupt if channel is still open
			interruptMu.Lock()
			if interruptCh != nil {
				close(interruptCh)
				interruptCh = nil
			}
			interruptMu.Unlock()

			// Signal that we're done listening
			close(listenerDoneCh)
			return
		}

		defer screen.Fini()

		// Add a message at the bottom of the screen
		width, height := screen.Size()
		message := "Press ESC or Ctrl+C at any time to return to main menu..."
		xPos := (width - len(message)) / 2
		if xPos < 0 {
			xPos = 0
		}
		yPos := height - 1 // At the very bottom

		// Clear the line
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

		// Set up the event handling loop
		keyEventCh := make(chan tcell.Key, 1)
		resizeCh := make(chan struct{}, 1)

		// Start a goroutine to handle events
		go func() {
			for {
				ev := screen.PollEvent()
				switch ev := ev.(type) {
				case *tcell.EventKey:
					if ev.Key() == tcell.KeyEscape || ev.Key() == tcell.KeyCtrlC {
						keyEventCh <- ev.Key()
						return
					}
				case *tcell.EventResize:
					resizeCh <- struct{}{}
				}
			}
		}()

		// Main event handling loop
		for {
			select {
			case <-osSignals:
				// OS signal received (Ctrl+C)
				fmt.Println("\nInterrupted by Ctrl+C, returning to main menu...")

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
				return

			case key := <-keyEventCh:
				// Keyboard interrupt (ESC or Ctrl+C)
				if key == tcell.KeyEscape {
					fmt.Println("\nInterrupted by ESC key, returning to main menu...")
				} else {
					fmt.Println("\nInterrupted by Ctrl+C, returning to main menu...")
				}

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
				return

			case <-resizeCh:
				// Window resize event
				screen.Sync()
				width, height = screen.Size()
				xPos = (width - len(message)) / 2
				if xPos < 0 {
					xPos = 0
				}
				yPos = height - 1

				// Clear the line
				for i := 0; i < width; i++ {
					screen.SetContent(i, yPos, ' ', nil, tcell.StyleDefault)
				}

				// Redraw the message
				for i, r := range message {
					if xPos+i < width {
						screen.SetContent(xPos+i, yPos, r, nil, tcell.StyleDefault.Foreground(tcell.ColorYellow).Bold(true))
					}
				}
				screen.Show()
			}
		}
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
