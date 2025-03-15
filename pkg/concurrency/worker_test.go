package concurrency

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestWorkerPool(t *testing.T) {
	// Create a worker pool with 4 workers
	pool := NewWorkerPool(4, 10)
	pool.Start()
	defer pool.Stop()

	// Create a wait group to wait for all results
	var wg sync.WaitGroup
	wg.Add(5)

	// Start a goroutine to collect results
	results := make(map[string]interface{})
	var resultsMu sync.Mutex

	go func() {
		for result := range pool.Results() {
			resultsMu.Lock()
			results[result.TaskID] = result.Value
			resultsMu.Unlock()
			wg.Done()
		}
	}()

	// Submit 5 tasks
	for i := 0; i < 5; i++ {
		taskID := fmt.Sprintf("task-%d", i)
		val := i
		pool.Submit(NewSimpleTask(taskID, func() interface{} {
			time.Sleep(100 * time.Millisecond) // Simulate work
			return val * 2
		}))
	}

	// Wait for all results with a timeout
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// All tasks completed
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for tasks to complete")
	}

	// Check results
	resultsMu.Lock()
	defer resultsMu.Unlock()

	if len(results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(results))
	}

	// Check each result
	for i := 0; i < 5; i++ {
		taskID := fmt.Sprintf("task-%d", i)
		result, ok := results[taskID]
		if !ok {
			t.Errorf("Missing result for task %s", taskID)
			continue
		}

		// Check result value
		expected := i * 2
		if result != expected {
			t.Errorf("Expected %d, got %v for task %s", expected, result, taskID)
		}
	}
}

func TestWorkerPoolPanic(t *testing.T) {
	// Create a worker pool with 2 workers
	pool := NewWorkerPool(2, 5)
	pool.Start()
	defer pool.Stop()

	// Create a task that panics
	panicTask := NewSimpleTask("panic-task", func() interface{} {
		panic("test panic")
		return nil
	})

	// Submit the task
	pool.Submit(panicTask)

	// Wait for the result
	var resultErr error
	select {
	case result := <-pool.Results():
		if result.TaskID != "panic-task" {
			t.Errorf("Expected result from panic-task, got %s", result.TaskID)
		}
		resultErr = result.Error
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for panic task result")
	}

	// Check the error
	if resultErr == nil {
		t.Error("Expected error from panic task, got nil")
	}

	// Check error type
	panicErr, ok := resultErr.(ErrTaskPanic)
	if !ok {
		t.Errorf("Expected ErrTaskPanic, got %T", resultErr)
	}

	// Check error message
	if panicErr.TaskID != "panic-task" {
		t.Errorf("Expected TaskID panic-task, got %s", panicErr.TaskID)
	}

	// Submit another task to make sure the worker pool is still working
	normalTask := NewSimpleTask("normal-task", func() interface{} {
		return "success"
	})

	pool.Submit(normalTask)

	// Wait for the result
	select {
	case result := <-pool.Results():
		if result.TaskID != "normal-task" {
			t.Errorf("Expected result from normal-task, got %s", result.TaskID)
		}
		if result.Value != "success" {
			t.Errorf("Expected success, got %v", result.Value)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for normal task result")
	}
}

func TestWorkerPoolCancellation(t *testing.T) {
	// Create a worker pool
	pool := NewWorkerPool(2, 10)
	pool.Start()

	// Submit a long-running task
	longTask := NewSimpleTask("long-task", func() interface{} {
		time.Sleep(2 * time.Second)
		return "done"
	})

	pool.Submit(longTask)

	// Stop the pool before the task completes
	time.Sleep(500 * time.Millisecond)
	pool.Stop()

	// Try to submit another task after stopping
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when submitting to a stopped pool")
		}
	}()

	pool.Submit(NewSimpleTask("after-stop", func() interface{} {
		return "should not run"
	}))
}
