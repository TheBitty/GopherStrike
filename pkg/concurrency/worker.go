// pkg/concurrency/worker.go
package concurrency

import (
	"GopherStrike/pkg/logging"
	"context"
	"runtime"
	"sync"
	"time"
)

// Logger for concurrency operations
var logger = logging.GetModuleLogger("concurrency")

// Task represents a task to be executed by a worker
type Task interface {
	Execute() interface{}
	GetID() string
}

// Result represents the result of a task execution
type Result struct {
	TaskID string
	Value  interface{}
	Error  error
}

// WorkerPool manages a pool of workers for concurrent task execution
type WorkerPool struct {
	numWorkers int
	taskQueue  chan Task
	results    chan Result
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewWorkerPool creates a new worker pool with the specified number of workers
func NewWorkerPool(numWorkers int, queueSize int) *WorkerPool {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	if queueSize <= 0 {
		queueSize = numWorkers * 10
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		numWorkers: numWorkers,
		taskQueue:  make(chan Task, queueSize),
		results:    make(chan Result, queueSize),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the worker pool
func (wp *WorkerPool) Start() {
	logger.Info("Starting worker pool with %d workers", wp.numWorkers)
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// worker processes tasks from the task queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	logger.Debug("Worker %d started", id)

	for {
		select {
		case <-wp.ctx.Done():
			logger.Debug("Worker %d shutting down", id)
			return
		case task, ok := <-wp.taskQueue:
			if !ok {
				logger.Debug("Worker %d: task queue closed", id)
				return
			}

			logger.Debug("Worker %d executing task %s", id, task.GetID())

			// Execute the task and capture panics
			var result interface{}
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Error("Worker %d: panic executing task %s: %v", id, task.GetID(), r)
						err = ErrTaskPanic{TaskID: task.GetID(), Reason: r}
					}
				}()
				result = task.Execute()
			}()

			// Send the result
			wp.results <- Result{
				TaskID: task.GetID(),
				Value:  result,
				Error:  err,
			}
		}
	}
}

// Submit submits a task to the worker pool
func (wp *WorkerPool) Submit(task Task) {
	wp.taskQueue <- task
}

// Results returns the results channel
func (wp *WorkerPool) Results() <-chan Result {
	return wp.results
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() {
	logger.Info("Stopping worker pool")
	wp.cancel()
	close(wp.taskQueue)
	wp.wg.Wait()
	close(wp.results)
}

// WaitWithTimeout waits for all tasks to complete with a timeout
func (wp *WorkerPool) WaitWithTimeout(timeout time.Duration) bool {
	logger.Info("Waiting for tasks to complete (timeout: %s)", timeout)

	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("All tasks completed successfully")
		return true
	case <-time.After(timeout):
		logger.Warning("Timed out waiting for tasks to complete")
		return false
	}
}

// ErrTaskPanic represents a panic that occurred during task execution
type ErrTaskPanic struct {
	TaskID string
	Reason interface{}
}

// Error implements the error interface
func (e ErrTaskPanic) Error() string {
	return "panic in task " + e.TaskID + ": " + stringify(e.Reason)
}

// Helper function to convert any value to string
func stringify(v interface{}) string {
	if v == nil {
		return "nil"
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "non-string panic"
}

// SimpleTask is a basic implementation of the Task interface
type SimpleTask struct {
	ID      string
	Handler func() interface{}
}

// Execute executes the task
func (t *SimpleTask) Execute() interface{} {
	return t.Handler()
}

// GetID returns the task ID
func (t *SimpleTask) GetID() string {
	return t.ID
}

// NewSimpleTask creates a new simple task
func NewSimpleTask(id string, handler func() interface{}) Task {
	return &SimpleTask{
		ID:      id,
		Handler: handler,
	}
}
