package safegoroutine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBasicPanicRecovery tests that panics are recovered
func TestBasicPanicRecovery(t *testing.T) {
	manager := NewManager()
	
	var panicCaught atomic.Bool
	manager.SetPanicHandler(func(name string, recovered interface{}, stackTrace []byte) {
		panicCaught.Store(true)
		if name != "test-panic" {
			t.Errorf("expected name 'test-panic', got %s", name)
		}
		if recovered != "test panic" {
			t.Errorf("expected panic 'test panic', got %v", recovered)
		}
	})
	
	done := make(chan bool)
	manager.Go("test-panic", func() {
		defer func() { done <- true }()
		panic("test panic")
	})
	
	select {
	case <-done:
		if !panicCaught.Load() {
			t.Error("panic was not caught")
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for goroutine")
	}
}

// TestMultiplePanics tests handling multiple concurrent panics
func TestMultiplePanics(t *testing.T) {
	manager := NewManager()
	
	var panicCount atomic.Uint32
	manager.SetPanicHandler(func(name string, recovered interface{}, stackTrace []byte) {
		panicCount.Add(1)
	})
	
	numGoroutines := 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		name := fmt.Sprintf("panic-%d", i)
		manager.Go(name, func() {
			defer wg.Done()
			panic("concurrent panic")
		})
	}
	
	wg.Wait()
	
	if panicCount.Load() != uint32(numGoroutines) {
		t.Errorf("expected %d panics, got %d", numGoroutines, panicCount.Load())
	}
}

// TestCriticalGoroutineRestart tests automatic restart of critical goroutines
func TestCriticalGoroutineRestart(t *testing.T) {
	manager := NewManager()
	
	var executionCount atomic.Uint32
	var panicCount atomic.Uint32
	
	manager.SetPanicHandler(func(name string, recovered interface{}, stackTrace []byte) {
		panicCount.Add(1)
	})
	
	policy := &RestartPolicy{
		MaxRestarts:   2,
		RestartDelay:  10 * time.Millisecond,
		BackoffFactor: 1.0,
		ResetInterval: 1 * time.Minute,
	}
	
	done := make(chan bool)
	manager.GoCritical("critical-test", func() {
		count := executionCount.Add(1)
		if count <= 2 {
			panic("intentional panic")
		}
		done <- true
	}, policy)
	
	select {
	case <-done:
		// Should execute 3 times: initial + 2 restarts
		if executionCount.Load() != 3 {
			t.Errorf("expected 3 executions, got %d", executionCount.Load())
		}
		if panicCount.Load() != 2 {
			t.Errorf("expected 2 panics, got %d", panicCount.Load())
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for critical goroutine")
	}
}

// TestMaxRestartsExceeded tests that goroutines stop after max restarts
func TestMaxRestartsExceeded(t *testing.T) {
	manager := NewManager()
	
	var executionCount atomic.Uint32
	
	policy := &RestartPolicy{
		MaxRestarts:   2,
		RestartDelay:  10 * time.Millisecond,
		BackoffFactor: 1.0,
		ResetInterval: 1 * time.Minute,
	}
	
	manager.GoCritical("max-restart-test", func() {
		executionCount.Add(1)
		panic("always panic")
	}, policy)
	
	time.Sleep(200 * time.Millisecond)
	
	// Should execute 3 times: initial + 2 restarts
	if executionCount.Load() != 3 {
		t.Errorf("expected 3 executions, got %d", executionCount.Load())
	}
	
	// Verify goroutine is no longer running
	if manager.IsRunning("max-restart-test") {
		t.Error("goroutine should not be running after max restarts")
	}
}

// TestExponentialBackoff tests exponential backoff between restarts
func TestExponentialBackoff(t *testing.T) {
	manager := NewManager()
	
	var executionTimes []time.Time
	var mu sync.Mutex
	
	policy := &RestartPolicy{
		MaxRestarts:     3,
		RestartDelay:    50 * time.Millisecond,
		BackoffFactor:   2.0,
		MaxBackoffDelay: 500 * time.Millisecond,
		ResetInterval:   1 * time.Minute,
	}
	
	done := make(chan bool)
	manager.GoCritical("backoff-test", func() {
		mu.Lock()
		executionTimes = append(executionTimes, time.Now())
		count := len(executionTimes)
		mu.Unlock()
		
		if count <= 3 {
			panic("testing backoff")
		}
		done <- true
	}, policy)
	
	select {
	case <-done:
		mu.Lock()
		times := executionTimes
		mu.Unlock()
		
		if len(times) != 4 {
			t.Errorf("expected 4 executions, got %d", len(times))
		}
		
		// Check backoff delays (allowing some tolerance)
		expectedDelays := []time.Duration{0, 50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
		for i := 1; i < len(times); i++ {
			actualDelay := times[i].Sub(times[i-1])
			expectedDelay := expectedDelays[i]
			
			// Allow 20ms tolerance
			if actualDelay < expectedDelay-20*time.Millisecond || actualDelay > expectedDelay+50*time.Millisecond {
				t.Errorf("delay %d: expected ~%v, got %v", i, expectedDelay, actualDelay)
			}
		}
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for backoff test")
	}
}

// TestContextCancellation tests that goroutines respect context cancellation
func TestContextCancellation(t *testing.T) {
	manager := NewManager()
	
	ctx, cancel := context.WithCancel(context.Background())
	
	var started atomic.Bool
	var stopped atomic.Bool
	
	manager.GoWithContext(ctx, "context-test", func() {
		started.Store(true)
		<-ctx.Done()
		stopped.Store(true)
	})
	
	time.Sleep(50 * time.Millisecond)
	
	if !started.Load() {
		t.Error("goroutine did not start")
	}
	
	cancel()
	time.Sleep(50 * time.Millisecond)
	
	if !stopped.Load() {
		t.Error("goroutine did not stop on context cancellation")
	}
}

// TestCircuitBreaker tests circuit breaker integration
func TestCircuitBreaker(t *testing.T) {
	manager := NewManager()
	
	// Configure circuit breaker to open after 2 failures
	manager.circuitBreaker = NewCircuitBreakerWithConfig(CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 1,
		Timeout:         100 * time.Millisecond,
		MaxHalfOpenTime: 200 * time.Millisecond,
	})
	
	var executionCount atomic.Uint32
	
	policy := &RestartPolicy{
		MaxRestarts:   5,
		RestartDelay:  10 * time.Millisecond,
		BackoffFactor: 1.0,
		ResetInterval: 1 * time.Minute,
	}
	
	manager.GoCritical("circuit-test", func() {
		count := executionCount.Add(1)
		if count <= 3 {
			panic("circuit breaker test")
		}
	}, policy)
	
	time.Sleep(150 * time.Millisecond)
	
	// Circuit should open after 2 failures
	state := manager.circuitBreaker.GetState("circuit-test")
	if state == CircuitClosed {
		t.Error("circuit breaker should be open or half-open")
	}
	
	// Wait for timeout and potential recovery
	time.Sleep(200 * time.Millisecond)
	
	// Should eventually succeed
	if executionCount.Load() < 3 {
		t.Errorf("expected at least 3 executions after circuit recovery, got %d", executionCount.Load())
	}
}

// TestStopGoroutine tests stopping a managed goroutine
func TestStopGoroutine(t *testing.T) {
	manager := NewManager()
	
	var running atomic.Bool
	done := make(chan bool)
	
	manager.Go("stoppable", func() {
		running.Store(true)
		time.Sleep(1 * time.Second)
		running.Store(false)
		done <- true
	})
	
	time.Sleep(50 * time.Millisecond)
	
	if !running.Load() {
		t.Error("goroutine should be running")
	}
	
	manager.Stop("stoppable")
	
	select {
	case <-done:
		// Goroutine completed
	case <-time.After(100 * time.Millisecond):
		// Goroutine was stopped
	}
	
	if manager.IsRunning("stoppable") {
		t.Error("goroutine should not be running after stop")
	}
}

// TestNormalCompletion tests that normal completion doesn't trigger restart
func TestNormalCompletion(t *testing.T) {
	manager := NewManager()
	
	var executionCount atomic.Uint32
	done := make(chan bool)
	
	policy := &RestartPolicy{
		MaxRestarts:   3,
		RestartDelay:  10 * time.Millisecond,
		BackoffFactor: 1.0,
		ResetInterval: 1 * time.Minute,
	}
	
	manager.GoCritical("normal-completion", func() {
		executionCount.Add(1)
		done <- true
	}, policy)
	
	<-done
	time.Sleep(100 * time.Millisecond)
	
	if executionCount.Load() != 1 {
		t.Errorf("expected 1 execution for normal completion, got %d", executionCount.Load())
	}
}

// TestRestartCountReset tests that restart count resets after interval
func TestRestartCountReset(t *testing.T) {
	manager := NewManager()
	
	var executionCount atomic.Uint32
	var lastExecution time.Time
	var mu sync.Mutex
	
	policy := &RestartPolicy{
		MaxRestarts:   1,
		RestartDelay:  10 * time.Millisecond,
		BackoffFactor: 1.0,
		ResetInterval: 100 * time.Millisecond,
	}
	
	done := make(chan bool)
	manager.GoCritical("reset-test", func() {
		mu.Lock()
		count := executionCount.Add(1)
		now := time.Now()
		
		// First round of failures
		if count <= 2 {
			lastExecution = now
			mu.Unlock()
			panic("first round")
		}
		
		// Wait for reset interval
		if count == 3 {
			if now.Sub(lastExecution) < policy.ResetInterval {
				mu.Unlock()
				time.Sleep(policy.ResetInterval)
				panic("waiting for reset")
			}
			lastExecution = now
			mu.Unlock()
			panic("second round start")
		}
		
		// Second round should also get a restart
		if count == 4 {
			mu.Unlock()
			done <- true
			return
		}
		
		mu.Unlock()
	}, policy)
	
	select {
	case <-done:
		if executionCount.Load() != 4 {
			t.Errorf("expected 4 executions with reset, got %d", executionCount.Load())
		}
	case <-time.After(1 * time.Second):
		t.Errorf("timeout waiting for reset test, executions: %d", executionCount.Load())
	}
}

// TestGlobalFunctions tests the global convenience functions
func TestGlobalFunctions(t *testing.T) {
	var executed atomic.Bool
	
	Go("global-test", func() {
		executed.Store(true)
	})
	
	time.Sleep(50 * time.Millisecond)
	
	if !executed.Load() {
		t.Error("global Go function did not execute")
	}
	
	// Test global stop
	done := make(chan bool)
	Go("global-stop-test", func() {
		time.Sleep(1 * time.Second)
		done <- true
	})
	
	time.Sleep(50 * time.Millisecond)
	Stop("global-stop-test")
	
	select {
	case <-done:
		t.Error("goroutine should have been stopped")
	case <-time.After(100 * time.Millisecond):
		// Expected - goroutine was stopped
	}
}

// TestMetrics tests that metrics are properly tracked
func TestMetrics(t *testing.T) {
	manager := NewManager()
	
	// Cause some panics
	for i := 0; i < 3; i++ {
		manager.Go(fmt.Sprintf("metric-test-%d", i), func() {
			panic("metrics test")
		})
	}
	
	time.Sleep(100 * time.Millisecond)
	
	if manager.metrics.TotalPanics.Load() != 3 {
		t.Errorf("expected 3 panics in metrics, got %d", manager.metrics.TotalPanics.Load())
	}
	
	// Test restart metrics
	policy := &RestartPolicy{
		MaxRestarts:   1,
		RestartDelay:  10 * time.Millisecond,
		BackoffFactor: 1.0,
		ResetInterval: 1 * time.Minute,
	}
	
	done := make(chan bool)
	var count atomic.Uint32
	manager.GoCritical("restart-metric-test", func() {
		if count.Add(1) <= 1 {
			panic("restart test")
		}
		done <- true
	}, policy)
	
	<-done
	
	if manager.metrics.TotalRestarts.Load() != 1 {
		t.Errorf("expected 1 restart in metrics, got %d", manager.metrics.TotalRestarts.Load())
	}
}