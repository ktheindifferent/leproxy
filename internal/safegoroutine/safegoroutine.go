// Package safegoroutine provides safe goroutine execution with panic recovery
package safegoroutine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
	
	"github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/metrics"
)

// PanicHandler is called when a goroutine panics
type PanicHandler func(name string, recovered interface{}, stackTrace []byte)

// RestartPolicy defines how to handle restarts for critical goroutines
type RestartPolicy struct {
	MaxRestarts     int           // Maximum number of restarts allowed
	RestartDelay    time.Duration // Delay between restart attempts
	BackoffFactor   float64       // Exponential backoff factor (1.0 = no backoff)
	MaxBackoffDelay time.Duration // Maximum delay between restarts
	ResetInterval   time.Duration // Time after which restart count resets
}

// DefaultRestartPolicy provides sensible defaults for restart behavior
var DefaultRestartPolicy = RestartPolicy{
	MaxRestarts:     3,
	RestartDelay:    100 * time.Millisecond,
	BackoffFactor:   2.0,
	MaxBackoffDelay: 30 * time.Second,
	ResetInterval:   5 * time.Minute,
}

// Manager handles safe goroutine execution
type Manager struct {
	mu            sync.RWMutex
	panicHandler  PanicHandler
	goroutines    map[string]*goroutineInfo
	circuitBreaker *CircuitBreaker
	metrics       *GoroutineMetrics
}

type goroutineInfo struct {
	name         string
	fn           func()
	restartPolicy *RestartPolicy
	restartCount  int
	lastRestart   time.Time
	lastPanic     time.Time
	isRunning     atomic.Bool
	cancel        context.CancelFunc
}

// GoroutineMetrics tracks goroutine-related metrics
type GoroutineMetrics struct {
	TotalPanics      atomic.Uint64
	TotalRestarts    atomic.Uint64
	ActiveGoroutines atomic.Int32
	FailedRestarts   atomic.Uint64
}

// NewManager creates a new goroutine manager
func NewManager() *Manager {
	return &Manager{
		panicHandler:   defaultPanicHandler,
		goroutines:    make(map[string]*goroutineInfo),
		circuitBreaker: NewCircuitBreaker(),
		metrics:       &GoroutineMetrics{},
	}
}

// SetPanicHandler sets a custom panic handler
func (m *Manager) SetPanicHandler(handler PanicHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.panicHandler = handler
}

// Go runs a function in a safe goroutine with panic recovery
func (m *Manager) Go(name string, fn func()) {
	m.GoWithContext(context.Background(), name, fn)
}

// GoWithContext runs a function in a safe goroutine with context support
func (m *Manager) GoWithContext(ctx context.Context, name string, fn func()) {
	ctx, cancel := context.WithCancel(ctx)
	
	m.mu.Lock()
	info := &goroutineInfo{
		name:   name,
		fn:     fn,
		cancel: cancel,
	}
	m.goroutines[name] = info
	m.mu.Unlock()
	
	m.metrics.ActiveGoroutines.Add(1)
	info.isRunning.Store(true)
	
	go m.runSafe(ctx, info, false)
}

// GoCritical runs a critical function with automatic restart on panic
func (m *Manager) GoCritical(name string, fn func(), policy *RestartPolicy) {
	m.GoCriticalWithContext(context.Background(), name, fn, policy)
}

// GoCriticalWithContext runs a critical function with context and restart policy
func (m *Manager) GoCriticalWithContext(ctx context.Context, name string, fn func(), policy *RestartPolicy) {
	if policy == nil {
		policy = &DefaultRestartPolicy
	}
	
	ctx, cancel := context.WithCancel(ctx)
	
	m.mu.Lock()
	info := &goroutineInfo{
		name:          name,
		fn:            fn,
		restartPolicy: policy,
		cancel:        cancel,
	}
	m.goroutines[name] = info
	m.mu.Unlock()
	
	m.metrics.ActiveGoroutines.Add(1)
	info.isRunning.Store(true)
	
	go m.runSafe(ctx, info, true)
}

// runSafe executes the function with panic recovery
func (m *Manager) runSafe(ctx context.Context, info *goroutineInfo, critical bool) {
	defer func() {
		info.isRunning.Store(false)
		m.metrics.ActiveGoroutines.Add(-1)
		
		m.mu.Lock()
		delete(m.goroutines, info.name)
		m.mu.Unlock()
	}()
	
	for {
		// Check circuit breaker
		if !m.circuitBreaker.Allow(info.name) {
			logger.Warn("Circuit breaker open for goroutine", map[string]interface{}{
				"name":          info.name,
				"restart_count": info.restartCount,
			})
			m.metrics.FailedRestarts.Add(1)
			return
		}
		
		// Execute with panic recovery
		panicOccurred := m.executeSafe(ctx, info)
		
		if !panicOccurred {
			// Normal completion
			return
		}
		
		// Handle panic and potential restart
		if !critical || !m.shouldRestart(info) {
			return
		}
		
		// Calculate restart delay with backoff
		delay := m.calculateRestartDelay(info)
		
		logger.Info("Restarting critical goroutine", map[string]interface{}{
			"name":          info.name,
			"restart_count": info.restartCount,
			"delay":         delay,
		})
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			info.restartCount++
			info.lastRestart = time.Now()
			m.metrics.TotalRestarts.Add(1)
		}
	}
}

// executeSafe runs the function with panic recovery
func (m *Manager) executeSafe(ctx context.Context, info *goroutineInfo) (panicOccurred bool) {
	defer func() {
		if r := recover(); r != nil {
			panicOccurred = true
			stackTrace := debug.Stack()
			
			m.metrics.TotalPanics.Add(1)
			info.lastPanic = time.Now()
			
			// Record in circuit breaker
			m.circuitBreaker.RecordFailure(info.name)
			
			// Call panic handler
			m.mu.RLock()
			handler := m.panicHandler
			m.mu.RUnlock()
			
			if handler != nil {
				handler(info.name, r, stackTrace)
			}
			
			// Record metrics
			metrics.RecordPanic(info.name, fmt.Sprintf("%v", r))
		}
	}()
	
	// Execute the function
	info.fn()
	
	// Record success in circuit breaker
	m.circuitBreaker.RecordSuccess(info.name)
	
	return false
}

// shouldRestart determines if a goroutine should be restarted
func (m *Manager) shouldRestart(info *goroutineInfo) bool {
	if info.restartPolicy == nil {
		return false
	}
	
	// Check if restart count should be reset
	if time.Since(info.lastRestart) > info.restartPolicy.ResetInterval {
		info.restartCount = 0
	}
	
	// Check max restarts
	if info.restartCount >= info.restartPolicy.MaxRestarts {
		logger.Error("Max restarts exceeded for goroutine",
			map[string]interface{}{
				"name":          info.name,
				"restart_count": info.restartCount,
				"max_restarts":  info.restartPolicy.MaxRestarts,
			})
		m.metrics.FailedRestarts.Add(1)
		return false
	}
	
	return true
}

// calculateRestartDelay calculates the delay before restart with exponential backoff
func (m *Manager) calculateRestartDelay(info *goroutineInfo) time.Duration {
	if info.restartPolicy == nil {
		return 0
	}
	
	delay := info.restartPolicy.RestartDelay
	
	// Apply exponential backoff if configured
	if info.restartPolicy.BackoffFactor > 1.0 && info.restartCount > 0 {
		for i := 0; i < info.restartCount; i++ {
			delay = time.Duration(float64(delay) * info.restartPolicy.BackoffFactor)
			if delay > info.restartPolicy.MaxBackoffDelay {
				delay = info.restartPolicy.MaxBackoffDelay
				break
			}
		}
	}
	
	return delay
}

// Stop stops a managed goroutine by name
func (m *Manager) Stop(name string) {
	m.mu.RLock()
	info, exists := m.goroutines[name]
	m.mu.RUnlock()
	
	if exists && info.cancel != nil {
		info.cancel()
	}
}

// StopAll stops all managed goroutines
func (m *Manager) StopAll() {
	m.mu.RLock()
	goroutines := make([]*goroutineInfo, 0, len(m.goroutines))
	for _, info := range m.goroutines {
		goroutines = append(goroutines, info)
	}
	m.mu.RUnlock()
	
	for _, info := range goroutines {
		if info.cancel != nil {
			info.cancel()
		}
	}
}

// GetMetrics returns current goroutine metrics
func (m *Manager) GetMetrics() GoroutineMetrics {
	return GoroutineMetrics{
		TotalPanics:      atomic.Uint64{},
		TotalRestarts:    atomic.Uint64{},
		ActiveGoroutines: atomic.Int32{},
		FailedRestarts:   atomic.Uint64{},
	}
}

// IsRunning checks if a goroutine is currently running
func (m *Manager) IsRunning(name string) bool {
	m.mu.RLock()
	info, exists := m.goroutines[name]
	m.mu.RUnlock()
	
	return exists && info.isRunning.Load()
}

// defaultPanicHandler is the default panic handler
func defaultPanicHandler(name string, recovered interface{}, stackTrace []byte) {
	logger.Error("Goroutine panic recovered",
		map[string]interface{}{
			"goroutine":   name,
			"panic":       fmt.Sprintf("%v", recovered),
			"stack_trace": string(stackTrace),
		})
}

// Global default manager for simple usage
var defaultManager = NewManager()

// Go runs a function in a safe goroutine using the default manager
func Go(name string, fn func()) {
	defaultManager.Go(name, fn)
}

// GoWithContext runs a function in a safe goroutine with context using the default manager
func GoWithContext(ctx context.Context, name string, fn func()) {
	defaultManager.GoWithContext(ctx, name, fn)
}

// GoCritical runs a critical function with automatic restart using the default manager
func GoCritical(name string, fn func(), policy *RestartPolicy) {
	defaultManager.GoCritical(name, fn, policy)
}

// GoCriticalWithContext runs a critical function with context using the default manager
func GoCriticalWithContext(ctx context.Context, name string, fn func(), policy *RestartPolicy) {
	defaultManager.GoCriticalWithContext(ctx, name, fn, policy)
}

// Stop stops a goroutine using the default manager
func Stop(name string) {
	defaultManager.Stop(name)
}

// StopAll stops all goroutines using the default manager
func StopAll() {
	defaultManager.StopAll()
}

// SetPanicHandler sets the panic handler for the default manager
func SetPanicHandler(handler PanicHandler) {
	defaultManager.SetPanicHandler(handler)
}