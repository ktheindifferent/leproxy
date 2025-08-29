package graceful

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Shutdown-specific error types
var (
	ErrShutdownTimeout    = errors.New("shutdown timeout exceeded")
	ErrShutdownCanceled   = errors.New("shutdown was canceled")
	ErrComponentShutdown  = errors.New("component shutdown failed")
	ErrForceShutdown      = errors.New("forced shutdown initiated")
	ErrShutdownInProgress = errors.New("shutdown already in progress")
	ErrNotReady           = errors.New("server not ready for shutdown")
)

// ShutdownPhase represents the phase of shutdown
type ShutdownPhase string

const (
	PhaseListeners   ShutdownPhase = "listeners"
	PhaseConnections ShutdownPhase = "connections"
	PhasePools       ShutdownPhase = "pools"
	PhaseServices    ShutdownPhase = "services"
	PhaseTracers     ShutdownPhase = "tracers"
	PhaseCleanup     ShutdownPhase = "cleanup"
)

// ShutdownError represents an error during shutdown with context
type ShutdownError struct {
	Phase     ShutdownPhase
	Component string
	Err       error
	Timestamp time.Time
	Duration  time.Duration
}

func (e *ShutdownError) Error() string {
	if e.Duration > 0 {
		return fmt.Sprintf("[%s] %s shutdown failed after %v: %v", 
			e.Phase, e.Component, e.Duration, e.Err)
	}
	return fmt.Sprintf("[%s] %s shutdown failed: %v", 
		e.Phase, e.Component, e.Err)
}

func (e *ShutdownError) Unwrap() error {
	return e.Err
}

// MultiError aggregates multiple errors during shutdown
type MultiError struct {
	errors []error
	mu     sync.RWMutex
}

// NewMultiError creates a new MultiError
func NewMultiError() *MultiError {
	return &MultiError{
		errors: make([]error, 0),
	}
}

// Add adds an error to the collection
func (m *MultiError) Add(err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = append(m.errors, err)
}

// AddWithContext adds an error with shutdown context
func (m *MultiError) AddWithContext(phase ShutdownPhase, component string, err error, duration time.Duration) {
	if err == nil {
		return
	}
	m.Add(&ShutdownError{
		Phase:     phase,
		Component: component,
		Err:       err,
		Timestamp: time.Now(),
		Duration:  duration,
	})
}

// HasErrors returns true if there are any errors
func (m *MultiError) HasErrors() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.errors) > 0
}

// Count returns the number of errors
func (m *MultiError) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.errors)
}

// Errors returns a copy of all errors
func (m *MultiError) Errors() []error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]error, len(m.errors))
	copy(result, m.errors)
	return result
}

// Error implements the error interface
func (m *MultiError) Error() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if len(m.errors) == 0 {
		return ""
	}
	
	if len(m.errors) == 1 {
		return m.errors[0].Error()
	}
	
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d errors occurred during shutdown:\n", len(m.errors)))
	
	// Group errors by phase for better readability
	phaseErrors := make(map[ShutdownPhase][]error)
	otherErrors := []error{}
	
	for _, err := range m.errors {
		if shutErr, ok := err.(*ShutdownError); ok {
			phaseErrors[shutErr.Phase] = append(phaseErrors[shutErr.Phase], err)
		} else {
			otherErrors = append(otherErrors, err)
		}
	}
	
	// Print errors grouped by phase
	for _, phase := range []ShutdownPhase{PhaseListeners, PhaseConnections, PhasePools, PhaseServices, PhaseTracers, PhaseCleanup} {
		if errors, ok := phaseErrors[phase]; ok && len(errors) > 0 {
			sb.WriteString(fmt.Sprintf("\n[%s Phase]:\n", phase))
			for i, err := range errors {
				sb.WriteString(fmt.Sprintf("  %d. %v\n", i+1, err))
			}
		}
	}
	
	// Print other errors
	if len(otherErrors) > 0 {
		sb.WriteString("\n[Other Errors]:\n")
		for i, err := range otherErrors {
			sb.WriteString(fmt.Sprintf("  %d. %v\n", i+1, err))
		}
	}
	
	return sb.String()
}

// Unwrap returns the first error for compatibility with errors.Unwrap
func (m *MultiError) Unwrap() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if len(m.errors) > 0 {
		return m.errors[0]
	}
	return nil
}

// ErrorOrNil returns nil if no errors, otherwise returns the MultiError
func (m *MultiError) ErrorOrNil() error {
	if !m.HasErrors() {
		return nil
	}
	return m
}

// ShutdownMetrics holds metrics about the shutdown process
type ShutdownMetrics struct {
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	ErrorCount      int
	ComponentsCount int
	PhaseMetrics    map[ShutdownPhase]*PhaseMetrics
	mu              sync.RWMutex
}

// PhaseMetrics holds metrics for a specific shutdown phase
type PhaseMetrics struct {
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	ErrorCount int
	Components []string
}

// NewShutdownMetrics creates new shutdown metrics
func NewShutdownMetrics() *ShutdownMetrics {
	return &ShutdownMetrics{
		PhaseMetrics: make(map[ShutdownPhase]*PhaseMetrics),
	}
}

// StartPhase marks the start of a shutdown phase
func (m *ShutdownMetrics) StartPhase(phase ShutdownPhase) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.StartTime.IsZero() {
		m.StartTime = time.Now()
	}
	
	m.PhaseMetrics[phase] = &PhaseMetrics{
		StartTime:  time.Now(),
		Components: make([]string, 0),
	}
}

// EndPhase marks the end of a shutdown phase
func (m *ShutdownMetrics) EndPhase(phase ShutdownPhase, errorCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if pm, ok := m.PhaseMetrics[phase]; ok {
		pm.EndTime = time.Now()
		pm.Duration = pm.EndTime.Sub(pm.StartTime)
		pm.ErrorCount = errorCount
	}
}

// AddComponent adds a component to the current phase
func (m *ShutdownMetrics) AddComponent(phase ShutdownPhase, component string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if pm, ok := m.PhaseMetrics[phase]; ok {
		pm.Components = append(pm.Components, component)
	}
}

// Finalize completes the metrics collection
func (m *ShutdownMetrics) Finalize(totalErrors int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.EndTime = time.Now()
	m.Duration = m.EndTime.Sub(m.StartTime)
	m.ErrorCount = totalErrors
	
	// Count total components
	for _, pm := range m.PhaseMetrics {
		m.ComponentsCount += len(pm.Components)
	}
}

// String returns a formatted summary of shutdown metrics
func (m *ShutdownMetrics) String() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var sb strings.Builder
	sb.WriteString("\n=== Shutdown Metrics ===\n")
	sb.WriteString(fmt.Sprintf("Total Duration: %v\n", m.Duration))
	sb.WriteString(fmt.Sprintf("Total Components: %d\n", m.ComponentsCount))
	sb.WriteString(fmt.Sprintf("Total Errors: %d\n", m.ErrorCount))
	
	if len(m.PhaseMetrics) > 0 {
		sb.WriteString("\nPhase Breakdown:\n")
		for _, phase := range []ShutdownPhase{PhaseListeners, PhaseConnections, PhasePools, PhaseServices, PhaseTracers, PhaseCleanup} {
			if pm, ok := m.PhaseMetrics[phase]; ok {
				sb.WriteString(fmt.Sprintf("  [%s]: %v (%d components, %d errors)\n", 
					phase, pm.Duration, len(pm.Components), pm.ErrorCount))
			}
		}
	}
	
	return sb.String()
}