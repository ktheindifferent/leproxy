package safegoroutine

import (
	"sync"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota
	CircuitOpen
	CircuitHalfOpen
)

// CircuitBreakerConfig defines circuit breaker parameters
type CircuitBreakerConfig struct {
	FailureThreshold   int           // Number of failures before opening
	SuccessThreshold   int           // Number of successes to close from half-open
	Timeout           time.Duration // Time before attempting to half-open
	MaxHalfOpenTime   time.Duration // Max time in half-open state
}

// DefaultCircuitBreakerConfig provides default circuit breaker settings
var DefaultCircuitBreakerConfig = CircuitBreakerConfig{
	FailureThreshold: 5,
	SuccessThreshold: 2,
	Timeout:         30 * time.Second,
	MaxHalfOpenTime: 60 * time.Second,
}

// CircuitBreaker implements the circuit breaker pattern for goroutines
type CircuitBreaker struct {
	mu       sync.RWMutex
	config   CircuitBreakerConfig
	breakers map[string]*circuit
}

type circuit struct {
	state            CircuitBreakerState
	failures         int
	successes        int
	lastFailureTime  time.Time
	lastSuccessTime  time.Time
	halfOpenTime     time.Time
	consecutiveFails int
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker() *CircuitBreaker {
	return NewCircuitBreakerWithConfig(DefaultCircuitBreakerConfig)
}

// NewCircuitBreakerWithConfig creates a circuit breaker with custom config
func NewCircuitBreakerWithConfig(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config:   config,
		breakers: make(map[string]*circuit),
	}
}

// Allow checks if a goroutine is allowed to run
func (cb *CircuitBreaker) Allow(name string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	c, exists := cb.breakers[name]
	if !exists {
		c = &circuit{state: CircuitClosed}
		cb.breakers[name] = c
	}
	
	now := time.Now()
	
	switch c.state {
	case CircuitClosed:
		return true
		
	case CircuitOpen:
		// Check if timeout has passed
		if now.Sub(c.lastFailureTime) > cb.config.Timeout {
			c.state = CircuitHalfOpen
			c.halfOpenTime = now
			c.successes = 0
			return true
		}
		return false
		
	case CircuitHalfOpen:
		// Check if we've been half-open too long
		if now.Sub(c.halfOpenTime) > cb.config.MaxHalfOpenTime {
			c.state = CircuitOpen
			c.lastFailureTime = now
			return false
		}
		return true
		
	default:
		return true
	}
}

// RecordSuccess records a successful execution
func (cb *CircuitBreaker) RecordSuccess(name string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	c, exists := cb.breakers[name]
	if !exists {
		return
	}
	
	c.lastSuccessTime = time.Now()
	c.consecutiveFails = 0
	
	switch c.state {
	case CircuitHalfOpen:
		c.successes++
		if c.successes >= cb.config.SuccessThreshold {
			c.state = CircuitClosed
			c.failures = 0
			c.successes = 0
		}
		
	case CircuitOpen:
		// Shouldn't happen, but reset if it does
		c.state = CircuitClosed
		c.failures = 0
		c.successes = 0
	}
}

// RecordFailure records a failed execution
func (cb *CircuitBreaker) RecordFailure(name string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	c, exists := cb.breakers[name]
	if !exists {
		c = &circuit{state: CircuitClosed}
		cb.breakers[name] = c
	}
	
	now := time.Now()
	c.lastFailureTime = now
	c.failures++
	c.consecutiveFails++
	
	switch c.state {
	case CircuitClosed:
		if c.consecutiveFails >= cb.config.FailureThreshold {
			c.state = CircuitOpen
		}
		
	case CircuitHalfOpen:
		// Any failure in half-open goes back to open
		c.state = CircuitOpen
		c.successes = 0
	}
}

// GetState returns the current state of a circuit
func (cb *CircuitBreaker) GetState(name string) CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	c, exists := cb.breakers[name]
	if !exists {
		return CircuitClosed
	}
	
	return c.state
}

// Reset resets a circuit breaker for a specific goroutine
func (cb *CircuitBreaker) Reset(name string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	delete(cb.breakers, name)
}

// ResetAll resets all circuit breakers
func (cb *CircuitBreaker) ResetAll() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.breakers = make(map[string]*circuit)
}

// GetStats returns statistics for a circuit
func (cb *CircuitBreaker) GetStats(name string) (state CircuitBreakerState, failures int, successes int) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	c, exists := cb.breakers[name]
	if !exists {
		return CircuitClosed, 0, 0
	}
	
	return c.state, c.failures, c.successes
}