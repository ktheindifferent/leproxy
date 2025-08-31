package tracing

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConfigValidator provides validation and health checking for tracing configuration
type ConfigValidator struct {
	mu              sync.RWMutex
	healthCache     map[string]*endpointHealth
	circuitBreakers map[string]*CircuitBreaker
}

// endpointHealth tracks the health status of an endpoint
type endpointHealth struct {
	endpoint    string
	lastChecked time.Time
	isHealthy   bool
	lastError   error
	checkCount  int64
}

// CircuitBreaker implements the circuit breaker pattern for exporters
type CircuitBreaker struct {
	mu           sync.RWMutex
	state        int32 // 0: closed, 1: open, 2: half-open
	failures     int32
	successCount int32
	lastFailTime time.Time
	
	// Configuration
	maxFailures      int32
	timeout          time.Duration
	halfOpenRequests int32
}

// Circuit breaker states
const (
	StateClosed = iota
	StateOpen
	StateHalfOpen
)

// Default configuration values
const (
	DefaultConnectionTimeout = 5 * time.Second
	DefaultExportTimeout     = 10 * time.Second
	DefaultMaxRetries        = 3
	DefaultRetryDelay        = 1 * time.Second
	DefaultHealthCheckTimeout = 3 * time.Second
	DefaultCircuitBreakerThreshold = 5
	DefaultCircuitBreakerTimeout = 30 * time.Second
)

// ExtendedConfig extends the base Config with validation and timeout settings
type ExtendedConfig struct {
	Config
	
	// Timeout configuration
	ConnectionTimeout time.Duration
	ExportTimeout     time.Duration
	
	// Retry configuration
	MaxRetries        int
	RetryDelay        time.Duration
	EnableExponentialBackoff bool
	
	// Health check configuration
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	
	// Fallback configuration
	EnableFallback      bool
	FallbackToStdout    bool
	
	// Circuit breaker configuration
	EnableCircuitBreaker bool
	CircuitBreakerThreshold int32
	CircuitBreakerTimeout time.Duration
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		healthCache:     make(map[string]*endpointHealth),
		circuitBreakers: make(map[string]*CircuitBreaker),
	}
}

// ValidateConfig validates the tracing configuration
func (cv *ConfigValidator) ValidateConfig(cfg *ExtendedConfig) error {
	// Set defaults if not specified
	cv.setDefaults(cfg)
	
	// Validate basic configuration
	if cfg.Enabled && cfg.ServiceName == "" {
		return fmt.Errorf("service name is required when tracing is enabled")
	}
	
	if cfg.SampleRate < 0 || cfg.SampleRate > 1 {
		return fmt.Errorf("sample rate must be between 0 and 1, got %f", cfg.SampleRate)
	}
	
	// Validate exporter configuration
	switch cfg.ExporterType {
	case "jaeger":
		if err := cv.validateJaegerEndpoint(cfg); err != nil {
			return fmt.Errorf("invalid Jaeger configuration: %w", err)
		}
	case "otlp":
		if err := cv.validateOTLPEndpoint(cfg); err != nil {
			return fmt.Errorf("invalid OTLP configuration: %w", err)
		}
	case "stdout":
		// Stdout exporter doesn't need validation
	default:
		if cfg.ExporterType != "" {
			return fmt.Errorf("unsupported exporter type: %s", cfg.ExporterType)
		}
	}
	
	return nil
}

// setDefaults sets default values for the configuration
func (cv *ConfigValidator) setDefaults(cfg *ExtendedConfig) {
	if cfg.ConnectionTimeout == 0 {
		cfg.ConnectionTimeout = DefaultConnectionTimeout
	}
	if cfg.ExportTimeout == 0 {
		cfg.ExportTimeout = DefaultExportTimeout
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = DefaultRetryDelay
	}
	if cfg.HealthCheckTimeout == 0 {
		cfg.HealthCheckTimeout = DefaultHealthCheckTimeout
	}
	if cfg.CircuitBreakerThreshold == 0 {
		cfg.CircuitBreakerThreshold = DefaultCircuitBreakerThreshold
	}
	if cfg.CircuitBreakerTimeout == 0 {
		cfg.CircuitBreakerTimeout = DefaultCircuitBreakerTimeout
	}
	
	// Enable fallback by default
	if !cfg.EnableFallback {
		cfg.EnableFallback = true
		cfg.FallbackToStdout = true
	}
}

// validateJaegerEndpoint validates the Jaeger endpoint
func (cv *ConfigValidator) validateJaegerEndpoint(cfg *ExtendedConfig) error {
	endpoint := cfg.JaegerEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:14268/api/traces"
		cfg.JaegerEndpoint = endpoint
	}
	
	// Parse URL
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid Jaeger endpoint URL: %w", err)
	}
	
	// Ensure it's HTTP or HTTPS
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("Jaeger endpoint must use http or https scheme, got %s", u.Scheme)
	}
	
	// Check if we can resolve the host (DNS check)
	host := u.Hostname()
	if host != "localhost" && host != "127.0.0.1" {
		if err := cv.checkDNS(host); err != nil {
			return fmt.Errorf("cannot resolve Jaeger host %s: %w", host, err)
		}
	}
	
	return nil
}

// validateOTLPEndpoint validates the OTLP endpoint
func (cv *ConfigValidator) validateOTLPEndpoint(cfg *ExtendedConfig) error {
	endpoint := cfg.OTLPEndpoint
	if endpoint == "" {
		endpoint = "localhost:4317"
		cfg.OTLPEndpoint = endpoint
	}
	
	// Check if it's a valid host:port format
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		// Try adding default port
		if !strings.Contains(endpoint, ":") {
			endpoint = endpoint + ":4317"
			cfg.OTLPEndpoint = endpoint
			host, port, err = net.SplitHostPort(endpoint)
			if err != nil {
				return fmt.Errorf("invalid OTLP endpoint format: %w", err)
			}
		} else {
			return fmt.Errorf("invalid OTLP endpoint format: %w", err)
		}
	}
	
	// Validate port
	if port == "" {
		return fmt.Errorf("OTLP endpoint must include a port")
	}
	
	// Check DNS resolution
	if host != "localhost" && host != "127.0.0.1" {
		if err := cv.checkDNS(host); err != nil {
			return fmt.Errorf("cannot resolve OTLP host %s: %w", host, err)
		}
	}
	
	return nil
}

// checkDNS checks if a hostname can be resolved
func (cv *ConfigValidator) checkDNS(host string) error {
	ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second) // TODO: Pass context from validator initialization
	defer cancel()
	
	resolver := &net.Resolver{}
	_, err := resolver.LookupHost(ctx, host)
	return err
}

// CheckEndpointHealth performs a health check on the specified endpoint
func (cv *ConfigValidator) CheckEndpointHealth(ctx context.Context, exporterType, endpoint string) (bool, error) {
	cv.mu.Lock()
	health, exists := cv.healthCache[endpoint]
	if !exists {
		health = &endpointHealth{
			endpoint: endpoint,
		}
		cv.healthCache[endpoint] = health
	}
	cv.mu.Unlock()
	
	// Check if we have a recent health check result
	if time.Since(health.lastChecked) < 30*time.Second && health.checkCount > 0 {
		return health.isHealthy, health.lastError
	}
	
	// Perform health check based on exporter type
	var err error
	var isHealthy bool
	
	switch exporterType {
	case "jaeger":
		isHealthy, err = cv.checkJaegerHealth(ctx, endpoint)
	case "otlp":
		isHealthy, err = cv.checkOTLPHealth(ctx, endpoint)
	default:
		// Stdout or unknown exporters are always considered healthy
		isHealthy = true
	}
	
	// Update health cache
	cv.mu.Lock()
	health.lastChecked = time.Now()
	health.isHealthy = isHealthy
	health.lastError = err
	atomic.AddInt64(&health.checkCount, 1)
	cv.mu.Unlock()
	
	return isHealthy, err
}

// checkJaegerHealth checks if the Jaeger endpoint is reachable
func (cv *ConfigValidator) checkJaegerHealth(ctx context.Context, endpoint string) (bool, error) {
	// For Jaeger, we can do a simple HTTP GET to check connectivity
	// Note: The actual traces endpoint might not support GET, but we can check the base URL
	u, err := url.Parse(endpoint)
	if err != nil {
		return false, err
	}
	
	// Try to connect to the base URL
	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	
	client := &http.Client{
		Timeout: DefaultHealthCheckTimeout,
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return false, err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("Jaeger endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()
	
	// Any response (even 404) means the server is reachable
	return true, nil
}

// checkOTLPHealth checks if the OTLP endpoint is reachable
func (cv *ConfigValidator) checkOTLPHealth(ctx context.Context, endpoint string) (bool, error) {
	// For gRPC endpoints, try to establish a TCP connection
	dialer := &net.Dialer{
		Timeout: DefaultHealthCheckTimeout,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return false, fmt.Errorf("OTLP endpoint unreachable: %w", err)
	}
	conn.Close()
	
	return true, nil
}

// GetCircuitBreaker returns or creates a circuit breaker for the endpoint
func (cv *ConfigValidator) GetCircuitBreaker(endpoint string, threshold int32, timeout time.Duration) *CircuitBreaker {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	
	cb, exists := cv.circuitBreakers[endpoint]
	if !exists {
		cb = NewCircuitBreaker(threshold, timeout)
		cv.circuitBreakers[endpoint] = cb
	}
	
	return cb
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int32, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            StateClosed,
		maxFailures:      maxFailures,
		timeout:          timeout,
		halfOpenRequests: 3, // Allow 3 requests in half-open state
	}
}

// Call executes the function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	state := atomic.LoadInt32(&cb.state)
	
	switch state {
	case StateOpen:
		// Check if we should transition to half-open
		cb.mu.RLock()
		shouldTransition := time.Since(cb.lastFailTime) > cb.timeout
		cb.mu.RUnlock()
		
		if shouldTransition {
			atomic.CompareAndSwapInt32(&cb.state, StateOpen, StateHalfOpen)
			atomic.StoreInt32(&cb.successCount, 0)
		} else {
			return fmt.Errorf("circuit breaker is open")
		}
		
	case StateHalfOpen:
		// Check if we've exceeded the half-open request limit
		if atomic.LoadInt32(&cb.successCount) >= cb.halfOpenRequests {
			// Transition back to closed if all requests succeeded
			atomic.CompareAndSwapInt32(&cb.state, StateHalfOpen, StateClosed)
			atomic.StoreInt32(&cb.failures, 0)
		}
	}
	
	// Execute the function
	err := fn()
	
	if err != nil {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}
	
	return err
}

// onFailure handles a failed call
func (cb *CircuitBreaker) onFailure() {
	failures := atomic.AddInt32(&cb.failures, 1)
	
	cb.mu.Lock()
	cb.lastFailTime = time.Now()
	cb.mu.Unlock()
	
	if failures >= cb.maxFailures {
		atomic.StoreInt32(&cb.state, StateOpen)
	}
	
	// If in half-open state, immediately go back to open
	if atomic.LoadInt32(&cb.state) == StateHalfOpen {
		atomic.StoreInt32(&cb.state, StateOpen)
	}
}

// onSuccess handles a successful call
func (cb *CircuitBreaker) onSuccess() {
	state := atomic.LoadInt32(&cb.state)
	
	if state == StateHalfOpen {
		successCount := atomic.AddInt32(&cb.successCount, 1)
		if successCount >= cb.halfOpenRequests {
			// All half-open requests succeeded, close the circuit
			atomic.StoreInt32(&cb.state, StateClosed)
			atomic.StoreInt32(&cb.failures, 0)
		}
	} else if state == StateClosed {
		// Reset failure count on success in closed state
		atomic.StoreInt32(&cb.failures, 0)
	}
}

// IsOpen returns true if the circuit breaker is open
func (cb *CircuitBreaker) IsOpen() bool {
	return atomic.LoadInt32(&cb.state) == StateOpen
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() string {
	state := atomic.LoadInt32(&cb.state)
	switch state {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// RetryWithBackoff performs an operation with exponential backoff retry
func RetryWithBackoff(ctx context.Context, operation func() error, maxRetries int, initialDelay time.Duration) error {
	var lastErr error
	delay := initialDelay
	
	for i := 0; i < maxRetries; i++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Try the operation
		if err := operation(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		
		// Don't sleep after the last attempt
		if i < maxRetries-1 {
			select {
			case <-time.After(delay):
				// Exponential backoff with jitter
				jitter := float64(time.Now().UnixNano()%100) / 100.0
				delay = time.Duration(float64(delay) * (1.5 + 0.5*jitter))
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	
	return fmt.Errorf("operation failed after %d retries: %w", maxRetries, lastErr)
}