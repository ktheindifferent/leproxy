package tracing

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDNSCheck(t *testing.T) {
	cv := NewConfigValidator()
	
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{
			name:    "valid_host_localhost",
			host:    "localhost",
			wantErr: false,
		},
		{
			name:    "valid_host_google",
			host:    "google.com",
			wantErr: false,
		},
		{
			name:    "invalid_host",
			host:    "this-host-definitely-does-not-exist-12345.invalid",
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cv.checkDNS(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkDNS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHealthCheckCaching(t *testing.T) {
	cv := NewConfigValidator()
	
	// Create a test server that counts requests
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	ctx := context.Background()
	
	// First health check should hit the server
	healthy, err := cv.CheckEndpointHealth(ctx, "jaeger", server.URL)
	if !healthy || err != nil {
		t.Errorf("First health check failed: healthy=%v, err=%v", healthy, err)
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request after first health check, got %d", requestCount)
	}
	
	// Second health check within cache window should use cache
	healthy, err = cv.CheckEndpointHealth(ctx, "jaeger", server.URL)
	if !healthy || err != nil {
		t.Errorf("Second health check failed: healthy=%v, err=%v", healthy, err)
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request after cached health check, got %d", requestCount)
	}
	
	// Update the cache entry to be expired
	cv.mu.Lock()
	if health, exists := cv.healthCache[server.URL]; exists {
		health.lastChecked = time.Now().Add(-31 * time.Second)
	}
	cv.mu.Unlock()
	
	// Third health check should hit the server again
	healthy, err = cv.CheckEndpointHealth(ctx, "jaeger", server.URL)
	if !healthy || err != nil {
		t.Errorf("Third health check failed: healthy=%v, err=%v", healthy, err)
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests after expired cache, got %d", requestCount)
	}
}

func TestJaegerEndpointValidation(t *testing.T) {
	cv := NewConfigValidator()
	
	tests := []struct {
		name    string
		config  *ExtendedConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_http_endpoint",
			config: &ExtendedConfig{
				Config: Config{
					JaegerEndpoint: "http://localhost:14268/api/traces",
				},
			},
			wantErr: false,
		},
		{
			name: "valid_https_endpoint",
			config: &ExtendedConfig{
				Config: Config{
					JaegerEndpoint: "https://localhost/api/traces",
				},
			},
			wantErr: false,
		},
		{
			name: "empty_endpoint_uses_default",
			config: &ExtendedConfig{
				Config: Config{
					JaegerEndpoint: "",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid_url_scheme",
			config: &ExtendedConfig{
				Config: Config{
					JaegerEndpoint: "ftp://jaeger.example.com/api/traces",
				},
			},
			wantErr: true,
			errMsg:  "must use http or https scheme",
		},
		{
			name: "malformed_url",
			config: &ExtendedConfig{
				Config: Config{
					JaegerEndpoint: "://invalid-url",
				},
			},
			wantErr: true,
			errMsg:  "invalid Jaeger endpoint URL",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cv.validateJaegerEndpoint(tt.config)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("validateJaegerEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("validateJaegerEndpoint() error message = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			}
			
			// Check that default is set when endpoint is empty
			if tt.config.JaegerEndpoint == "" && err == nil {
				expectedDefault := "http://localhost:14268/api/traces"
				if tt.config.JaegerEndpoint != expectedDefault {
					t.Errorf("Expected default endpoint %s, got %s", expectedDefault, tt.config.JaegerEndpoint)
				}
			}
		})
	}
}

func TestOTLPEndpointValidation(t *testing.T) {
	cv := NewConfigValidator()
	
	tests := []struct {
		name    string
		config  *ExtendedConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_endpoint_with_port",
			config: &ExtendedConfig{
				Config: Config{
					OTLPEndpoint: "localhost:4317",
				},
			},
			wantErr: false,
		},
		{
			name: "valid_localhost_endpoint",
			config: &ExtendedConfig{
				Config: Config{
					OTLPEndpoint: "localhost:4317",
				},
			},
			wantErr: false,
		},
		{
			name: "endpoint_without_port_gets_default",
			config: &ExtendedConfig{
				Config: Config{
					OTLPEndpoint: "localhost",
				},
			},
			wantErr: false,
		},
		{
			name: "empty_endpoint_uses_default",
			config: &ExtendedConfig{
				Config: Config{
					OTLPEndpoint: "",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid_port_format",
			config: &ExtendedConfig{
				Config: Config{
					OTLPEndpoint: "host:port:extra",
				},
			},
			wantErr: true,
			errMsg:  "invalid OTLP endpoint format",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cv.validateOTLPEndpoint(tt.config)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOTLPEndpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("validateOTLPEndpoint() error message = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			}
			
			// Check defaults
			if tt.name == "empty_endpoint_uses_default" && err == nil {
				expectedDefault := "localhost:4317"
				if tt.config.OTLPEndpoint != expectedDefault {
					t.Errorf("Expected default endpoint %s, got %s", expectedDefault, tt.config.OTLPEndpoint)
				}
			}
			
			if tt.name == "endpoint_without_port_gets_default" && err == nil {
				expectedEndpoint := "localhost:4317"
				if tt.config.OTLPEndpoint != expectedEndpoint {
					t.Errorf("Expected endpoint with port %s, got %s", expectedEndpoint, tt.config.OTLPEndpoint)
				}
			}
		})
	}
}

func TestOTLPHealthCheck(t *testing.T) {
	cv := NewConfigValidator()
	
	// Start a test TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	
	tests := []struct {
		name        string
		endpoint    string
		wantHealthy bool
	}{
		{
			name:        "reachable_endpoint",
			endpoint:    listener.Addr().String(),
			wantHealthy: true,
		},
		{
			name:        "unreachable_endpoint",
			endpoint:    "localhost:99999",
			wantHealthy: false,
		},
		{
			name:        "invalid_endpoint",
			endpoint:    "not-a-valid-endpoint",
			wantHealthy: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			
			healthy, _ := cv.checkOTLPHealth(ctx, tt.endpoint)
			if healthy != tt.wantHealthy {
				t.Errorf("checkOTLPHealth() healthy = %v, want %v", healthy, tt.wantHealthy)
			}
		})
	}
}

func TestCircuitBreakerStates(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	
	// Verify initial state
	if cb.IsOpen() {
		t.Error("Circuit breaker should not be open initially")
	}
	
	// Test state transitions
	successCount := 0
	failureCount := 0
	
	// Cause failures to open circuit
	for i := 0; i < 2; i++ {
		err := cb.Call(func() error {
			failureCount++
			return fmt.Errorf("error %d", failureCount)
		})
		if err == nil {
			t.Error("Expected error from failing function")
		}
	}
	
	// Circuit should be open
	if !cb.IsOpen() {
		t.Error("Circuit breaker should be open after failures")
	}
	
	// Immediate call should fail
	err := cb.Call(func() error {
		successCount++
		return nil
	})
	if err == nil {
		t.Error("Expected circuit breaker to reject call when open")
	}
	
	// Wait for half-open transition
	time.Sleep(60 * time.Millisecond)
	
	// Should allow test request in half-open state
	err = cb.Call(func() error {
		successCount++
		return nil
	})
	if err != nil {
		t.Errorf("Expected successful call in half-open state, got %v", err)
	}
	
	// Continue with successful calls to close circuit
	for i := 0; i < 2; i++ {
		err = cb.Call(func() error {
			successCount++
			return nil
		})
		if err != nil {
			t.Errorf("Expected successful call, got %v", err)
		}
	}
	
	// Circuit should be closed again
	if cb.IsOpen() {
		t.Error("Circuit breaker should be closed after successful half-open requests")
	}
}

func TestRetryDelayExponentialBackoff(t *testing.T) {
	startTime := time.Now()
	attempts := 0
	
	err := RetryWithBackoff(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return fmt.Errorf("attempt %d failed", attempts)
		}
		return nil
	}, 3, 10*time.Millisecond)
	
	duration := time.Since(startTime)
	
	if err != nil {
		t.Errorf("Expected success after retries, got %v", err)
	}
	
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
	
	// With exponential backoff, total delay should be more than initial delay * 2
	// First retry: 10ms, Second retry: ~15-20ms (with jitter)
	minExpectedDuration := 25 * time.Millisecond
	if duration < minExpectedDuration {
		t.Errorf("Expected at least %v total duration with backoff, got %v", minExpectedDuration, duration)
	}
}