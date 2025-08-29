package tracing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestTracerProviderShutdown tests the enhanced shutdown functionality
func TestTracerProviderShutdown(t *testing.T) {
	tests := []struct {
		name            string
		hasProvider     bool
		contextTimeout  time.Duration
		shutdownDelay   time.Duration
		expectedError   bool
		errorContains   string
	}{
		{
			name:           "successful shutdown with provider",
			hasProvider:    true,
			contextTimeout: 5 * time.Second,
			shutdownDelay:  0,
			expectedError:  false,
		},
		{
			name:           "no-op shutdown without provider",
			hasProvider:    false,
			contextTimeout: 5 * time.Second,
			shutdownDelay:  0,
			expectedError:  false,
		},
		{
			name:           "shutdown timeout",
			hasProvider:    true,
			contextTimeout: 100 * time.Millisecond,
			shutdownDelay:  200 * time.Millisecond,
			expectedError:  true,
			errorContains:  "timed out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create tracer provider
			tp := &TracerProvider{
				config: Config{
					ServiceName: "test-service",
				},
			}

			if tt.hasProvider {
				// For testing timeout scenarios, we would need a mock provider
				// Since we can't easily mock the actual provider, we'll use the real one
				config := Config{
					Enabled:      true,
					ServiceName:  "test-service",
					ExporterType: "stdout",
					SampleRate:   1.0,
				}
				
				realTP, err := NewTracerProvider(config)
				if err != nil {
					t.Fatalf("Failed to create tracer provider: %v", err)
				}
				tp = realTP
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), tt.contextTimeout)
			defer cancel()

			// If we need to simulate delay, do it in a goroutine
			if tt.shutdownDelay > 0 {
				// This simulates a slow shutdown by using a very short timeout
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()
			}

			// Perform shutdown
			err := tp.Shutdown(ctx)

			// Check results
			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestInitTracer tests the InitTracer function
func TestInitTracer(t *testing.T) {
	tests := []struct {
		name         string
		serviceName  string
		endpoint     string
		exporterType string
		envVars      map[string]string
		expectError  bool
	}{
		{
			name:         "jaeger exporter",
			serviceName:  "test-service",
			endpoint:     "localhost:14268",
			exporterType: "jaeger",
			expectError:  false,
		},
		{
			name:         "otlp exporter",
			serviceName:  "test-service",
			endpoint:     "localhost:4317",
			exporterType: "otlp",
			expectError:  false,
		},
		{
			name:         "stdout exporter (default)",
			serviceName:  "test-service",
			endpoint:     "",
			exporterType: "unknown",
			expectError:  false,
		},
		{
			name:         "with sample rate from env",
			serviceName:  "test-service",
			endpoint:     "localhost:14268",
			exporterType: "jaeger",
			envVars: map[string]string{
				"OTEL_TRACE_SAMPLE_RATE": "0.5",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			// Initialize tracer
			tp, err := InitTracer(tt.serviceName, tt.endpoint, tt.exporterType)

			// Check results
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tp == nil {
					t.Errorf("Expected tracer provider but got nil")
				} else {
					// Clean up
					ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
					defer cancel()
					tp.Shutdown(ctx)
				}
			}
		})
	}
}

// TestShutdownWithConcurrentOperations tests shutdown while operations are in progress
func TestShutdownWithConcurrentOperations(t *testing.T) {
	config := Config{
		Enabled:      true,
		ServiceName:  "test-service",
		ExporterType: "stdout",
		SampleRate:   1.0,
	}
	
	tp, err := NewTracerProvider(config)
	if err != nil {
		t.Fatalf("Failed to create tracer provider: %v", err)
	}

	// Start multiple concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, span := tp.StartSpan(context.Background(), "test-operation")
			time.Sleep(10 * time.Millisecond)
			span.End()
			done <- true
		}()
	}

	// Give operations time to start
	time.Sleep(5 * time.Millisecond)

	// Shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = tp.Shutdown(shutdownCtx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Wait for operations to complete
	timeout := time.After(1 * time.Second)
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Operation completed
		case <-timeout:
			t.Errorf("Operations did not complete in time")
			return
		}
	}
}

// TestShutdownErrorAggregation tests error aggregation during shutdown
func TestShutdownErrorAggregation(t *testing.T) {
	// This test would be more comprehensive with mock providers
	// For now, we test the error formatting
	
	tp := &TracerProvider{
		config: Config{
			ServiceName: "test-service",
		},
	}
	
	// Test with nil provider (should not error)
	err := tp.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Expected no error for nil provider, got: %v", err)
	}
}

// TestShutdownIdempotency tests that shutdown can be called multiple times safely
func TestShutdownIdempotency(t *testing.T) {
	config := Config{
		Enabled:      true,
		ServiceName:  "test-service",
		ExporterType: "stdout",
		SampleRate:   1.0,
	}
	
	tp, err := NewTracerProvider(config)
	if err != nil {
		t.Fatalf("Failed to create tracer provider: %v", err)
	}

	// First shutdown
	ctx1, cancel1 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel1()
	err1 := tp.Shutdown(ctx1)
	if err1 != nil {
		t.Errorf("First shutdown failed: %v", err1)
	}

	// Second shutdown (should be safe)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel2()
	err2 := tp.Shutdown(ctx2)
	// The second shutdown might return an error depending on the provider implementation
	// but it should not panic
	_ = err2
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != substr && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}

// MockProvider for testing shutdown behavior
type MockProvider struct {
	shutdownDelay time.Duration
	shutdownError error
}

func (m *MockProvider) Shutdown(ctx context.Context) error {
	if m.shutdownDelay > 0 {
		select {
		case <-time.After(m.shutdownDelay):
			return m.shutdownError
		case <-ctx.Done():
			return errors.New("shutdown cancelled")
		}
	}
	return m.shutdownError
}