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

func TestConfigValidator_ValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  ExtendedConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid_jaeger_config",
			config: ExtendedConfig{
				Config: Config{
					Enabled:        true,
					ServiceName:    "test-service",
					ExporterType:   "jaeger",
					JaegerEndpoint: "http://localhost:14268/api/traces",
					SampleRate:     0.5,
				},
			},
			wantErr: false,
		},
		{
			name: "valid_otlp_config",
			config: ExtendedConfig{
				Config: Config{
					Enabled:      true,
					ServiceName:  "test-service",
					ExporterType: "otlp",
					OTLPEndpoint: "localhost:4317",
					SampleRate:   1.0,
				},
			},
			wantErr: false,
		},
		{
			name: "valid_stdout_config",
			config: ExtendedConfig{
				Config: Config{
					Enabled:      true,
					ServiceName:  "test-service",
					ExporterType: "stdout",
					SampleRate:   0.1,
				},
			},
			wantErr: false,
		},
		{
			name: "disabled_tracing",
			config: ExtendedConfig{
				Config: Config{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "missing_service_name",
			config: ExtendedConfig{
				Config: Config{
					Enabled:      true,
					ExporterType: "jaeger",
				},
			},
			wantErr: true,
			errMsg:  "service name is required",
		},
		{
			name: "invalid_sample_rate_negative",
			config: ExtendedConfig{
				Config: Config{
					Enabled:     true,
					ServiceName: "test-service",
					SampleRate:  -0.1,
				},
			},
			wantErr: true,
			errMsg:  "sample rate must be between 0 and 1",
		},
		{
			name: "invalid_sample_rate_too_high",
			config: ExtendedConfig{
				Config: Config{
					Enabled:     true,
					ServiceName: "test-service",
					SampleRate:  1.5,
				},
			},
			wantErr: true,
			errMsg:  "sample rate must be between 0 and 1",
		},
		{
			name: "invalid_jaeger_url",
			config: ExtendedConfig{
				Config: Config{
					Enabled:        true,
					ServiceName:    "test-service",
					ExporterType:   "jaeger",
					JaegerEndpoint: "not-a-url",
				},
			},
			wantErr: true,
			errMsg:  "Jaeger endpoint must use http or https scheme",
		},
		{
			name: "invalid_otlp_endpoint",
			config: ExtendedConfig{
				Config: Config{
					Enabled:      true,
					ServiceName:  "test-service",
					ExporterType: "otlp",
					OTLPEndpoint: "invalid:port:format",
				},
			},
			wantErr: true,
			errMsg:  "invalid OTLP endpoint format",
		},
		{
			name: "unsupported_exporter_type",
			config: ExtendedConfig{
				Config: Config{
					Enabled:      true,
					ServiceName:  "test-service",
					ExporterType: "unsupported",
				},
			},
			wantErr: true,
			errMsg:  "unsupported exporter type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cv := NewConfigValidator()
			err := cv.ValidateConfig(&tt.config)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateConfig() error message = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestConfigValidator_CheckEndpointHealth(t *testing.T) {
	// Start a test HTTP server for Jaeger endpoint
	jaegerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer jaegerServer.Close()

	// Start a test TCP listener for OTLP endpoint
	otlpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create OTLP listener: %v", err)
	}
	defer otlpListener.Close()
	
	go func() {
		for {
			conn, err := otlpListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	tests := []struct {
		name         string
		exporterType string
		endpoint     string
		wantHealthy  bool
	}{
		{
			name:         "healthy_jaeger_endpoint",
			exporterType: "jaeger",
			endpoint:     jaegerServer.URL + "/api/traces",
			wantHealthy:  true,
		},
		{
			name:         "unhealthy_jaeger_endpoint",
			exporterType: "jaeger",
			endpoint:     "http://localhost:99999/api/traces",
			wantHealthy:  false,
		},
		{
			name:         "healthy_otlp_endpoint",
			exporterType: "otlp",
			endpoint:     otlpListener.Addr().String(),
			wantHealthy:  true,
		},
		{
			name:         "unhealthy_otlp_endpoint",
			exporterType: "otlp",
			endpoint:     "localhost:99999",
			wantHealthy:  false,
		},
		{
			name:         "stdout_always_healthy",
			exporterType: "stdout",
			endpoint:     "",
			wantHealthy:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cv := NewConfigValidator()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			
			healthy, _ := cv.CheckEndpointHealth(ctx, tt.exporterType, tt.endpoint)
			
			if healthy != tt.wantHealthy {
				t.Errorf("CheckEndpointHealth() healthy = %v, want %v", healthy, tt.wantHealthy)
			}
		})
	}
}

func TestCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)
	
	// Test initial state
	if cb.GetState() != "closed" {
		t.Errorf("Initial state should be closed, got %s", cb.GetState())
	}
	
	// Test successful calls
	for i := 0; i < 3; i++ {
		err := cb.Call(func() error {
			return nil
		})
		if err != nil {
			t.Errorf("Successful call should not return error, got %v", err)
		}
	}
	
	// Test that circuit is still closed
	if cb.GetState() != "closed" {
		t.Errorf("State should still be closed after successful calls, got %s", cb.GetState())
	}
	
	// Test failures to open the circuit
	for i := 0; i < 3; i++ {
		_ = cb.Call(func() error {
			return fmt.Errorf("test error")
		})
	}
	
	// Circuit should now be open
	if cb.GetState() != "open" {
		t.Errorf("State should be open after failures, got %s", cb.GetState())
	}
	
	// Calls should fail immediately when open
	err := cb.Call(func() error {
		return nil
	})
	if err == nil || !contains(err.Error(), "circuit breaker is open") {
		t.Errorf("Call should fail when circuit is open, got %v", err)
	}
	
	// Wait for timeout to transition to half-open
	time.Sleep(150 * time.Millisecond)
	
	// Next call should be allowed (half-open state)
	err = cb.Call(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Call should succeed in half-open state, got %v", err)
	}
	
	// After successful calls in half-open, circuit should close
	for i := 0; i < 2; i++ {
		_ = cb.Call(func() error {
			return nil
		})
	}
	
	if cb.GetState() != "closed" {
		t.Errorf("State should be closed after successful half-open calls, got %s", cb.GetState())
	}
}

func TestRetryWithBackoff(t *testing.T) {
	tests := []struct {
		name        string
		operation   func() error
		maxRetries  int
		wantSuccess bool
	}{
		{
			name: "successful_first_try",
			operation: func() error {
				return nil
			},
			maxRetries:  3,
			wantSuccess: true,
		},
		{
			name: "successful_after_retry",
			operation: func() func() error {
				count := 0
				return func() error {
					count++
					if count < 3 {
						return fmt.Errorf("temporary error")
					}
					return nil
				}
			}(),
			maxRetries:  3,
			wantSuccess: true,
		},
		{
			name: "all_retries_fail",
			operation: func() error {
				return fmt.Errorf("permanent error")
			},
			maxRetries:  2,
			wantSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := RetryWithBackoff(ctx, tt.operation, tt.maxRetries, 10*time.Millisecond)
			
			if (err == nil) != tt.wantSuccess {
				t.Errorf("RetryWithBackoff() success = %v, want %v, error: %v", err == nil, tt.wantSuccess, err)
			}
		})
	}
}

func TestRetryWithBackoff_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Cancel context immediately
	cancel()
	
	callCount := 0
	err := RetryWithBackoff(ctx, func() error {
		callCount++
		return fmt.Errorf("error")
	}, 3, 100*time.Millisecond)
	
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
	
	if callCount > 1 {
		t.Errorf("Expected at most 1 call when context is cancelled, got %d", callCount)
	}
}

func TestMetricsCollector(t *testing.T) {
	mc := NewMetricsCollector()
	
	// Record some successes
	mc.RecordExportSuccess("jaeger", 10*time.Millisecond)
	mc.RecordExportSuccess("jaeger", 20*time.Millisecond)
	mc.RecordExportSuccess("otlp", 15*time.Millisecond)
	
	// Record some failures
	mc.RecordExportFailure("jaeger", "timeout")
	mc.RecordExportFailure("jaeger", "timeout")
	mc.RecordExportFailure("otlp", "connection_refused")
	
	// Record fallback activation
	mc.RecordFallbackActivation()
	mc.RecordFallbackActivation()
	
	// Get metrics
	metrics := mc.GetMetrics()
	
	// Check export successes
	successes := metrics["export_successes"].(map[string]int64)
	if successes["jaeger"] != 2 {
		t.Errorf("Expected 2 Jaeger successes, got %d", successes["jaeger"])
	}
	if successes["otlp"] != 1 {
		t.Errorf("Expected 1 OTLP success, got %d", successes["otlp"])
	}
	
	// Check export failures
	failures := metrics["export_failures"].(map[string]int64)
	if failures["jaeger_timeout"] != 2 {
		t.Errorf("Expected 2 Jaeger timeout failures, got %d", failures["jaeger_timeout"])
	}
	if failures["otlp_connection_refused"] != 1 {
		t.Errorf("Expected 1 OTLP connection refused failure, got %d", failures["otlp_connection_refused"])
	}
	
	// Check fallback activations
	if metrics["fallback_activations"].(int64) != 2 {
		t.Errorf("Expected 2 fallback activations, got %d", metrics["fallback_activations"])
	}
	
	// Check average latencies
	avgLatencies := metrics["average_export_latencies_ms"].(map[string]float64)
	if avgLatencies["jaeger"] != 15.0 { // (10 + 20) / 2
		t.Errorf("Expected average Jaeger latency of 15ms, got %f", avgLatencies["jaeger"])
	}
	if avgLatencies["otlp"] != 15.0 {
		t.Errorf("Expected average OTLP latency of 15ms, got %f", avgLatencies["otlp"])
	}
}

func TestTracerProviderWithFallback(t *testing.T) {
	// Test with unreachable endpoint to trigger fallback
	cfg := ExtendedConfig{
		Config: Config{
			Enabled:        true,
			ServiceName:    "test-service",
			ExporterType:   "jaeger",
			JaegerEndpoint: "http://localhost:99999/api/traces",
			SampleRate:     1.0,
		},
		EnableFallback:   true,
		FallbackToStdout: true,
		MaxRetries:       1,
		RetryDelay:       10 * time.Millisecond,
		ConnectionTimeout: 100 * time.Millisecond,
	}
	
	tp, err := NewTracerProviderWithExtendedConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to create tracer provider with fallback: %v", err)
	}
	defer tp.Shutdown(context.Background())
	
	// Check that fallback is active
	if !tp.IsFallbackActive() {
		t.Error("Expected fallback to be active with unreachable endpoint")
	}
	
	// Test that tracing still works with fallback
	ctx := context.Background()
	ctx, span := tp.StartSpan(ctx, "test-span")
	span.End()
	
	// Check metrics
	metrics := tp.GetMetrics()
	if metrics == nil {
		t.Error("Expected metrics to be available")
	}
}

func TestDefaultsAreSet(t *testing.T) {
	cfg := &ExtendedConfig{
		Config: Config{
			Enabled:     true,
			ServiceName: "test",
		},
	}
	
	cv := NewConfigValidator()
	cv.setDefaults(cfg)
	
	if cfg.ConnectionTimeout != DefaultConnectionTimeout {
		t.Errorf("Expected default connection timeout %v, got %v", DefaultConnectionTimeout, cfg.ConnectionTimeout)
	}
	
	if cfg.ExportTimeout != DefaultExportTimeout {
		t.Errorf("Expected default export timeout %v, got %v", DefaultExportTimeout, cfg.ExportTimeout)
	}
	
	if cfg.MaxRetries != DefaultMaxRetries {
		t.Errorf("Expected default max retries %d, got %d", DefaultMaxRetries, cfg.MaxRetries)
	}
	
	if cfg.RetryDelay != DefaultRetryDelay {
		t.Errorf("Expected default retry delay %v, got %v", DefaultRetryDelay, cfg.RetryDelay)
	}
	
	if !cfg.EnableFallback {
		t.Error("Expected fallback to be enabled by default")
	}
	
	if !cfg.FallbackToStdout {
		t.Error("Expected fallback to stdout to be enabled by default")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && s[0:len(substr)] == substr || len(s) > len(substr) && s[len(s)-len(substr):] == substr || len(substr) > 0 && len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}