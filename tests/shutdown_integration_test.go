package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/artyom/leproxy/internal/graceful"
	"github.com/artyom/leproxy/internal/tracing"
)

// TestIntegratedShutdown tests the complete shutdown flow with all components
func TestIntegratedShutdown(t *testing.T) {
	// Create a test HTTP server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	httpServer := &http.Server{
		Handler:        handler,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    60 * time.Second,
	}
	
	// Initialize tracing
	tracerProvider, err := tracing.InitTracer("test-service", "", "stdout")
	if err != nil {
		t.Fatalf("Failed to initialize tracer: %v", err)
	}
	
	// Create graceful server
	gracefulServer := graceful.New(graceful.Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 10 * time.Second,
	})
	
	// Create shutdown coordinator
	coordinator := graceful.NewShutdownCoordinator(gracefulServer, 15*time.Second)
	
	// Add tracer shutdown
	coordinator.AddShutdownFunc(
		"tracer",
		func(ctx context.Context) error {
			return tracerProvider.Shutdown(ctx)
		},
		5*time.Second,
	)
	
	// Add mock metrics server shutdown
	metricsShutdown := false
	coordinator.AddShutdownFunc(
		"metrics",
		func(ctx context.Context) error {
			metricsShutdown = true
			return nil
		},
		2*time.Second,
	)
	
	// Add mock health server shutdown
	healthShutdown := false
	coordinator.AddShutdownFunc(
		"health",
		func(ctx context.Context) error {
			healthShutdown = true
			return nil
		},
		2*time.Second,
	)
	
	// Start test server
	testServer := httptest.NewUnstartedServer(handler)
	listener := testServer.Listener
	
	// Start the graceful server in a goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- gracefulServer.Serve(listener)
	}()
	
	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	
	// Make a request to ensure server is running
	resp, err := http.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
	
	// Perform coordinated shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	err = coordinator.Shutdown(shutdownCtx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
	
	// Verify all components were shutdown
	if !metricsShutdown {
		t.Error("Metrics server was not shutdown")
	}
	if !healthShutdown {
		t.Error("Health server was not shutdown")
	}
	
	// Verify server is no longer accepting connections
	_, err = http.Get("http://" + listener.Addr().String())
	if err == nil {
		t.Error("Server still accepting connections after shutdown")
	}
}

// TestShutdownUnderLoad tests shutdown while handling active requests
func TestShutdownUnderLoad(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		
		// Simulate work
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	
	httpServer := &http.Server{
		Handler: handler,
	}
	
	// Initialize tracing
	tracerProvider, err := tracing.InitTracer("load-test-service", "", "stdout")
	if err != nil {
		t.Fatalf("Failed to initialize tracer: %v", err)
	}
	
	// Create graceful server
	gracefulServer := graceful.New(graceful.Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	// Create shutdown coordinator
	coordinator := graceful.NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add tracer shutdown
	coordinator.AddShutdownFunc(
		"tracer",
		func(ctx context.Context) error {
			return tracerProvider.Shutdown(ctx)
		},
		3*time.Second,
	)
	
	// Start test server
	testServer := httptest.NewUnstartedServer(handler)
	listener := testServer.Listener
	
	// Start the server
	go gracefulServer.Serve(listener)
	
	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	
	// Start making concurrent requests
	var wg sync.WaitGroup
	stopRequests := make(chan struct{})
	
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: 1 * time.Second,
			}
			
			for {
				select {
				case <-stopRequests:
					return
				default:
					req, _ := http.NewRequest("GET", "http://"+listener.Addr().String(), nil)
					ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
					req = req.WithContext(ctx)
					
					resp, err := client.Do(req)
					if err == nil {
						resp.Body.Close()
					}
					cancel()
					
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
	}
	
	// Let requests run for a bit
	time.Sleep(200 * time.Millisecond)
	
	// Initiate shutdown while requests are in flight
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	shutdownComplete := make(chan error, 1)
	go func() {
		shutdownComplete <- coordinator.Shutdown(shutdownCtx)
	}()
	
	// Stop generating new requests
	close(stopRequests)
	
	// Wait for shutdown to complete
	select {
	case err := <-shutdownComplete:
		if err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("Shutdown timed out")
	}
	
	// Wait for request goroutines to finish
	wg.Wait()
	
	mu.Lock()
	finalCount := requestCount
	mu.Unlock()
	
	if finalCount == 0 {
		t.Error("No requests were processed")
	}
	
	t.Logf("Processed %d requests before shutdown", finalCount)
}

// TestShutdownWithFailingComponent tests shutdown when one component fails
func TestShutdownWithFailingComponent(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	// Initialize tracing
	tracerProvider, err := tracing.InitTracer("fail-test-service", "", "stdout")
	if err != nil {
		t.Fatalf("Failed to initialize tracer: %v", err)
	}
	
	// Create graceful server
	gracefulServer := graceful.New(graceful.Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	// Create shutdown coordinator
	coordinator := graceful.NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add tracer shutdown
	coordinator.AddShutdownFunc(
		"tracer",
		func(ctx context.Context) error {
			return tracerProvider.Shutdown(ctx)
		},
		3*time.Second,
	)
	
	// Add a failing component
	coordinator.AddShutdownFunc(
		"failing-component",
		func(ctx context.Context) error {
			return errors.New("component failed to shutdown")
		},
		2*time.Second,
	)
	
	// Add a successful component
	successfulShutdown := false
	coordinator.AddShutdownFunc(
		"successful-component",
		func(ctx context.Context) error {
			successfulShutdown = true
			return nil
		},
		2*time.Second,
	)
	
	// Perform shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	err = coordinator.Shutdown(shutdownCtx)
	
	// We expect an error due to the failing component
	if err == nil {
		t.Error("Expected error from failing component, got nil")
	} else if !contains(err.Error(), "component failed to shutdown") {
		t.Errorf("Error should mention failing component: %v", err)
	}
	
	// But the successful component should still have been shutdown
	if !successfulShutdown {
		t.Error("Successful component was not shutdown despite another component failing")
	}
}

// TestSignalHandling tests signal-based shutdown
func TestSignalHandling(t *testing.T) {
	if os.Getenv("BE_SUBPROCESS") == "1" {
		// This is the subprocess that will receive signals
		runSignalTestSubprocess()
		return
	}
	
	// Skip this test in short mode as it involves subprocesses
	if testing.Short() {
		t.Skip("Skipping signal test in short mode")
	}
	
	// This test would require running a subprocess and sending it signals
	// For now, we'll just document the expected behavior
	t.Log("Signal handling test would verify SIGINT and SIGTERM trigger graceful shutdown")
}

// runSignalTestSubprocess runs the actual signal test logic
func runSignalTestSubprocess() {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := graceful.New(graceful.Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	coordinator := graceful.NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Start signal handler
	go coordinator.HandleSignals()
	
	// Signal readiness
	os.Stdout.Write([]byte("READY\n"))
	
	// Wait for signal
	select {}
}

// TestShutdownTimeout tests that shutdown respects timeout
func TestShutdownTimeout(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate a very slow request
			time.Sleep(10 * time.Second)
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := graceful.New(graceful.Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 1 * time.Second, // Short timeout
	})
	
	coordinator := graceful.NewShutdownCoordinator(gracefulServer, 2*time.Second)
	
	// Add a slow shutdown function
	coordinator.AddShutdownFunc(
		"slow-component",
		func(ctx context.Context) error {
			select {
			case <-time.After(5 * time.Second):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		500*time.Millisecond, // Very short timeout for this component
	)
	
	// Start test server
	testServer := httptest.NewUnstartedServer(httpServer.Handler)
	listener := testServer.Listener
	
	// Start the server
	go gracefulServer.Serve(listener)
	
	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	
	// Start a slow request
	go func() {
		http.Get("http://" + listener.Addr().String())
	}()
	
	// Give request time to start
	time.Sleep(50 * time.Millisecond)
	
	// Perform shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	start := time.Now()
	err := coordinator.Shutdown(shutdownCtx)
	elapsed := time.Since(start)
	
	// Should complete within the timeout period (plus a small buffer)
	if elapsed > 2*time.Second {
		t.Errorf("Shutdown took too long: %v", elapsed)
	}
	
	// Should have an error due to timeout
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || (len(s) > len(substr) && s[:len(substr)] == substr) || (len(s) > len(substr) && contains(s[1:], substr)))
}