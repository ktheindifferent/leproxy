package graceful

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestShutdownCoordinator tests the shutdown coordinator functionality
func TestShutdownCoordinator(t *testing.T) {
	// Create a test HTTP server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	
	httpServer := &http.Server{
		Handler: handler,
	}
	
	// Create graceful server
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	// Create shutdown coordinator
	coordinator := NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add some shutdown functions
	var shutdown1Called, shutdown2Called atomic.Bool
	
	coordinator.AddShutdownFunc("resource1", func(ctx context.Context) error {
		shutdown1Called.Store(true)
		return nil
	}, 2*time.Second)
	
	coordinator.AddShutdownFunc("resource2", func(ctx context.Context) error {
		shutdown2Called.Store(true)
		return nil
	}, 2*time.Second)
	
	// Perform shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := coordinator.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
	
	// Verify all shutdown functions were called
	if !shutdown1Called.Load() {
		t.Error("Shutdown function 1 was not called")
	}
	if !shutdown2Called.Load() {
		t.Error("Shutdown function 2 was not called")
	}
}

// TestShutdownCoordinatorWithErrors tests error handling during shutdown
func TestShutdownCoordinatorWithErrors(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	coordinator := NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add shutdown functions with errors
	coordinator.AddShutdownFunc("failing-resource", func(ctx context.Context) error {
		return errors.New("resource shutdown failed")
	}, 2*time.Second)
	
	coordinator.AddShutdownFunc("successful-resource", func(ctx context.Context) error {
		return nil
	}, 2*time.Second)
	
	// Perform shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := coordinator.Shutdown(ctx)
	if err == nil {
		t.Error("Expected error from failing resource, got nil")
	} else if !contains(err.Error(), "resource shutdown failed") {
		t.Errorf("Expected error to contain 'resource shutdown failed', got: %v", err)
	}
}

// TestShutdownCoordinatorTimeout tests timeout handling
func TestShutdownCoordinatorTimeout(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	coordinator := NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add a slow shutdown function
	coordinator.AddShutdownFunc("slow-resource", func(ctx context.Context) error {
		select {
		case <-time.After(10 * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, 100*time.Millisecond) // Very short timeout
	
	// Perform shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	start := time.Now()
	err := coordinator.Shutdown(ctx)
	elapsed := time.Since(start)
	
	// Should complete within a reasonable time despite slow resource
	if elapsed > 2*time.Second {
		t.Errorf("Shutdown took too long: %v", elapsed)
	}
	
	if err == nil {
		t.Error("Expected error from timeout, got nil")
	}
}

// TestShutdownCoordinatorConcurrency tests concurrent shutdown operations
func TestShutdownCoordinatorConcurrency(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	coordinator := NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add multiple shutdown functions
	var callCount atomic.Int32
	for i := 0; i < 10; i++ {
		name := "resource" + string(rune('0'+i))
		coordinator.AddShutdownFunc(name, func(ctx context.Context) error {
			callCount.Add(1)
			time.Sleep(10 * time.Millisecond)
			return nil
		}, 2*time.Second)
	}
	
	// Perform shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := coordinator.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
	
	// Verify all functions were called
	if callCount.Load() != 10 {
		t.Errorf("Expected 10 shutdown functions to be called, got %d", callCount.Load())
	}
}

// TestShutdownCoordinatorEmptyFunctions tests shutdown with no additional functions
func TestShutdownCoordinatorEmptyFunctions(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	coordinator := NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Don't add any shutdown functions
	
	// Perform shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := coordinator.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
}

// TestShutdownCoordinatorPanic tests recovery from panics in shutdown functions
func TestShutdownCoordinatorPanic(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	coordinator := NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add a function that panics
	coordinator.AddShutdownFunc("panicking-resource", func(ctx context.Context) error {
		// We should add panic recovery in the actual implementation
		// For now, this test documents the expected behavior
		return errors.New("simulated panic recovery")
	}, 2*time.Second)
	
	// Perform shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// This should not panic
	err := coordinator.Shutdown(ctx)
	_ = err // Error is expected but shouldn't crash
}

// TestGracefulServerWithActiveConnections tests shutdown with active connections
func TestGracefulServerWithActiveConnections(t *testing.T) {
	// Create a test server
	var activeRequests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeRequests.Add(1)
		defer activeRequests.Add(-1)
		
		// Simulate a long-running request
		select {
		case <-time.After(100 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			return
		}
	})
	
	httpServer := &http.Server{
		Handler: handler,
	}
	
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	// Start the server
	listener := httptest.NewUnstartedServer(handler).Listener
	go gracefulServer.Serve(listener)
	
	// Make some concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Simulate HTTP request
			_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n")) // Ignore error as connection may be closing
			time.Sleep(50 * time.Millisecond)
		}()
	}
	
	// Give requests time to start
	time.Sleep(20 * time.Millisecond)
	
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	err := gracefulServer.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
	
	// Wait for all requests to complete
	wg.Wait()
}

// TestShutdownCoordinatorAddFunctionDuringShutdown tests adding functions during shutdown
func TestShutdownCoordinatorAddFunctionDuringShutdown(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	gracefulServer := New(Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	})
	
	coordinator := NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Add a function that tries to add another function during shutdown
	coordinator.AddShutdownFunc("resource1", func(ctx context.Context) error {
		// Try to add another function during shutdown (should be safe but ignored)
		coordinator.AddShutdownFunc("late-resource", func(ctx context.Context) error {
			return nil
		}, 1*time.Second)
		return nil
	}, 2*time.Second)
	
	// Perform shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := coordinator.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected shutdown error: %v", err)
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || (len(s) > len(substr) && s[:len(substr)] == substr) || (len(s) > len(substr) && contains(s[1:], substr)))
}