package graceful

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestServer_GracefulShutdown(t *testing.T) {
	// Create a test HTTP server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a long-running request
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	httpServer := &http.Server{
		Handler: handler,
	}

	cfg := Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	}

	srv := New(cfg)

	// Start the server
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Send a request in the background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		http.Get(ts.URL)
	}()

	// Give the request time to start
	time.Sleep(50 * time.Millisecond)

	// Shutdown the server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}

	// Wait for the background request to complete
	wg.Wait()
}

func TestServer_ShutdownTimeout(t *testing.T) {
	// Create a test HTTP server with a long-running handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a very long-running request
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	})

	httpServer := &http.Server{
		Handler: handler,
	}

	cfg := Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 1 * time.Second,
	}

	srv := New(cfg)

	// Shutdown with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := srv.Shutdown(ctx)
	// We expect this to timeout
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestServer_Reload(t *testing.T) {
	reloadCalled := false
	reloadFunc := func() error {
		reloadCalled = true
		return nil
	}

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	cfg := Config{
		HTTPServer: httpServer,
		ReloadFunc: reloadFunc,
	}

	srv := New(cfg)

	err := srv.Reload()
	if err != nil {
		t.Errorf("Unexpected error during reload: %v", err)
	}

	if !reloadCalled {
		t.Error("Reload function was not called")
	}
}

func TestServer_Stats(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	cfg := Config{
		HTTPServer: httpServer,
	}

	srv := New(cfg)

	// Get initial stats
	stats := srv.Stats()
	if stats.TotalRequests != 0 {
		t.Errorf("Expected 0 total requests, got %d", stats.TotalRequests)
	}

	// Simulate a connection
	conn := &mockConn{}
	srv.trackConnection(conn, http.StateNew)

	stats = srv.Stats()
	if stats.ActiveRequests != 1 {
		t.Errorf("Expected 1 active request, got %d", stats.ActiveRequests)
	}
	if stats.TotalRequests != 1 {
		t.Errorf("Expected 1 total request, got %d", stats.TotalRequests)
	}

	// Close the connection
	srv.trackConnection(conn, http.StateClosed)

	stats = srv.Stats()
	if stats.ActiveRequests != 0 {
		t.Errorf("Expected 0 active requests, got %d", stats.ActiveRequests)
	}
}

func TestManager_ShutdownAll(t *testing.T) {
	manager := NewManager()

	// Create multiple servers
	for i := 0; i < 3; i++ {
		httpServer := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		}

		cfg := Config{
			HTTPServer: httpServer,
		}

		srv := New(cfg)
		manager.Add(string(rune('a'+i)), srv)
	}

	// Shutdown all servers
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.ShutdownAll(ctx)
	if err != nil {
		t.Errorf("Unexpected error during shutdown all: %v", err)
	}
}

// mockConn is a mock implementation of net.Conn for testing
type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                        { return nil }
func (m *mockConn) LocalAddr() net.Addr                 { return nil }
func (m *mockConn) RemoteAddr() net.Addr                { return nil }
func (m *mockConn) SetDeadline(t time.Time) error       { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error   { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error  { return nil }