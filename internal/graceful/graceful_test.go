package graceful

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

// Additional tests for enhanced shutdown functionality

func TestMultiError(t *testing.T) {
	t.Run("Empty MultiError", func(t *testing.T) {
		me := NewMultiError()
		if me.HasErrors() {
			t.Error("Empty MultiError should not have errors")
		}
		if me.ErrorOrNil() != nil {
			t.Error("Empty MultiError should return nil")
		}
		if me.Count() != 0 {
			t.Error("Empty MultiError should have count 0")
		}
	})

	t.Run("Single Error", func(t *testing.T) {
		me := NewMultiError()
		err := errors.New("test error")
		me.Add(err)
		
		if !me.HasErrors() {
			t.Error("MultiError should have errors")
		}
		if me.Count() != 1 {
			t.Errorf("Expected count 1, got %d", me.Count())
		}
		if me.ErrorOrNil() == nil {
			t.Error("Should return non-nil error")
		}
	})

	t.Run("Multiple Errors With Context", func(t *testing.T) {
		me := NewMultiError()
		me.AddWithContext(PhaseListeners, "listener1", errors.New("listen failed"), 100*time.Millisecond)
		me.AddWithContext(PhaseConnections, "conn1", errors.New("connection failed"), 200*time.Millisecond)
		me.Add(nil) // Should be ignored
		me.AddWithContext(PhaseServices, "service1", errors.New("service failed"), 300*time.Millisecond)
		
		if me.Count() != 3 {
			t.Errorf("Expected count 3, got %d", me.Count())
		}
		
		errStr := me.Error()
		if errStr == "" {
			t.Error("Error string should not be empty")
		}
		
		// Check that error string contains phase information
		if !strings.Contains(errStr, "listeners") {
			t.Error("Error string should contain phase information")
		}
	})

	t.Run("Concurrent Add", func(t *testing.T) {
		me := NewMultiError()
		var wg sync.WaitGroup
		numGoroutines := 100
		
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				me.Add(fmt.Errorf("error from goroutine %d", id))
			}(i)
		}
		
		wg.Wait()
		
		if me.Count() != numGoroutines {
			t.Errorf("Expected %d errors, got %d", numGoroutines, me.Count())
		}
	})
}

func TestShutdownError(t *testing.T) {
	err := &ShutdownError{
		Phase:     PhaseConnections,
		Component: "http-server",
		Err:       errors.New("connection timeout"),
		Duration:  5 * time.Second,
		Timestamp: time.Now(),
	}
	
	errStr := err.Error()
	if errStr == "" {
		t.Error("Error string should not be empty")
	}
	
	if !strings.Contains(errStr, "connections") {
		t.Error("Error should contain phase name")
	}
	
	if !strings.Contains(errStr, "http-server") {
		t.Error("Error should contain component name")
	}
	
	if !strings.Contains(errStr, "5s") {
		t.Error("Error should contain duration")
	}
	
	if err.Unwrap() == nil {
		t.Error("Unwrap should return the underlying error")
	}
}

func TestShutdownMetrics(t *testing.T) {
	metrics := NewShutdownMetrics()
	
	// Test phase tracking
	metrics.StartPhase(PhaseListeners)
	metrics.AddComponent(PhaseListeners, "listener1")
	metrics.AddComponent(PhaseListeners, "listener2")
	time.Sleep(10 * time.Millisecond) // Ensure some duration
	metrics.EndPhase(PhaseListeners, 0)
	
	metrics.StartPhase(PhaseConnections)
	metrics.AddComponent(PhaseConnections, "conn1")
	time.Sleep(10 * time.Millisecond)
	metrics.EndPhase(PhaseConnections, 1)
	
	metrics.Finalize(1)
	
	if metrics.ComponentsCount != 3 {
		t.Errorf("Expected 3 components, got %d", metrics.ComponentsCount)
	}
	
	if metrics.ErrorCount != 1 {
		t.Errorf("Expected 1 error, got %d", metrics.ErrorCount)
	}
	
	if metrics.Duration == 0 {
		t.Error("Duration should not be zero")
	}
	
	// Check phase metrics
	if pm, ok := metrics.PhaseMetrics[PhaseListeners]; !ok {
		t.Error("PhaseListeners metrics should exist")
	} else {
		if len(pm.Components) != 2 {
			t.Errorf("Expected 2 components in PhaseListeners, got %d", len(pm.Components))
		}
		if pm.ErrorCount != 0 {
			t.Errorf("Expected 0 errors in PhaseListeners, got %d", pm.ErrorCount)
		}
	}
	
	// Test String() output
	output := metrics.String()
	if !strings.Contains(output, "Shutdown Metrics") {
		t.Error("String output should contain header")
	}
	if !strings.Contains(output, "Total Duration") {
		t.Error("String output should contain duration")
	}
}

func TestServer_ShutdownWithHooks(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	cfg := Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
		EnableProgress:  false,
	}
	
	srv := New(cfg)
	
	var hookExecuted int32
	var hookOrder []string
	var mu sync.Mutex
	
	// Register multiple hooks with different priorities and phases
	srv.RegisterShutdownHook(ShutdownHook{
		Name:     "pool1",
		Phase:    PhasePools,
		Priority: 1,
		Shutdown: func(ctx context.Context) error {
			atomic.AddInt32(&hookExecuted, 1)
			mu.Lock()
			hookOrder = append(hookOrder, "pool1")
			mu.Unlock()
			return nil
		},
	})
	
	srv.RegisterShutdownHook(ShutdownHook{
		Name:     "service1",
		Phase:    PhaseServices,
		Priority: 1,
		Shutdown: func(ctx context.Context) error {
			atomic.AddInt32(&hookExecuted, 1)
			mu.Lock()
			hookOrder = append(hookOrder, "service1")
			mu.Unlock()
			return nil
		},
	})
	
	srv.RegisterShutdownHook(ShutdownHook{
		Name:     "tracer1",
		Phase:    PhaseTracers,
		Priority: 1,
		Shutdown: func(ctx context.Context) error {
			atomic.AddInt32(&hookExecuted, 1)
			mu.Lock()
			hookOrder = append(hookOrder, "tracer1")
			mu.Unlock()
			return nil
		},
	})
	
	// Register cleanup functions
	var cleanupExecuted int32
	srv.RegisterCleanup(func() error {
		atomic.AddInt32(&cleanupExecuted, 1)
		return nil
	})
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	err := srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}
	
	if atomic.LoadInt32(&hookExecuted) != 3 {
		t.Errorf("Expected 3 hooks to be executed, got %d", atomic.LoadInt32(&hookExecuted))
	}
	
	if atomic.LoadInt32(&cleanupExecuted) != 1 {
		t.Errorf("Expected 1 cleanup function to be executed, got %d", atomic.LoadInt32(&cleanupExecuted))
	}
	
	// Check phase ordering (pools -> services -> tracers)
	expectedOrder := []string{"pool1", "service1", "tracer1"}
	mu.Lock()
	defer mu.Unlock()
	
	for i, expected := range expectedOrder {
		if i >= len(hookOrder) || hookOrder[i] != expected {
			t.Errorf("Expected %s at position %d, got %v", expected, i, hookOrder)
		}
	}
}

func TestServer_ShutdownWithErrors(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	cfg := Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	}
	
	srv := New(cfg)
	
	// Register hooks that will fail
	srv.RegisterShutdownHook(ShutdownHook{
		Name:     "failing-hook1",
		Phase:    PhaseServices,
		Priority: 1,
		Shutdown: func(ctx context.Context) error {
			return errors.New("hook1 failed")
		},
	})
	
	srv.RegisterShutdownHook(ShutdownHook{
		Name:     "failing-hook2",
		Phase:    PhaseServices,
		Priority: 2,
		Shutdown: func(ctx context.Context) error {
			return errors.New("hook2 failed")
		},
	})
	
	srv.RegisterCleanup(func() error {
		return errors.New("cleanup failed")
	})
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	err := srv.Shutdown(ctx)
	if err == nil {
		t.Error("Expected error from failing hooks")
	}
	
	// Check that error contains all failures
	errStr := err.Error()
	if !strings.Contains(errStr, "hook1 failed") {
		t.Error("Error should contain hook1 failure")
	}
	if !strings.Contains(errStr, "hook2 failed") {
		t.Error("Error should contain hook2 failure")
	}
	if !strings.Contains(errStr, "cleanup failed") {
		t.Error("Error should contain cleanup failure")
	}
}

func TestServer_ProgressReporting(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	cfg := Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
		EnableProgress:  true,
	}
	
	srv := New(cfg)
	
	// Monitor progress channel
	progressChan := srv.GetShutdownProgress()
	if progressChan == nil {
		t.Fatal("Progress channel should not be nil when EnableProgress is true")
	}
	
	var progressUpdates []ShutdownProgress
	var wg sync.WaitGroup
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		for progress := range progressChan {
			progressUpdates = append(progressUpdates, progress)
		}
	}()
	
	// Add some hooks to generate progress
	srv.RegisterShutdownHook(ShutdownHook{
		Name:     "test-hook",
		Phase:    PhaseServices,
		Priority: 1,
		Shutdown: func(ctx context.Context) error {
			return nil
		},
	})
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	err := srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}
	
	// Wait for progress reporter to finish
	wg.Wait()
	
	if len(progressUpdates) == 0 {
		t.Error("Expected progress updates during shutdown")
	}
	
	// Check that progress updates contain expected phases
	hasListenerPhase := false
	hasConnectionPhase := false
	for _, update := range progressUpdates {
		if update.Phase == PhaseListeners {
			hasListenerPhase = true
		}
		if update.Phase == PhaseConnections {
			hasConnectionPhase = true
		}
	}
	
	if !hasListenerPhase {
		t.Error("Expected progress updates for listener phase")
	}
	if !hasConnectionPhase {
		t.Error("Expected progress updates for connection phase")
	}
}

func TestServer_IsShuttingDown(t *testing.T) {
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	
	cfg := Config{
		HTTPServer:      httpServer,
		ShutdownTimeout: 5 * time.Second,
	}
	
	srv := New(cfg)
	
	if srv.IsShuttingDown() {
		t.Error("Server should not be shutting down initially")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	err := srv.Shutdown(ctx)
	if err != nil {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}
	
	if !srv.IsShuttingDown() {
		t.Error("Server should be marked as shutting down")
	}
}

func TestSortShutdownHooks(t *testing.T) {
	hooks := []ShutdownHook{
		{Name: "hook3", Priority: 3},
		{Name: "hook1", Priority: 1},
		{Name: "hook2", Priority: 2},
		{Name: "hook5", Priority: 5},
		{Name: "hook4", Priority: 4},
	}
	
	sortShutdownHooks(hooks)
	
	// Check that hooks are sorted by priority (ascending)
	for i := 0; i < len(hooks)-1; i++ {
		if hooks[i].Priority > hooks[i+1].Priority {
			t.Errorf("Hooks not sorted correctly: %v", hooks)
			break
		}
	}
	
	// Check specific order
	expectedOrder := []string{"hook1", "hook2", "hook3", "hook4", "hook5"}
	for i, expected := range expectedOrder {
		if hooks[i].Name != expected {
			t.Errorf("Expected %s at position %d, got %s", expected, i, hooks[i].Name)
		}
	}
}