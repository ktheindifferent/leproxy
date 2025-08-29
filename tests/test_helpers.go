// +build integration

package tests

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestServer manages a test server with proper lifecycle management
type TestServer struct {
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	handler  ConnectionHandler
	t        testing.TB
}

// ConnectionHandler is a function that handles incoming connections
type ConnectionHandler func(conn net.Conn)

// NewTestServer creates a new test server with lifecycle management
func NewTestServer(t testing.TB, addr string, handler ConnectionHandler) (*TestServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	ts := &TestServer{
		listener: listener,
		ctx:      ctx,
		cancel:   cancel,
		handler:  handler,
		t:        t,
	}
	
	return ts, nil
}

// Start begins accepting connections
func (ts *TestServer) Start() {
	ts.wg.Add(1)
	go ts.serve()
}

// serve handles the main server loop
func (ts *TestServer) serve() {
	defer ts.wg.Done()
	
	for {
		conn, err := ts.listener.Accept()
		if err != nil {
			// Check if listener was closed (shutdown case)
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			// Check if we should shutdown
			select {
			case <-ts.ctx.Done():
				return
			default:
				// Real error occurred
				if ts.t != nil {
					ts.t.Logf("Accept error: %v", err)
				}
				return
			}
		}
		
		// Check for shutdown before handling connection
		select {
		case <-ts.ctx.Done():
			conn.Close()
			return
		default:
			// Handle connection in a goroutine with proper tracking
			ts.wg.Add(1)
			go ts.handleConnection(conn)
		}
	}
}

// handleConnection processes a single connection
func (ts *TestServer) handleConnection(conn net.Conn) {
	defer ts.wg.Done()
	defer conn.Close()
	
	// Create a channel to signal when handler is done
	done := make(chan struct{})
	
	go func() {
		ts.handler(conn)
		close(done)
	}()
	
	// Wait for either handler completion or context cancellation
	select {
	case <-done:
	case <-ts.ctx.Done():
		// Force close connection on shutdown
		conn.Close()
	}
}

// Stop gracefully shuts down the server
func (ts *TestServer) Stop() error {
	// Close listener first to unblock Accept() immediately
	// This will cause Accept() to return an error
	if err := ts.listener.Close(); err != nil {
		// Ignore "use of closed network connection" errors
		if !strings.Contains(err.Error(), "use of closed") {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}
	
	// Cancel context to signal shutdown
	ts.cancel()
	
	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		return nil
	case <-time.After(2 * time.Second):
		return fmt.Errorf("timeout waiting for server shutdown")
	}
}

// Addr returns the server's listening address
func (ts *TestServer) Addr() string {
	return ts.listener.Addr().String()
}

// ProxyTestServer wraps a proxy server with lifecycle management
type ProxyTestServer struct {
	*TestServer
	proxy interface{}
}

// ProxyHandler is a function type for handling proxy connections
type ProxyHandler func(net.Conn)

// NewProxyTestServer creates a new proxy test server
func NewProxyTestServer(t testing.TB, addr string, handler ProxyHandler) (*ProxyTestServer, error) {
	ts, err := NewTestServer(t, addr, ConnectionHandler(handler))
	if err != nil {
		return nil, err
	}
	
	return &ProxyTestServer{
		TestServer: ts,
		proxy:      nil,
	}, nil
}

// GoroutineLeakDetector helps detect goroutine leaks in tests
type GoroutineLeakDetector struct {
	baseline int
	t        testing.TB
}

// NewGoroutineLeakDetector creates a new leak detector
func NewGoroutineLeakDetector(t testing.TB) *GoroutineLeakDetector {
	return &GoroutineLeakDetector{
		baseline: runtime.NumGoroutine(),
		t:        t,
	}
}

// Check verifies no goroutine leaks occurred
func (gld *GoroutineLeakDetector) Check() {
	// Give goroutines time to clean up
	time.Sleep(100 * time.Millisecond)
	
	// Force GC to clean up any dangling goroutines
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	
	current := runtime.NumGoroutine()
	if current > gld.baseline {
		// Get stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		
		gld.t.Errorf("Goroutine leak detected: baseline=%d, current=%d, leaked=%d\nStack:\n%s",
			gld.baseline, current, current-gld.baseline, buf[:stackLen])
	}
}

// CheckWithTolerance allows a small number of additional goroutines
func (gld *GoroutineLeakDetector) CheckWithTolerance(tolerance int) {
	// Give goroutines time to clean up
	time.Sleep(100 * time.Millisecond)
	
	// Force GC to clean up any dangling goroutines
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	
	current := runtime.NumGoroutine()
	leaked := current - gld.baseline
	
	if leaked > tolerance {
		// Get stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		
		gld.t.Errorf("Goroutine leak detected: baseline=%d, current=%d, leaked=%d (tolerance=%d)\nStack:\n%s",
			gld.baseline, current, leaked, tolerance, buf[:stackLen])
	}
}

// WaitForPort waits for a port to become available
func WaitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	
	return fmt.Errorf("timeout waiting for port %s", addr)
}

// MustStartTestServer creates and starts a test server, failing the test on error
func MustStartTestServer(t testing.TB, addr string, handler ConnectionHandler) *TestServer {
	ts, err := NewTestServer(t, addr, handler)
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	
	ts.Start()
	
	// Register cleanup
	t.Cleanup(func() {
		if err := ts.Stop(); err != nil {
			t.Errorf("Failed to stop test server: %v", err)
		}
	})
	
	return ts
}

// MustStartProxyTestServer creates and starts a proxy test server, failing the test on error
func MustStartProxyTestServer(t testing.TB, addr string, handler ProxyHandler) *ProxyTestServer {
	pts, err := NewProxyTestServer(t, addr, handler)
	if err != nil {
		t.Fatalf("Failed to create proxy test server: %v", err)
	}
	
	pts.Start()
	
	// Register cleanup
	t.Cleanup(func() {
		if err := pts.Stop(); err != nil {
			t.Errorf("Failed to stop proxy test server: %v", err)
		}
	})
	
	return pts
}