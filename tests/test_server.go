// Package tests provides testing utilities for LeProxy
package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrServerStopped indicates the server has been stopped
	ErrServerStopped = errors.New("server stopped")
	// ErrMaxConnections indicates maximum connections limit reached
	ErrMaxConnections = errors.New("maximum connections limit reached")
	// ErrConnectionRefused indicates the connection was refused
	ErrConnectionRefused = errors.New("connection refused")
)

// ConnectionHandler processes incoming connections
type ConnectionHandler interface {
	HandleConnection(conn net.Conn)
}

// HandlerFunc is an adapter to allow the use of ordinary functions as ConnectionHandlers
type HandlerFunc func(net.Conn)

// HandleConnection implements ConnectionHandler
func (f HandlerFunc) HandleConnection(conn net.Conn) {
	f(conn)
}

// TestServer provides a robust test server with proper lifecycle management
type TestServer struct {
	// Configuration
	addr           string
	maxConnections int
	handler        ConnectionHandler
	
	// Lifecycle management
	listener    net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	startOnce   sync.Once
	stopOnce    sync.Once
	
	// Connection tracking
	connections    sync.Map
	connCount      atomic.Int32
	totalAccepted  atomic.Int64
	totalClosed    atomic.Int64
	
	// State
	mu       sync.RWMutex
	started  bool
	stopping bool
	stopped  bool
	
	// Error tracking
	acceptErrors chan error
	lastError    error
}

// NewTestServer creates a new test server with the given configuration
func NewTestServer(addr string, handler ConnectionHandler, maxConnections int) *TestServer {
	if maxConnections <= 0 {
		maxConnections = 100 // Default reasonable limit
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &TestServer{
		addr:           addr,
		maxConnections: maxConnections,
		handler:        handler,
		ctx:            ctx,
		cancel:         cancel,
		acceptErrors:   make(chan error, 10),
	}
}

// Start begins accepting connections
func (ts *TestServer) Start() error {
	ts.mu.Lock()
	if ts.stopped {
		ts.mu.Unlock()
		return ErrServerStopped
	}
	if ts.started {
		ts.mu.Unlock()
		return nil // Already started
	}
	ts.mu.Unlock()
	
	var startErr error
	ts.startOnce.Do(func() {
		startErr = ts.start()
	})
	return startErr
}

func (ts *TestServer) start() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	if ts.stopped {
		return ErrServerStopped
	}
	
	// Create listener
	listener, err := net.Listen("tcp", ts.addr)
	if err != nil {
		ts.lastError = err
		return fmt.Errorf("failed to listen on %s: %w", ts.addr, err)
	}
	
	ts.listener = listener
	ts.started = true
	
	// Start accept loop
	ts.wg.Add(1)
	go ts.acceptLoop()
	
	// Start error monitor
	ts.wg.Add(1)
	go ts.errorMonitor()
	
	return nil
}

// acceptLoop handles incoming connections
func (ts *TestServer) acceptLoop() {
	defer ts.wg.Done()
	defer ts.closeAllConnections()
	
	for {
		// Check if we're stopping
		select {
		case <-ts.ctx.Done():
			return
		default:
		}
		
		// Set accept deadline to check for shutdown periodically
		if tcpListener, ok := ts.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond))
		}
		
		conn, err := ts.listener.Accept()
		if err != nil {
			// Check if it's a timeout (expected for periodic shutdown checks)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			
			// Check if we're stopping
			select {
			case <-ts.ctx.Done():
				return
			default:
				// Log the error but continue
				select {
				case ts.acceptErrors <- err:
				default:
					// Channel full, drop old errors
				}
				
				// Check if it's a permanent error
				if !isTemporaryError(err) {
					ts.mu.Lock()
					ts.lastError = err
					ts.mu.Unlock()
					return
				}
				continue
			}
		}
		
		// Check connection limit
		currentCount := ts.connCount.Load()
		if currentCount >= int32(ts.maxConnections) {
			conn.Close()
			select {
			case ts.acceptErrors <- ErrMaxConnections:
			default:
			}
			continue
		}
		
		// Track connection
		ts.connCount.Add(1)
		ts.totalAccepted.Add(1)
		
		connID := ts.totalAccepted.Load()
		wrappedConn := &trackedConn{
			Conn:   conn,
			id:     connID,
			server: ts,
		}
		ts.connections.Store(connID, wrappedConn)
		
		// Handle connection in goroutine
		ts.wg.Add(1)
		go ts.handleConnection(wrappedConn)
	}
}

// handleConnection processes a single connection
func (ts *TestServer) handleConnection(conn *trackedConn) {
	defer ts.wg.Done()
	defer conn.cleanup()
	
	// Set connection deadline if server is stopping
	go func() {
		<-ts.ctx.Done()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}()
	
	// Call the handler if provided
	if ts.handler != nil {
		ts.handler.HandleConnection(conn)
	}
}

// errorMonitor logs accept errors
func (ts *TestServer) errorMonitor() {
	defer ts.wg.Done()
	
	for {
		select {
		case <-ts.ctx.Done():
			return
		case err := <-ts.acceptErrors:
			// In production, you would log this
			_ = err
		}
	}
}

// Stop gracefully shuts down the server
func (ts *TestServer) Stop() error {
	var stopErr error
	ts.stopOnce.Do(func() {
		stopErr = ts.stop()
	})
	return stopErr
}

func (ts *TestServer) stop() error {
	ts.mu.Lock()
	ts.stopping = true
	ts.mu.Unlock()
	
	// Cancel context to signal shutdown
	ts.cancel()
	
	// Close listener to stop accepting new connections
	if ts.listener != nil {
		ts.listener.Close()
	}
	
	// Wait for graceful shutdown with timeout
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// Graceful shutdown completed
	case <-time.After(10 * time.Second):
		// Force close remaining connections
		ts.closeAllConnections()
		<-done
	}
	
	ts.mu.Lock()
	ts.stopped = true
	ts.mu.Unlock()
	
	return nil
}

// closeAllConnections forcefully closes all active connections
func (ts *TestServer) closeAllConnections() {
	ts.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*trackedConn); ok {
			conn.Close()
		}
		return true
	})
}

// GetAddr returns the server's listening address
func (ts *TestServer) GetAddr() string {
	if ts.listener != nil {
		return ts.listener.Addr().String()
	}
	return ts.addr
}

// GetStats returns server statistics
func (ts *TestServer) GetStats() ServerStats {
	return ServerStats{
		ActiveConnections: int(ts.connCount.Load()),
		TotalAccepted:    ts.totalAccepted.Load(),
		TotalClosed:      ts.totalClosed.Load(),
	}
}

// IsRunning returns true if the server is currently running
func (ts *TestServer) IsRunning() bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.started && !ts.stopped
}

// WaitForConnections waits until the server has at least n connections
func (ts *TestServer) WaitForConnections(n int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		if ts.connCount.Load() >= int32(n) {
			return nil
		}
		
		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for %d connections (current: %d)", 
					n, ts.connCount.Load())
			}
		case <-ts.ctx.Done():
			return ErrServerStopped
		}
	}
}

// ServerStats contains server statistics
type ServerStats struct {
	ActiveConnections int
	TotalAccepted    int64
	TotalClosed      int64
}

// trackedConn wraps a connection with tracking
type trackedConn struct {
	net.Conn
	id       int64
	server   *TestServer
	closed   atomic.Bool
	closeOnce sync.Once
}

// Close closes the connection and updates tracking
func (tc *trackedConn) Close() error {
	var err error
	tc.closeOnce.Do(func() {
		err = tc.Conn.Close()
		tc.cleanup()
	})
	return err
}

// cleanup removes the connection from tracking
func (tc *trackedConn) cleanup() {
	if tc.closed.CompareAndSwap(false, true) {
		tc.server.connections.Delete(tc.id)
		tc.server.connCount.Add(-1)
		tc.server.totalClosed.Add(1)
	}
}

// isTemporaryError checks if an error is temporary
func isTemporaryError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}
	return false
}

// SimpleBackend creates a simple echo backend for testing
func SimpleBackend(conn net.Conn) {
	defer conn.Close()
	
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		
		if _, err := conn.Write(buf[:n]); err != nil {
			return
		}
	}
}

// DelayedBackend creates a backend that delays before responding
func DelayedBackend(delay time.Duration) HandlerFunc {
	return func(conn net.Conn) {
		defer conn.Close()
		time.Sleep(delay)
		conn.Write([]byte("delayed response"))
	}
}

// UnresponsiveBackend creates a backend that accepts but never responds
func UnresponsiveBackend(conn net.Conn) {
	// Accept but don't respond or close
	select {}
}