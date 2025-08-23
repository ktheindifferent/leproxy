package pool

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Mock connection for testing
type mockConn struct {
	closed    bool
	closeErr  error
	id        int
	healthErr error
	mu        sync.Mutex
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errors.New("connection closed")
	}
	return len(b), nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errors.New("connection closed")
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("already closed")
	}
	m.closed = true
	return m.closeErr
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5432}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestNewPool(t *testing.T) {
	config := &Config{
		MaxConnections:  10,
		MinConnections:  2,
		MaxIdleTime:     time.Minute,
		HealthCheckTime: 30 * time.Second,
	}
	
	var connID int32
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return &mockConn{id: int(id)}, nil
	}
	
	healthCheck := func(conn net.Conn) error {
		if mc, ok := conn.(*mockConn); ok {
			return mc.healthErr
		}
		return nil
	}
	
	pool := NewPool(config, factory, healthCheck)
	
	if pool == nil {
		t.Fatal("NewPool returned nil")
	}
	
	// Check configuration
	if pool.config.MaxConnections != config.MaxConnections {
		t.Errorf("MaxConnections = %d, want %d", pool.config.MaxConnections, config.MaxConnections)
	}
	
	if pool.config.MinConnections != config.MinConnections {
		t.Errorf("MinConnections = %d, want %d", pool.config.MinConnections, config.MinConnections)
	}
}

func TestPoolGet(t *testing.T) {
	config := &Config{
		MaxConnections: 5,
		MinConnections: 1,
		MaxIdleTime:    time.Minute,
	}
	
	var connID int32
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return &mockConn{id: int(id)}, nil
	}
	
	pool := NewPool(config, factory, nil)
	ctx := context.Background()
	
	// Get a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	
	if conn == nil {
		t.Fatal("Got nil connection")
	}
	
	// Return the connection
	pool.Put(conn)
	
	// Get it again - should be the same connection
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection second time: %v", err)
	}
	
	// Check it's the same connection (reused from pool)
	if mc1, ok := conn.(*mockConn); ok {
		if mc2, ok := conn2.(*mockConn); ok {
			if mc1.id != mc2.id {
				t.Error("Expected to get the same connection from pool")
			}
		}
	}
	
	pool.Put(conn2)
}

func TestPoolMaxConnections(t *testing.T) {
	config := &Config{
		MaxConnections: 2,
		MinConnections: 0,
		MaxIdleTime:    time.Minute,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	pool := NewPool(config, factory, nil)
	ctx := context.Background()
	
	// Get max connections
	conns := make([]net.Conn, config.MaxConnections)
	for i := 0; i < config.MaxConnections; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		conns[i] = conn
	}
	
	// Try to get one more with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	
	_, err := pool.Get(timeoutCtx)
	if err == nil {
		t.Error("Expected error when exceeding max connections")
	}
	
	// Return one connection
	pool.Put(conns[0])
	
	// Now we should be able to get one
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Errorf("Should be able to get connection after returning one: %v", err)
	}
	pool.Put(conn)
	
	// Return all connections
	for i := 1; i < len(conns); i++ {
		pool.Put(conns[i])
	}
}

func TestPoolFactoryError(t *testing.T) {
	config := &Config{
		MaxConnections: 5,
		MinConnections: 0,
	}
	
	expectedErr := errors.New("connection failed")
	factory := func(ctx context.Context) (net.Conn, error) {
		return nil, expectedErr
	}
	
	pool := NewPool(config, factory, nil)
	ctx := context.Background()
	
	conn, err := pool.Get(ctx)
	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}
	
	if conn != nil {
		t.Error("Expected nil connection on factory error")
	}
}

func TestPoolHealthCheck(t *testing.T) {
	config := &Config{
		MaxConnections:  5,
		MinConnections:  1,
		HealthCheckTime: 100 * time.Millisecond,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	var healthCheckCalled bool
	healthCheck := func(conn net.Conn) error {
		healthCheckCalled = true
		if mc, ok := conn.(*mockConn); ok {
			return mc.healthErr
		}
		return nil
	}
	
	pool := NewPool(config, factory, healthCheck)
	ctx := context.Background()
	
	// Get and return a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	
	// Set connection to fail health check
	if mc, ok := conn.(*mockConn); ok {
		mc.healthErr = errors.New("health check failed")
	}
	
	pool.Put(conn)
	
	// Wait for health check to run
	time.Sleep(200 * time.Millisecond)
	
	if !healthCheckCalled {
		t.Error("Health check should have been called")
	}
	
	// Get a connection - should be a new one since old failed health check
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection after health check: %v", err)
	}
	
	// Verify it's a different connection
	if mc1, ok := conn.(*mockConn); ok {
		if mc2, ok := conn2.(*mockConn); ok {
			if mc1.id == mc2.id {
				t.Error("Should have gotten a new connection after health check failure")
			}
		}
	}
	
	pool.Put(conn2)
}

func TestPoolClose(t *testing.T) {
	config := &Config{
		MaxConnections: 5,
		MinConnections: 1,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	pool := NewPool(config, factory, nil)
	ctx := context.Background()
	
	// Get some connections
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)
	
	// Return them
	pool.Put(conn1)
	pool.Put(conn2)
	
	// Close the pool
	err := pool.Close()
	if err != nil {
		t.Errorf("Failed to close pool: %v", err)
	}
	
	// Try to get a connection - should fail
	_, err = pool.Get(ctx)
	if err == nil {
		t.Error("Expected error when getting connection from closed pool")
	}
}

func TestPoolStats(t *testing.T) {
	config := &Config{
		MaxConnections: 5,
		MinConnections: 1,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	pool := NewPool(config, factory, nil)
	ctx := context.Background()
	
	// Initial stats
	stats := pool.Stats()
	if stats.TotalConnections != 0 {
		t.Errorf("Initial TotalConnections = %d, want 0", stats.TotalConnections)
	}
	
	// Get connections
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)
	
	stats = pool.Stats()
	if stats.ActiveConnections != 2 {
		t.Errorf("ActiveConnections = %d, want 2", stats.ActiveConnections)
	}
	
	// Return one
	pool.Put(conn1)
	
	stats = pool.Stats()
	if stats.ActiveConnections != 1 {
		t.Errorf("After returning one, ActiveConnections = %d, want 1", stats.ActiveConnections)
	}
	if stats.IdleConnections != 1 {
		t.Errorf("After returning one, IdleConnections = %d, want 1", stats.IdleConnections)
	}
	
	pool.Put(conn2)
}

func TestPoolConcurrency(t *testing.T) {
	config := &Config{
		MaxConnections: 10,
		MinConnections: 0,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		time.Sleep(10 * time.Millisecond) // Simulate connection creation time
		return &mockConn{}, nil
	}
	
	pool := NewPool(config, factory, nil)
	ctx := context.Background()
	
	var wg sync.WaitGroup
	errors := make(chan error, 20)
	
	// Start multiple goroutines getting and returning connections
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := pool.Get(ctx)
			if err != nil {
				errors <- err
				return
			}
			
			// Use connection briefly
			time.Sleep(5 * time.Millisecond)
			
			pool.Put(conn)
		}()
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
	
	// Final stats check
	stats := pool.Stats()
	if stats.ActiveConnections != 0 {
		t.Errorf("All connections should be returned, active = %d", stats.ActiveConnections)
	}
}

func TestPoolIdleTimeout(t *testing.T) {
	config := &Config{
		MaxConnections: 5,
		MinConnections: 0,
		MaxIdleTime:    100 * time.Millisecond,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	pool := NewPool(config, factory, nil)
	ctx := context.Background()
	
	// Get and return a connection
	conn, _ := pool.Get(ctx)
	mc1, ok := conn.(*mockConn)
	if !ok {
		t.Fatal("Expected connection to be *mockConn")
	}
	pool.Put(conn)
	
	// Wait for idle timeout
	time.Sleep(200 * time.Millisecond)
	
	// Get a connection - should be a new one
	conn2, _ := pool.Get(ctx)
	mc2, ok := conn2.(*mockConn)
	if !ok {
		t.Fatal("Expected connection to be *mockConn")
	}
	
	if mc1.id == mc2.id {
		t.Error("Should have gotten a new connection after idle timeout")
	}
	
	// Check that old connection was closed
	if !mc1.closed {
		t.Error("Idle connection should have been closed")
	}
	
	pool.Put(conn2)
}