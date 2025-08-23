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
	config := Config{
		MaxConns:    10,
		MinConns:    2,
		IdleTimeout: time.Minute,
		MaxLifetime: 30 * time.Second,
	}
	
	var connID int32
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return &mockConn{id: int(id)}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	
	if pool == nil {
		t.Fatal("New returned nil")
	}
	
	// Check configuration
	if pool.maxConns != config.MaxConns {
		t.Errorf("MaxConns = %d, want %d", pool.maxConns, config.MaxConns)
	}
	
	if pool.minConns != config.MinConns {
		t.Errorf("MinConns = %d, want %d", pool.minConns, config.MinConns)
	}
	
	pool.Close()
}

func TestPoolGet(t *testing.T) {
	config := Config{
		MaxConns:    5,
		MinConns:    0,
		IdleTimeout: time.Minute,
		MaxLifetime: 5 * time.Minute,
	}
	
	var connID int32
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return &mockConn{id: int(id)}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
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
	conn.Close()
	
	// Get it again
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection second time: %v", err)
	}
	
	conn2.Close()
}

func TestPoolMaxConnections(t *testing.T) {
	config := Config{
		MaxConns:    2,
		MinConns:    0,
		IdleTimeout: time.Minute,
		MaxLifetime: 5 * time.Minute,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	// Get max connections
	conns := make([]net.Conn, config.MaxConns)
	for i := 0; i < config.MaxConns; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		conns[i] = conn
	}
	
	// Try to get one more with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	
	_, err = pool.Get(timeoutCtx)
	if err == nil {
		t.Error("Expected error when exceeding max connections")
	}
	
	// Return one connection
	conns[0].Close()
	
	// Now we should be able to get one
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Errorf("Should be able to get connection after returning one: %v", err)
	}
	conn.Close()
	
	// Return all connections
	for i := 1; i < len(conns); i++ {
		conns[i].Close()
	}
}

func TestPoolFactoryError(t *testing.T) {
	config := Config{
		MaxConns:    5,
		MinConns:    0,
		IdleTimeout: time.Minute,
		MaxLifetime: 5 * time.Minute,
	}
	
	expectedErr := errors.New("connection failed")
	factory := func(ctx context.Context) (net.Conn, error) {
		return nil, expectedErr
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
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
	config := Config{
		MaxConns:    5,
		MinConns:    0,
		IdleTimeout: 100 * time.Millisecond,
		MaxLifetime: 5 * time.Minute,
	}
	
	var connID int32
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return &mockConn{id: int(id)}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	// Get and return a connection
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	
	var id1 int
	switch c := conn.(type) {
	case *PooledConn:
		if mc, ok := c.Conn.(*mockConn); ok {
			id1 = mc.id
		}
	case *mockConn:
		id1 = c.id
	}
	
	// Return the connection
	conn.Close()
	
	// Wait for idle timeout
	time.Sleep(200 * time.Millisecond)
	
	// Trigger cleanup by getting a new connection
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection after timeout: %v", err)
	}
	
	// Should be a different connection since old one timed out
	var id2 int
	switch c := conn2.(type) {
	case *PooledConn:
		if mc, ok := c.Conn.(*mockConn); ok {
			id2 = mc.id
		}
	case *mockConn:
		id2 = c.id
	}
	
	if id2 == id1 {
		t.Error("Should have gotten a new connection after idle timeout")
	}
	
	conn2.Close()
}

func TestPoolClose(t *testing.T) {
	config := Config{
		MaxConns:    5,
		MinConns:    0,
		IdleTimeout: time.Minute,
		MaxLifetime: 5 * time.Minute,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	
	ctx := context.Background()
	
	// Get some connections
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)
	
	// Return them
	conn1.Close()
	conn2.Close()
	
	// Close the pool
	err = pool.Close()
	if err != nil {
		t.Errorf("Failed to close pool: %v", err)
	}
	
	// Try to get a connection - should fail
	_, err = pool.Get(ctx)
	if err != ErrPoolClosed {
		t.Error("Expected ErrPoolClosed when getting connection from closed pool")
	}
}

func TestPoolStats(t *testing.T) {
	config := Config{
		MaxConns:    5,
		MinConns:    0,
		IdleTimeout: time.Minute,
		MaxLifetime: 5 * time.Minute,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	// Initial stats
	stats := pool.Stats()
	if stats.Created != 0 {
		t.Errorf("Initial Created = %d, want 0", stats.Created)
	}
	
	// Get connections
	conn1, _ := pool.Get(ctx)
	conn2, _ := pool.Get(ctx)
	
	stats = pool.Stats()
	if stats.Active != 2 {
		t.Errorf("Active = %d, want 2", stats.Active)
	}
	
	// Return one
	conn1.Close()
	
	// Give time for the connection to return to pool
	time.Sleep(10 * time.Millisecond)
	
	stats = pool.Stats()
	if stats.Active != 1 {
		t.Errorf("After returning one, Active = %d, want 1", stats.Active)
	}
	if stats.Idle != 1 {
		t.Errorf("After returning one, Idle = %d, want 1", stats.Idle)
	}
	
	conn2.Close()
}

func TestPoolConcurrency(t *testing.T) {
	config := Config{
		MaxConns:    10,
		MinConns:    0,
		IdleTimeout: time.Minute,
		MaxLifetime: 5 * time.Minute,
	}
	
	factory := func(ctx context.Context) (net.Conn, error) {
		time.Sleep(10 * time.Millisecond) // Simulate connection creation time
		return &mockConn{}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
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
			
			conn.Close()
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
	if stats.Active != 0 {
		t.Errorf("All connections should be returned, active = %d", stats.Active)
	}
}

func TestPoolIdleTimeout(t *testing.T) {
	config := Config{
		MaxConns:    5,
		MinConns:    0,
		IdleTimeout: 100 * time.Millisecond,
		MaxLifetime: 5 * time.Minute,
	}
	
	var connID int32
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return &mockConn{id: int(id)}, nil
	}
	
	config.Factory = factory
	
	pool, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	// Get and return a connection
	conn, _ := pool.Get(ctx)
	var id1 int
	switch c := conn.(type) {
	case *PooledConn:
		if mc, ok := c.Conn.(*mockConn); ok {
			id1 = mc.id
		}
	case *mockConn:
		id1 = c.id
	}
	conn.Close()
	
	// Wait for idle timeout
	time.Sleep(200 * time.Millisecond)
	
	// Trigger cleanup
	pool.cleanup()
	
	// Get a connection - should be a new one
	conn2, _ := pool.Get(ctx)
	var id2 int
	switch c := conn2.(type) {
	case *PooledConn:
		if mc, ok := c.Conn.(*mockConn); ok {
			id2 = mc.id
		}
	case *mockConn:
		id2 = c.id
	}
	
	if id2 == id1 {
		t.Error("Should have gotten a new connection after idle timeout")
	}
	
	conn2.Close()
}