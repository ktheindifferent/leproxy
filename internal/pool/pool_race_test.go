package pool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MockConn implements net.Conn for testing
type MockConn struct {
	id       int
	closed   int32
	readErr  error
	writeErr error
	mu       sync.RWMutex
}

func NewMockConn(id int) *MockConn {
	return &MockConn{id: id}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return 0, errors.New("connection closed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.readErr != nil {
		return 0, m.readErr
	}
	return len(b), nil
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	if atomic.LoadInt32(&m.closed) == 1 {
		return 0, errors.New("connection closed")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func (m *MockConn) Close() error {
	atomic.StoreInt32(&m.closed, 1)
	return nil
}

func (m *MockConn) IsClosed() bool {
	return atomic.LoadInt32(&m.closed) == 1
}

func (m *MockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Simulate timeout error when deadline is set
	if !t.IsZero() && time.Until(t) < time.Millisecond {
		m.readErr = &net.OpError{Op: "read", Err: timeoutError{}}
	} else {
		m.readErr = nil
	}
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type timeoutError struct{}

func (e timeoutError) Error() string   { return "timeout" }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

// Test for race conditions with concurrent operations
func TestPoolRaceConditions(t *testing.T) {
	var connID int32
	
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		// Simulate some creation delay
		time.Sleep(time.Millisecond)
		return NewMockConn(int(id)), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    0,
		MaxConns:    10,
		MaxLifetime: 5 * time.Second,
		IdleTimeout: 2 * time.Second,
	}
	
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	// Run concurrent operations
	var wg sync.WaitGroup
	errors := make(chan error, 100)
	
	// Concurrent getters
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				conn, err := pool.Get(ctx)
				cancel()
				
				if err != nil && err != context.DeadlineExceeded {
					errors <- fmt.Errorf("get error: %w", err)
					return
				}
				
				if conn != nil {
					// Simulate some work
					time.Sleep(time.Millisecond)
					if err := conn.Close(); err != nil {
						errors <- fmt.Errorf("close error: %w", err)
					}
				}
			}
		}()
	}
	
	// Concurrent stats readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				stats := pool.Stats()
				// Basic sanity check
				if stats.Active < 0 || stats.Idle < 0 {
					errors <- fmt.Errorf("invalid stats: active=%d, idle=%d", stats.Active, stats.Idle)
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}
	
	// Test draining separately - don't undrain during concurrent operations
	// as it can cause unexpected errors
	
	// Wait for all goroutines
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Error(err)
	}
}

// Test connection leak detection
func TestConnectionLeakDetection(t *testing.T) {
	var connID int32
	
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return NewMockConn(int(id)), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    0,
		MaxConns:    5,
		MaxLifetime: 10 * time.Second,
		IdleTimeout: 5 * time.Second,
	}
	
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	
	// Get connections without returning them (simulating leak)
	ctx := context.Background()
	leakedConns := make([]net.Conn, 3)
	for i := 0; i < 3; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection: %v", err)
		}
		leakedConns[i] = conn
	}
	
	// Check for leaked connections
	leaked := pool.GetLeakedConnections()
	if len(leaked) != 3 {
		t.Errorf("Expected 3 leaked connections, got %d", len(leaked))
	}
	
	// Return one connection
	if err := leakedConns[0].Close(); err != nil {
		t.Errorf("Failed to return connection: %v", err)
	}
	
	// Wait a bit for the close to process
	time.Sleep(10 * time.Millisecond)
	
	// Check again
	leaked = pool.GetLeakedConnections()
	if len(leaked) != 2 {
		t.Errorf("Expected 2 leaked connections after returning one, got %d", len(leaked))
	}
	
	// Close pool should clean up leaks
	pool.Close()
	
	// All connections should be closed now
	leaked = pool.GetLeakedConnections()
	if len(leaked) != 0 {
		t.Errorf("Expected 0 leaked connections after pool close, got %d", len(leaked))
	}
}

// Test pool closure race condition
func TestPoolClosureRace(t *testing.T) {
	var connID int32
	
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return NewMockConn(int(id)), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    2,
		MaxConns:    10,
		MaxLifetime: 10 * time.Second,
		IdleTimeout: 5 * time.Second,
	}
	
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	
	var wg sync.WaitGroup
	errors := make(chan error, 100)
	
	// Start operations that will race with close
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			conn, err := pool.Get(ctx)
			if err != nil {
				// Pool closed error is expected
				if err != ErrPoolClosed && err != ErrPoolDraining {
					errors <- fmt.Errorf("unexpected error: %w", err)
				}
				return
			}
			
			// Try to return connection
			time.Sleep(time.Millisecond)
			if err := conn.Close(); err != nil {
				// Error during close might happen if pool is closing
				// but shouldn't panic
			}
		}()
	}
	
	// Close pool while operations are running
	time.Sleep(5 * time.Millisecond)
	if err := pool.Close(); err != nil {
		t.Errorf("Failed to close pool: %v", err)
	}
	
	// Try to close again (should be idempotent)
	if err := pool.Close(); err != nil {
		t.Errorf("Second close failed: %v", err)
	}
	
	wg.Wait()
	close(errors)
	
	for err := range errors {
		t.Error(err)
	}
}

// Test graceful draining
func TestPoolDraining(t *testing.T) {
	var connID int32
	
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		return NewMockConn(int(id)), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    0,
		MaxConns:    5,
		MaxLifetime: 10 * time.Second,
		IdleTimeout: 5 * time.Second,
	}
	
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	// Get some connections
	ctx := context.Background()
	conns := make([]net.Conn, 3)
	for i := 0; i < 3; i++ {
		conn, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection: %v", err)
		}
		conns[i] = conn
	}
	
	// Start draining
	pool.Drain()
	
	// New connections should fail
	_, err = pool.Get(ctx)
	if err != ErrPoolDraining {
		t.Errorf("Expected ErrPoolDraining, got %v", err)
	}
	
	// Return connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			t.Errorf("Failed to return connection: %v", err)
		}
	}
	
	// Wait for drain to complete
	err = pool.WaitForDrain(1 * time.Second)
	if err != nil {
		t.Errorf("Failed to drain: %v", err)
	}
	
	stats := pool.Stats()
	if stats.Active != 0 {
		t.Errorf("Expected 0 active connections after drain, got %d", stats.Active)
	}
}

// Test connection counting accuracy under stress
func TestConnectionCountingAccuracy(t *testing.T) {
	var connID int32
	var totalCreated int32
	var totalClosed int32
	
	factory := func(ctx context.Context) (net.Conn, error) {
		id := atomic.AddInt32(&connID, 1)
		atomic.AddInt32(&totalCreated, 1)
		return NewMockConn(int(id)), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    0,
		MaxConns:    20,
		MaxLifetime: 100 * time.Millisecond, // Short lifetime for more churn
		IdleTimeout: 50 * time.Millisecond,
	}
	
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	
	// Run stress test
	var wg sync.WaitGroup
	stopCh := make(chan struct{})
	
	// Connection users
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
					conn, err := pool.Get(ctx)
					cancel()
					
					if err == nil && conn != nil {
						// Hold connection briefly
						time.Sleep(time.Duration(time.Now().UnixNano()%10) * time.Millisecond)
						conn.Close()
						atomic.AddInt32(&totalClosed, 1)
					}
				}
			}
		}()
	}
	
	// Let it run for a bit
	time.Sleep(500 * time.Millisecond)
	close(stopCh)
	wg.Wait()
	
	// Get final stats
	stats := pool.Stats()
	
	// Close pool
	pool.Close()
	
	// Verify counts
	if stats.Created != uint64(atomic.LoadInt32(&totalCreated)) {
		t.Errorf("Connection count mismatch: pool=%d, actual=%d", 
			stats.Created, totalCreated)
	}
	
	// Active + Idle should be reasonable
	total := stats.Active + stats.Idle
	if total < 0 || total > int32(cfg.MaxConns) {
		t.Errorf("Invalid connection count: active=%d, idle=%d, max=%d",
			stats.Active, stats.Idle, cfg.MaxConns)
	}
}

// Test cleanup goroutine doesn't leak
func TestCleanupGoroutineNoLeak(t *testing.T) {
	factory := func(ctx context.Context) (net.Conn, error) {
		return NewMockConn(1), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    1,
		MaxConns:    5,
		MaxLifetime: 10 * time.Second,
		IdleTimeout: 5 * time.Second,
	}
	
	// Get initial goroutine count
	initialGoroutines := runtime.NumGoroutine()
	
	// Create and close multiple pools
	for i := 0; i < 5; i++ {
		pool, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create pool: %v", err)
		}
		
		// Use the pool a bit
		ctx := context.Background()
		for j := 0; j < 3; j++ {
			conn, err := pool.Get(ctx)
			if err == nil {
				conn.Close()
			}
		}
		
		// Close and wait
		pool.Close()
		time.Sleep(10 * time.Millisecond)
	}
	
	// Wait for goroutines to finish
	time.Sleep(100 * time.Millisecond)
	
	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	leaked := finalGoroutines - initialGoroutines
	
	// Allow small variation due to runtime goroutines
	if leaked > 2 {
		t.Errorf("Possible goroutine leak: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, leaked)
	}
}

// Benchmark connection get/return
func BenchmarkPoolGetReturn(b *testing.B) {
	factory := func(ctx context.Context) (net.Conn, error) {
		return NewMockConn(1), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    10,
		MaxConns:    100,
		MaxLifetime: 30 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	}
	
	pool, err := New(cfg)
	if err != nil {
		b.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.Get(ctx)
			if err != nil {
				b.Fatal(err)
			}
			conn.Close()
		}
	})
}

// Benchmark with contention
func BenchmarkPoolContention(b *testing.B) {
	factory := func(ctx context.Context) (net.Conn, error) {
		// Simulate some work
		time.Sleep(100 * time.Microsecond)
		return NewMockConn(1), nil
	}
	
	cfg := Config{
		Factory:     factory,
		MinConns:    5,
		MaxConns:    10, // Limited pool size to create contention
		MaxLifetime: 30 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	}
	
	pool, err := New(cfg)
	if err != nil {
		b.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.Get(ctx)
			if err != nil {
				continue // Expected under contention
			}
			// Hold connection briefly to increase contention
			time.Sleep(time.Microsecond)
			conn.Close()
		}
	})
}