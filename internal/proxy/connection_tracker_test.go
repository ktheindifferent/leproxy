package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     atomic.Bool
	closeChan  chan struct{}
	deadline   time.Time
}

func newMockConn(remote string) *mockConn {
	return &mockConn{
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		closeChan:  make(chan struct{}),
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	<-m.closeChan
	return 0, fmt.Errorf("connection closed")
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed.Load() {
		return 0, fmt.Errorf("connection closed")
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	if m.closed.CompareAndSwap(false, true) {
		close(m.closeChan)
	}
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockConn) SetDeadline(t time.Time) error {
	m.deadline = t
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestConnectionTracker_Basic(t *testing.T) {
	tracker := NewConnectionTracker(10, 5*time.Second)
	
	// Test tracking a connection
	conn := newMockConn("127.0.0.1:1234")
	info, err := tracker.Track(conn, TypeMySQL)
	if err != nil {
		t.Fatalf("Failed to track connection: %v", err)
	}
	if info == nil {
		t.Fatal("Expected connection info, got nil")
	}
	
	// Verify stats
	stats := tracker.GetStats()
	if activeConns := stats["active_connections"].(int32); activeConns != 1 {
		t.Errorf("Expected 1 active connection, got %d", activeConns)
	}
	if totalConns := stats["total_connections"].(uint64); totalConns != 1 {
		t.Errorf("Expected 1 total connection, got %d", totalConns)
	}
	
	// Test untracking
	tracker.Untrack(conn)
	
	// Verify stats after untrack
	stats = tracker.GetStats()
	if activeConns := stats["active_connections"].(int32); activeConns != 0 {
		t.Errorf("Expected 0 active connections after untrack, got %d", activeConns)
	}
}

func TestConnectionTracker_MaxConnections(t *testing.T) {
	maxConns := 5
	tracker := NewConnectionTracker(maxConns, 5*time.Second)
	
	conns := make([]*mockConn, 0, maxConns+1)
	
	// Track up to max connections
	for i := 0; i < maxConns; i++ {
		conn := newMockConn(fmt.Sprintf("127.0.0.1:%d", 1234+i))
		conns = append(conns, conn)
		
		_, err := tracker.Track(conn, TypePostgres)
		if err != nil {
			t.Fatalf("Failed to track connection %d: %v", i, err)
		}
	}
	
	// Verify we're at max
	if activeCount := tracker.GetActiveCount(); activeCount != int32(maxConns) {
		t.Errorf("Expected %d active connections, got %d", maxConns, activeCount)
	}
	
	// Try to track one more - should fail
	extraConn := newMockConn("127.0.0.1:9999")
	_, err := tracker.Track(extraConn, TypePostgres)
	if err == nil {
		t.Error("Expected error when exceeding max connections, got nil")
	}
	
	// Verify rejected connection was counted
	stats := tracker.GetStats()
	if rejected := stats["rejected_connections"].(uint64); rejected != 1 {
		t.Errorf("Expected 1 rejected connection, got %d", rejected)
	}
	
	// Untrack one connection
	tracker.Untrack(conns[0])
	
	// Now we should be able to track the extra connection
	_, err = tracker.Track(extraConn, TypePostgres)
	if err != nil {
		t.Errorf("Failed to track connection after freeing slot: %v", err)
	}
	
	// Clean up
	for _, conn := range conns[1:] {
		tracker.Untrack(conn)
	}
	tracker.Untrack(extraConn)
}

func TestConnectionTracker_ConcurrentOperations(t *testing.T) {
	tracker := NewConnectionTracker(100, 5*time.Second)
	
	numGoroutines := 20
	connsPerGoroutine := 5
	
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*connsPerGoroutine)
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			conns := make([]*mockConn, 0, connsPerGoroutine)
			
			// Track connections
			for j := 0; j < connsPerGoroutine; j++ {
				conn := newMockConn(fmt.Sprintf("127.0.0.1:%d", 10000+id*100+j))
				conns = append(conns, conn)
				
				if _, err := tracker.Track(conn, TypeRedis); err != nil {
					errors <- fmt.Errorf("goroutine %d: failed to track conn %d: %v", id, j, err)
					return
				}
				
				// Simulate some activity
				tracker.UpdateActivity(conn, uint64(j*100), uint64(j*50))
			}
			
			// Small delay to simulate work
			time.Sleep(10 * time.Millisecond)
			
			// Untrack all connections
			for _, conn := range conns {
				tracker.Untrack(conn)
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Error(err)
	}
	
	// Verify all connections are cleaned up
	if activeCount := tracker.GetActiveCount(); activeCount != 0 {
		t.Errorf("Expected 0 active connections after cleanup, got %d", activeCount)
	}
	
	// Verify total connections
	stats := tracker.GetStats()
	expectedTotal := uint64(numGoroutines * connsPerGoroutine)
	if total := stats["total_connections"].(uint64); total != expectedTotal {
		t.Errorf("Expected %d total connections, got %d", expectedTotal, total)
	}
}

func TestConnectionTracker_GracefulShutdown(t *testing.T) {
	tracker := NewConnectionTracker(10, 2*time.Second)
	
	// Track some connections
	conns := make([]*mockConn, 5)
	for i := 0; i < 5; i++ {
		conns[i] = newMockConn(fmt.Sprintf("127.0.0.1:%d", 2000+i))
		if _, err := tracker.Track(conns[i], TypeMongoDB); err != nil {
			t.Fatalf("Failed to track connection: %v", err)
		}
	}
	
	// Start graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- tracker.CloseAll(ctx)
	}()
	
	// Simulate connections closing after a delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		for _, conn := range conns {
			tracker.Untrack(conn)
			conn.Close()
		}
	}()
	
	// Wait for shutdown
	err := <-shutdownDone
	if err != nil {
		t.Errorf("Graceful shutdown failed: %v", err)
	}
	
	// Verify tracker is closed
	if !tracker.closed.Load() {
		t.Error("Tracker should be marked as closed after shutdown")
	}
	
	// Verify we can't track new connections
	newConn := newMockConn("127.0.0.1:9999")
	if _, err := tracker.Track(newConn, TypeMongoDB); err == nil {
		t.Error("Should not be able to track connections after shutdown")
	}
}

func TestConnectionTracker_IdleConnectionCleanup(t *testing.T) {
	tracker := NewConnectionTracker(10, 5*time.Second)
	
	// Track connections with different activity levels
	activeConn := newMockConn("127.0.0.1:3001")
	idleConn1 := newMockConn("127.0.0.1:3002")
	idleConn2 := newMockConn("127.0.0.1:3003")
	
	tracker.Track(activeConn, TypeKafka)
	tracker.Track(idleConn1, TypeKafka)
	tracker.Track(idleConn2, TypeKafka)
	
	// Update activity for active connection
	tracker.UpdateActivity(activeConn, 100, 50)
	
	// Let idle connections age
	time.Sleep(100 * time.Millisecond)
	
	// Update activity for active connection again
	tracker.UpdateActivity(activeConn, 200, 100)
	
	// Clean up idle connections (very short idle time for testing)
	closed := tracker.CleanupIdleConnections(50 * time.Millisecond)
	
	// Should have closed 2 idle connections
	if closed != 2 {
		t.Errorf("Expected to close 2 idle connections, closed %d", closed)
	}
	
	// Active connection should still be tracked
	if tracker.GetActiveCount() != 1 {
		t.Errorf("Expected 1 active connection remaining, got %d", tracker.GetActiveCount())
	}
	
	// Clean up
	tracker.Untrack(activeConn)
}

func TestConnectionTracker_Backpressure(t *testing.T) {
	maxConns := 10
	tracker := NewConnectionTracker(maxConns, 5*time.Second)
	
	// Track connections up to 90% of max (backpressure threshold)
	threshold := int(float64(maxConns) * 0.9)
	conns := make([]*mockConn, 0, threshold)
	
	for i := 0; i < threshold-1; i++ {
		conn := newMockConn(fmt.Sprintf("127.0.0.1:%d", 4000+i))
		conns = append(conns, conn)
		tracker.Track(conn, TypeCassandra)
	}
	
	// Should not trigger backpressure yet
	if tracker.ShouldPauseAccept() {
		t.Error("Should not pause accepts below threshold")
	}
	
	// Add one more to reach threshold
	conn := newMockConn("127.0.0.1:4999")
	conns = append(conns, conn)
	tracker.Track(conn, TypeCassandra)
	
	// Should now trigger backpressure
	if !tracker.ShouldPauseAccept() {
		t.Error("Should pause accepts at or above threshold")
	}
	
	// Clean up
	for _, c := range conns {
		tracker.Untrack(c)
	}
}

func TestConnectionTracker_HealthCheck(t *testing.T) {
	maxConns := 10
	tracker := NewConnectionTracker(maxConns, 5*time.Second)
	
	// Initially healthy
	if !tracker.IsHealthy() {
		t.Error("Tracker should be healthy initially")
	}
	
	// Add custom health callback
	customHealthy := atomic.Bool{}
	customHealthy.Store(true)
	tracker.SetHealthCallback(func() bool {
		return customHealthy.Load()
	})
	
	// Still healthy with custom callback
	if !tracker.IsHealthy() {
		t.Error("Tracker should be healthy with custom callback returning true")
	}
	
	// Set custom health to false
	customHealthy.Store(false)
	if tracker.IsHealthy() {
		t.Error("Tracker should be unhealthy when custom callback returns false")
	}
	
	// Reset custom health
	customHealthy.Store(true)
	
	// Fill up to 95% capacity (health check threshold)
	healthThreshold := int(float64(maxConns) * 0.95)
	conns := make([]*mockConn, 0, healthThreshold)
	
	for i := 0; i < healthThreshold-1; i++ {
		conn := newMockConn(fmt.Sprintf("127.0.0.1:%d", 5000+i))
		conns = append(conns, conn)
		tracker.Track(conn, TypeElastic)
	}
	
	// Should still be healthy just below threshold
	if !tracker.IsHealthy() {
		t.Error("Tracker should be healthy below 95% capacity")
	}
	
	// Add one more to reach threshold
	conn := newMockConn("127.0.0.1:5999")
	tracker.Track(conn, TypeElastic)
	
	// Should now be unhealthy
	if tracker.IsHealthy() {
		t.Error("Tracker should be unhealthy at 95% capacity")
	}
	
	// Close tracker
	tracker.closed.Store(true)
	if tracker.IsHealthy() {
		t.Error("Tracker should be unhealthy when closed")
	}
}

func TestConnectionTracker_UpdateActivity(t *testing.T) {
	tracker := NewConnectionTracker(10, 5*time.Second)
	
	conn := newMockConn("127.0.0.1:6000")
	info, err := tracker.Track(conn, TypeMemcached)
	if err != nil {
		t.Fatalf("Failed to track connection: %v", err)
	}
	
	// Update activity multiple times
	tracker.UpdateActivity(conn, 100, 50)
	tracker.UpdateActivity(conn, 200, 150)
	tracker.UpdateActivity(conn, 300, 200)
	
	// Verify bytes are accumulated
	if info.BytesIn.Load() != 600 {
		t.Errorf("Expected 600 bytes in, got %d", info.BytesIn.Load())
	}
	if info.BytesOut.Load() != 400 {
		t.Errorf("Expected 400 bytes out, got %d", info.BytesOut.Load())
	}
	
	// Verify last active time is updated
	lastActive := info.LastActive.Load()
	if lastActive == nil {
		t.Error("Last active time should be set")
	}
	
	// Clean up
	tracker.Untrack(conn)
	
	// Verify stats include byte totals
	stats := tracker.GetStats()
	if totalIn := stats["total_bytes_in"].(uint64); totalIn != 600 {
		t.Errorf("Expected 600 total bytes in, got %d", totalIn)
	}
	if totalOut := stats["total_bytes_out"].(uint64); totalOut != 400 {
		t.Errorf("Expected 400 total bytes out, got %d", totalOut)
	}
}

func TestConnectionTracker_ConcurrentCloseAll(t *testing.T) {
	tracker := NewConnectionTracker(100, 1*time.Second)
	
	// Track many connections
	numConns := 50
	conns := make([]*mockConn, numConns)
	for i := 0; i < numConns; i++ {
		conns[i] = newMockConn(fmt.Sprintf("127.0.0.1:%d", 7000+i))
		tracker.Track(conns[i], TypeSMTP)
	}
	
	// Start multiple goroutines to untrack connections during shutdown
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			time.Sleep(100 * time.Millisecond)
			for j := start; j < start+5 && j < numConns; j++ {
				tracker.Untrack(conns[j])
				conns[j].Close()
			}
		}(i * 5)
	}
	
	// Start graceful shutdown concurrently
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	shutdownErr := make(chan error, 1)
	go func() {
		shutdownErr <- tracker.CloseAll(ctx)
	}()
	
	// Wait for untrack goroutines
	wg.Wait()
	
	// Wait for shutdown
	if err := <-shutdownErr; err != nil {
		t.Logf("Shutdown completed with: %v", err)
	}
	
	// Verify no active connections remain
	if active := tracker.GetActiveCount(); active != 0 {
		t.Errorf("Expected 0 active connections after shutdown, got %d", active)
	}
}