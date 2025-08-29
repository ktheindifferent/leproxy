package tests

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// TestResourceLeakComparison demonstrates the difference between
// the old approach (with leaks) and the new TestServer (without leaks)
func TestResourceLeakComparison(t *testing.T) {
	t.Run("OldApproachWithLeaks", func(t *testing.T) {
		// Get baseline
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		baselineGoroutines := runtime.NumGoroutine()
		
		// Simulate old approach - accepting connections without cleanup
		listener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		
		// Old pattern: goroutine that may leak
		done := make(chan bool)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				// Potential leak: no connection tracking
				go func(c net.Conn) {
					// Simulate work
					time.Sleep(50 * time.Millisecond)
					c.Close()
				}(conn)
				
				select {
				case <-done:
					return
				default:
				}
			}
		}()
		
		// Create some connections
		for i := 0; i < 5; i++ {
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				continue
			}
			conn.Close()
		}
		
		// "Stop" server (but goroutines may still be running)
		close(done)
		listener.Close()
		
		// Wait a bit
		time.Sleep(200 * time.Millisecond)
		runtime.GC()
		
		// Check goroutines
		afterGoroutines := runtime.NumGoroutine()
		leaked := afterGoroutines - baselineGoroutines
		
		// In the old approach, we might have leaked goroutines
		t.Logf("Old approach: baseline=%d, after=%d, potential leaks=%d",
			baselineGoroutines, afterGoroutines, leaked)
	})
	
	t.Run("NewApproachNoLeaks", func(t *testing.T) {
		// Get baseline
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		baselineGoroutines := runtime.NumGoroutine()
		
		// Use new TestServer
		server := NewTestServer("localhost:0", HandlerFunc(func(conn net.Conn) {
			// Simulate work
			time.Sleep(50 * time.Millisecond)
			conn.Close()
		}), 10)
		
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		
		// Create some connections
		for i := 0; i < 5; i++ {
			conn, err := net.Dial("tcp", server.GetAddr())
			if err != nil {
				continue
			}
			conn.Close()
		}
		
		// Properly stop server
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
		
		// Wait for cleanup
		time.Sleep(200 * time.Millisecond)
		runtime.GC()
		
		// Check goroutines
		afterGoroutines := runtime.NumGoroutine()
		leaked := afterGoroutines - baselineGoroutines
		
		// With proper cleanup, we should have no leaks
		t.Logf("New approach: baseline=%d, after=%d, leaks=%d",
			baselineGoroutines, afterGoroutines, leaked)
		
		if leaked > 2 { // Allow small variance
			t.Errorf("TestServer leaked goroutines: %d", leaked)
		}
		
		// Verify stats
		stats := server.GetStats()
		if stats.ActiveConnections != 0 {
			t.Errorf("Active connections not cleaned up: %d", stats.ActiveConnections)
		}
		if stats.TotalClosed != stats.TotalAccepted {
			t.Errorf("Not all connections closed: accepted=%d, closed=%d",
				stats.TotalAccepted, stats.TotalClosed)
		}
	})
}

// TestConnectionLimitProtection verifies that connection limits prevent resource exhaustion
func TestConnectionLimitProtection(t *testing.T) {
	maxConns := 5
	server := NewTestServer("localhost:0", HandlerFunc(func(conn net.Conn) {
		// Hold connection open
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}), maxConns)
	
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()
	
	// Try to create more connections than the limit
	var conns []net.Conn
	accepted := 0
	rejected := 0
	
	for i := 0; i < maxConns+5; i++ {
		conn, err := net.Dial("tcp", server.GetAddr())
		if err != nil {
			rejected++
			continue
		}
		
		// Successfully connected
		conns = append(conns, conn)
		accepted++
	}
	
	// Wait to see the actual active connections
	time.Sleep(50 * time.Millisecond)
	stats := server.GetStats()
	actualActive := stats.ActiveConnections
	
	// Clean up
	for _, conn := range conns {
		conn.Close()
	}
	
	t.Logf("Connection limit test: max=%d, tcp_accepted=%d, rejected=%d, active=%d",
		maxConns, accepted, rejected, actualActive)
	
	// The limit should be enforced
	if actualActive > maxConns {
		t.Errorf("Active connections (%d) exceeded limit (%d)", actualActive, maxConns)
	}
	
	// Final stats check
	finalStats := server.GetStats()
	t.Logf("Final stats: total_accepted=%d, active=%d, closed=%d",
		finalStats.TotalAccepted, finalStats.ActiveConnections, finalStats.TotalClosed)
}