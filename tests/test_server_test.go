package tests

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestTestServer verifies the TestServer implementation
func TestTestServer(t *testing.T) {
	t.Run("BasicLifecycle", func(t *testing.T) {
		server := NewTestServer("localhost:0", HandlerFunc(SimpleBackend), 10)
		
		// Start server
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		
		// Verify it's running
		if !server.IsRunning() {
			t.Error("Server should be running")
		}
		
		// Get stats
		stats := server.GetStats()
		if stats.ActiveConnections != 0 {
			t.Errorf("Expected 0 connections, got %d", stats.ActiveConnections)
		}
		
		// Stop server
		if err := server.Stop(); err != nil {
			t.Fatalf("Failed to stop server: %v", err)
		}
		
		// Verify it's stopped
		if server.IsRunning() {
			t.Error("Server should be stopped")
		}
	})
	
	t.Run("ConnectionTracking", func(t *testing.T) {
		server := NewTestServer("localhost:0", HandlerFunc(SimpleBackend), 100)
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		defer server.Stop()
		
		// Create multiple connections
		var conns []net.Conn
		for i := 0; i < 5; i++ {
			conn, err := net.Dial("tcp", server.GetAddr())
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			conns = append(conns, conn)
		}
		
		// Wait for connections to be tracked
		if err := server.WaitForConnections(5, 2*time.Second); err != nil {
			t.Fatalf("Failed waiting for connections: %v", err)
		}
		
		stats := server.GetStats()
		if stats.ActiveConnections != 5 {
			t.Errorf("Expected 5 active connections, got %d", stats.ActiveConnections)
		}
		if stats.TotalAccepted != 5 {
			t.Errorf("Expected 5 total accepted, got %d", stats.TotalAccepted)
		}
		
		// Close some connections
		for i := 0; i < 3; i++ {
			conns[i].Close()
		}
		
		// Wait for cleanup
		time.Sleep(100 * time.Millisecond)
		
		stats = server.GetStats()
		if stats.ActiveConnections != 2 {
			t.Errorf("Expected 2 active connections after closing 3, got %d", stats.ActiveConnections)
		}
		if stats.TotalClosed != 3 {
			t.Errorf("Expected 3 closed connections, got %d", stats.TotalClosed)
		}
		
		// Close remaining
		for i := 3; i < 5; i++ {
			conns[i].Close()
		}
	})
	
	t.Run("ConnectionLimit", func(t *testing.T) {
		maxConns := 3
		server := NewTestServer("localhost:0", HandlerFunc(func(conn net.Conn) {
			// Hold connection open
			time.Sleep(1 * time.Second)
			conn.Close()
		}), maxConns)
		
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		defer server.Stop()
		
		// Create connections up to limit
		var conns []net.Conn
		for i := 0; i < maxConns; i++ {
			conn, err := net.Dial("tcp", server.GetAddr())
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			conns = append(conns, conn)
		}
		
		// Wait for connections to be tracked
		if err := server.WaitForConnections(maxConns, 2*time.Second); err != nil {
			t.Fatalf("Failed waiting for connections: %v", err)
		}
		
		// Try to exceed limit - should fail or get closed immediately
		conn, err := net.Dial("tcp", server.GetAddr())
		if err == nil {
			// Connection was accepted, should be closed immediately
			buf := make([]byte, 1)
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err := conn.Read(buf)
			if err == nil {
				t.Error("Connection should have been rejected or closed")
			}
			conn.Close()
		}
		
		// Clean up
		for _, conn := range conns {
			conn.Close()
		}
	})
	
	t.Run("GracefulShutdown", func(t *testing.T) {
		server := NewTestServer("localhost:0", HandlerFunc(func(conn net.Conn) {
			// Simulate long-running connection
			time.Sleep(500 * time.Millisecond)
			conn.Close()
		}), 10)
		
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		
		// Create connections
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := net.Dial("tcp", server.GetAddr())
				if err != nil {
					return
				}
				defer conn.Close()
				
				// Try to read (will block until server closes connection)
				buf := make([]byte, 1)
				conn.Read(buf)
			}()
		}
		
		// Wait for connections to establish
		if err := server.WaitForConnections(3, 2*time.Second); err != nil {
			t.Fatalf("Failed waiting for connections: %v", err)
		}
		
		// Stop server (should wait for connections to finish)
		stopDone := make(chan bool)
		go func() {
			server.Stop()
			close(stopDone)
		}()
		
		select {
		case <-stopDone:
			// Good, shutdown completed
		case <-time.After(2 * time.Second):
			t.Error("Server stop took too long")
		}
		
		// Wait for all goroutines
		wg.Wait()
		
		// Check final stats
		stats := server.GetStats()
		if stats.ActiveConnections != 0 {
			t.Errorf("Expected 0 active connections after stop, got %d", stats.ActiveConnections)
		}
		if stats.TotalClosed != stats.TotalAccepted {
			t.Errorf("Not all connections were closed: accepted=%d, closed=%d", 
				stats.TotalAccepted, stats.TotalClosed)
		}
	})
	
	t.Run("NoResourceLeaks", func(t *testing.T) {
		// Get baseline goroutine count
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
		baselineGoroutines := runtime.NumGoroutine()
		
		// Run multiple server lifecycles
		for i := 0; i < 3; i++ {
			server := NewTestServer("localhost:0", HandlerFunc(SimpleBackend), 50)
			if err := server.Start(); err != nil {
				t.Fatalf("Failed to start server: %v", err)
			}
			
			// Create and close connections
			for j := 0; j < 10; j++ {
				conn, err := net.Dial("tcp", server.GetAddr())
				if err != nil {
					continue
				}
				conn.Write([]byte("test"))
				buf := make([]byte, 4)
				conn.Read(buf)
				conn.Close()
			}
			
			// Stop server
			if err := server.Stop(); err != nil {
				t.Fatalf("Failed to stop server: %v", err)
			}
		}
		
		// Allow cleanup
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
		
		// Check goroutine count
		finalGoroutines := runtime.NumGoroutine()
		leaked := finalGoroutines - baselineGoroutines
		
		// Allow for some variance in goroutine count
		if leaked > 5 {
			t.Errorf("Possible goroutine leak: baseline=%d, final=%d, leaked=%d",
				baselineGoroutines, finalGoroutines, leaked)
		}
	})
	
	t.Run("MultipleStartStop", func(t *testing.T) {
		server := NewTestServer("localhost:0", HandlerFunc(SimpleBackend), 10)
		
		// First start
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		
		// Second start should be no-op
		if err := server.Start(); err != nil {
			t.Errorf("Second start should not error: %v", err)
		}
		
		// First stop
		if err := server.Stop(); err != nil {
			t.Fatalf("Failed to stop server: %v", err)
		}
		
		// Second stop should be no-op
		if err := server.Stop(); err != nil {
			t.Errorf("Second stop should not error: %v", err)
		}
		
		// Cannot start after stop
		if err := server.Start(); err != ErrServerStopped {
			t.Errorf("Expected ErrServerStopped, got: %v", err)
		}
	})
	
	t.Run("ConcurrentOperations", func(t *testing.T) {
		server := NewTestServer("localhost:0", HandlerFunc(SimpleBackend), 100)
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		defer server.Stop()
		
		// Concurrent connections
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				conn, err := net.Dial("tcp", server.GetAddr())
				if err != nil {
					return
				}
				defer conn.Close()
				
				// Send and receive data
				msg := fmt.Sprintf("msg-%d", id)
				conn.Write([]byte(msg))
				
				buf := make([]byte, len(msg))
				conn.Read(buf)
			}(i)
		}
		
		// Wait for all operations
		wg.Wait()
		
		// Check stats
		stats := server.GetStats()
		if stats.TotalAccepted < 40 { // Allow for some connection failures
			t.Errorf("Expected at least 40 connections, got %d", stats.TotalAccepted)
		}
	})
}

// TestTestServerMemoryLeaks runs a stress test to detect memory leaks
func TestTestServerMemoryLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}
	
	// Run many iterations with connections
	for iteration := 0; iteration < 10; iteration++ {
		server := NewTestServer("localhost:0", HandlerFunc(SimpleBackend), 100)
		if err := server.Start(); err != nil {
			t.Fatalf("Failed to start server: %v", err)
		}
		
		// Create many short-lived connections
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				
				d := net.Dialer{}
				conn, err := d.DialContext(ctx, "tcp", server.GetAddr())
				if err != nil {
					return
				}
				
				conn.Write([]byte("test"))
				conn.Close()
			}()
		}
		
		wg.Wait()
		server.Stop()
		
		// Force GC between iterations
		runtime.GC()
		runtime.Gosched()
	}
	
	// Final memory check would go here in a real application
	// using runtime.MemStats
}

// BenchmarkTestServer benchmarks the TestServer
func BenchmarkTestServer(b *testing.B) {
	server := NewTestServer("localhost:0", HandlerFunc(SimpleBackend), 1000)
	if err := server.Start(); err != nil {
		b.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := net.Dial("tcp", server.GetAddr())
			if err != nil {
				continue
			}
			
			conn.Write([]byte("bench"))
			buf := make([]byte, 5)
			conn.Read(buf)
			conn.Close()
		}
	})
	
	b.StopTimer()
	stats := server.GetStats()
	b.Logf("Total connections: %d, Total closed: %d", stats.TotalAccepted, stats.TotalClosed)
}