// +build integration

package tests

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestGoroutineLeakDetection verifies the leak detection mechanism works
func TestGoroutineLeakDetection(t *testing.T) {
	t.Run("NoLeak", func(t *testing.T) {
		detector := NewGoroutineLeakDetector(t)
		
		// Create some goroutines that properly exit
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				time.Sleep(10 * time.Millisecond)
			}()
		}
		wg.Wait()
		
		// Should not detect any leaks
		detector.Check()
	})
	
	t.Run("WithManagedServer", func(t *testing.T) {
		detector := NewGoroutineLeakDetector(t)
		
		// Create a test server that properly cleans up
		handler := func(conn net.Conn) {
			defer conn.Close()
			// Simple echo server
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				conn.Write(buf[:n])
			}
		}
		
		server, err := NewTestServer(t, "localhost:0", handler)
		if err != nil {
			t.Fatalf("Failed to create server: %v", err)
		}
		server.Start()
		
		// Connect and disconnect multiple times
		for i := 0; i < 3; i++ {
			conn, err := net.Dial("tcp", server.Addr())
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			
			// Send and receive data
			msg := []byte("test message")
			conn.Write(msg)
			
			buf := make([]byte, len(msg))
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			conn.Read(buf)
			
			conn.Close()
		}
		
		// Manually stop server and check for leaks
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server: %v", err)
		}
		
		// Check for leaks after manual cleanup
		detector.Check()
	})
}

// TestProxyServersNoLeak verifies simple test servers clean up properly
func TestProxyServersNoLeak(t *testing.T) {
	// Test with simple echo servers to verify the test infrastructure itself doesn't leak
	servers := []struct {
		name string
		port string
	}{
		{name: "Server1", port: "localhost:0"},
		{name: "Server2", port: "localhost:0"},
		{name: "Server3", port: "localhost:0"},
	}
	
	for _, tc := range servers {
		t.Run(tc.name, func(t *testing.T) {
			detector := NewGoroutineLeakDetector(t)
			
			// Simple echo handler
			handler := func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
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
			
			// Start test server
			server := MustStartTestServer(t, tc.port, handler)
			
			// Make a few connections
			for i := 0; i < 3; i++ {
				conn, err := net.Dial("tcp", server.Addr())
				if err != nil {
					t.Fatalf("Could not connect to %s: %v", tc.name, err)
				}
				
				// Send and receive data
				msg := []byte("test message")
				conn.Write(msg)
				
				buf := make([]byte, len(msg))
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				conn.Read(buf)
				
				conn.Close()
			}
			
			// Server cleanup happens automatically
			t.Cleanup(func() {
				// Allow some tolerance for background cleanup
				detector.CheckWithTolerance(2)
			})
		})
	}
}

// TestConcurrentConnections verifies no leaks with many concurrent connections
func TestConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}
	
	detector := NewGoroutineLeakDetector(t)
	
	// Create a simple echo server
	handler := func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 1024)
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
	
	server := MustStartTestServer(t, "localhost:0", handler)
	
	// Create many concurrent connections
	const numConnections = 100
	const numMessages = 10
	
	var wg sync.WaitGroup
	errors := make(chan error, numConnections)
	
	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", server.Addr())
			if err != nil {
				errors <- fmt.Errorf("connection %d: dial failed: %w", id, err)
				return
			}
			defer conn.Close()
			
			// Send and receive messages
			for j := 0; j < numMessages; j++ {
				msg := fmt.Sprintf("message %d-%d", id, j)
				
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				
				if _, err := conn.Write([]byte(msg)); err != nil {
					errors <- fmt.Errorf("connection %d: write failed: %w", id, err)
					return
				}
				
				buf := make([]byte, len(msg))
				if _, err := conn.Read(buf); err != nil {
					errors <- fmt.Errorf("connection %d: read failed: %w", id, err)
					return
				}
			}
		}(i)
	}
	
	// Wait for all connections to complete
	wg.Wait()
	close(errors)
	
	// Check for errors
	var errCount int
	for err := range errors {
		t.Logf("Connection error: %v", err)
		errCount++
	}
	
	if errCount > numConnections/10 { // Allow up to 10% failure rate
		t.Errorf("Too many connection errors: %d/%d", errCount, numConnections)
	}
	
	// Check for goroutine leaks after cleanup
	t.Cleanup(func() {
		// Allow some tolerance for cleanup
		detector.CheckWithTolerance(5)
	})
}

// TestServerShutdownSequence verifies proper shutdown order
func TestServerShutdownSequence(t *testing.T) {
	detector := NewGoroutineLeakDetector(t)
	
	// Track shutdown sequence
	var shutdownOrder []string
	var mu sync.Mutex
	
	recordShutdown := func(name string) {
		mu.Lock()
		shutdownOrder = append(shutdownOrder, name)
		mu.Unlock()
	}
	
	// Create nested test servers
	handler1 := func(conn net.Conn) {
		defer conn.Close()
		defer recordShutdown("handler1")
		
		// Keep connection open until context cancels
		buf := make([]byte, 1)
		conn.Read(buf)
	}
	
	handler2 := func(conn net.Conn) {
		defer conn.Close()
		defer recordShutdown("handler2")
		
		// Keep connection open until context cancels
		buf := make([]byte, 1)
		conn.Read(buf)
	}
	
	server1 := MustStartTestServer(t, "localhost:0", handler1)
	server2 := MustStartTestServer(t, "localhost:0", handler2)
	
	// Make connections to both servers
	conn1, err := net.Dial("tcp", server1.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to server1: %v", err)
	}
	defer conn1.Close()
	
	conn2, err := net.Dial("tcp", server2.Addr())
	if err != nil {
		t.Fatalf("Failed to connect to server2: %v", err)
	}
	defer conn2.Close()
	
	// Close connections before cleanup
	conn1.Close()
	conn2.Close()
	
	// Give handlers time to record shutdown
	time.Sleep(100 * time.Millisecond)
	
	// Verify no leaks after cleanup
	t.Cleanup(func() {
		detector.Check()
		
		// Log shutdown order for debugging
		mu.Lock()
		t.Logf("Shutdown order: %v", shutdownOrder)
		mu.Unlock()
	})
}

// BenchmarkTestServerOverhead measures overhead of managed test servers
func BenchmarkTestServerOverhead(b *testing.B) {
	// Simple handler that immediately closes
	handler := func(conn net.Conn) {
		conn.Close()
	}
	
	b.Run("ManagedServer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			server, err := NewTestServer(b, "localhost:0", handler)
			if err != nil {
				b.Fatalf("Failed to create server: %v", err)
			}
			server.Start()
			
			// Make a connection
			conn, err := net.Dial("tcp", server.Addr())
			if err == nil {
				conn.Close()
			}
			
			// Stop server
			if err := server.Stop(); err != nil {
				b.Errorf("Failed to stop server: %v", err)
			}
		}
	})
	
	b.Run("UnmanagedServer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			listener, err := net.Listen("tcp", "localhost:0")
			if err != nil {
				b.Fatalf("Failed to create listener: %v", err)
			}
			
			done := make(chan struct{})
			go func() {
				conn, _ := listener.Accept()
				if conn != nil {
					conn.Close()
				}
				close(done)
			}()
			
			// Make a connection
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err == nil {
				conn.Close()
			}
			
			listener.Close()
			<-done
		}
	})
}

// TestGoroutineStackAnalysis analyzes goroutine stacks for debugging
func TestGoroutineStackAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stack analysis in short mode")
	}
	
	// Get initial goroutine count
	initial := runtime.NumGoroutine()
	t.Logf("Initial goroutine count: %d", initial)
	
	// Create some test servers
	servers := make([]*TestServer, 3)
	for i := range servers {
		handler := func(conn net.Conn) {
			defer conn.Close()
			// Simple handler
			buf := make([]byte, 1)
			conn.Read(buf)
		}
		
		server, err := NewTestServer(t, fmt.Sprintf("localhost:0"), handler)
		if err != nil {
			t.Fatalf("Failed to create server %d: %v", i, err)
		}
		server.Start()
		servers[i] = server
	}
	
	// Get goroutine count with servers running
	withServers := runtime.NumGoroutine()
	t.Logf("Goroutine count with %d servers: %d (delta: %d)", 
		len(servers), withServers, withServers-initial)
	
	// Stop all servers
	for i, server := range servers {
		if err := server.Stop(); err != nil {
			t.Errorf("Failed to stop server %d: %v", i, err)
		}
	}
	
	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	
	// Get final count
	final := runtime.NumGoroutine()
	t.Logf("Final goroutine count: %d (delta from initial: %d)", 
		final, final-initial)
	
	// Check for leaks
	if final > initial+2 { // Allow small tolerance
		// Print stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Logf("Goroutine stack traces:\n%s", buf[:stackLen])
		
		t.Errorf("Possible goroutine leak: initial=%d, final=%d, leaked=%d",
			initial, final, final-initial)
	}
}