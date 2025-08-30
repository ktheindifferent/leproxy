package dbproxy

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBaseProxyGoroutineLeaks tests that BaseProxy properly cleans up goroutines
func TestBaseProxyGoroutineLeaks(t *testing.T) {
	// Record initial goroutine count
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Create backend server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock backend server
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			// Echo server
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	
	// Create proxy with mock handler
	handler := &mockHandler{}
	proxy := NewBaseProxy(backendListener.Addr().String(), nil, handler)
	
	// Start proxy in goroutine
	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		proxy.Serve(listener)
	}()
	
	// Test multiple connections
	var clientWg sync.WaitGroup
	numConnections := 10
	for i := 0; i < numConnections; i++ {
		clientWg.Add(1)
		go func(id int) {
			defer clientWg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Errorf("Connection %d failed to dial: %v", id, err)
				return
			}
			defer conn.Close()
			
			// Send some data
			testData := fmt.Sprintf("test-%d", id)
			if _, err := conn.Write([]byte(testData)); err != nil {
				t.Errorf("Connection %d failed to write: %v", id, err)
				return
			}
			
			// Read response
			buf := make([]byte, len(testData))
			if _, err := conn.Read(buf); err != nil {
				t.Errorf("Connection %d failed to read: %v", id, err)
				return
			}
			
			// Verify response
			if string(buf) != testData {
				t.Errorf("Connection %d got wrong response: expected %s, got %s", id, testData, string(buf))
			}
		}(i)
	}
	
	// Wait for all clients to complete
	clientWg.Wait()
	
	// Give some time for connections to close
	time.Sleep(100 * time.Millisecond)
	
	// Shutdown proxy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := proxy.Shutdown(ctx); err != nil {
		t.Errorf("Failed to shutdown proxy: %v", err)
	}
	
	// Wait for proxy to finish
	proxyWg.Wait()
	
	// Close listeners
	listener.Close()
	backendListener.Close()
	
	// Wait for goroutines to clean up
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 { // Allow small variance for test framework
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, diff=%d", 
			initialGoroutines, finalGoroutines, goroutineDiff)
		
		// Print stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Logf("Current goroutine stack traces:\n%s", buf[:stackLen])
	}
	
	// Verify no active connections remain
	if activeConns := proxy.GetActiveConnections(); activeConns != 0 {
		t.Errorf("Active connections not cleaned up: %d remaining", activeConns)
	}
}

// TestProxyWithConnectionFailures tests handling of connection failures
func TestProxyWithConnectionFailures(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create proxy with unreachable backend
	handler := &mockHandler{}
	proxy := NewBaseProxy("127.0.0.1:1", nil, handler) // Port 1 is typically unavailable
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Try to connect multiple times
	var wg sync.WaitGroup
	failedConnections := int32(0)
	
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				atomic.AddInt32(&failedConnections, 1)
				return
			}
			defer conn.Close()
			
			// Connection should be closed by proxy due to backend failure
			buf := make([]byte, 1)
			_, err = conn.Read(buf)
			if err == nil {
				t.Error("Expected connection to be closed due to backend failure")
			}
		}()
	}
	
	wg.Wait()
	
	// Shutdown proxy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxy.Shutdown(ctx)
	
	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("Goroutine leak after connection failures: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestProxyIdleTimeout tests that idle connections are properly timed out
func TestProxyIdleTimeout(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock backend that doesn't send data
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			// Just hold the connection open
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(10 * time.Second)
			}(conn)
		}
	}()
	
	// Create proxy with short idle timeout
	handler := &mockHandler{}
	proxy := NewBaseProxy(backendListener.Addr().String(), nil, handler)
	proxy.IdleTimeout = 1 * time.Second
	proxy.ReadTimeout = 500 * time.Millisecond
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Create idle connection
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	
	// Wait for timeout
	time.Sleep(2 * time.Second)
	
	// Connection should be closed due to idle timeout
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Expected connection to be closed due to idle timeout")
	}
	conn.Close()
	
	// Shutdown proxy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxy.Shutdown(ctx)
	
	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("Goroutine leak after idle timeout: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestConcurrentShutdown tests graceful shutdown under load
func TestConcurrentShutdown(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Echo backend
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					time.Sleep(10 * time.Millisecond) // Simulate processing
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	
	// Create proxy
	handler := &mockHandler{}
	proxy := NewBaseProxy(backendListener.Addr().String(), nil, handler)
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Create many concurrent connections
	var connWg sync.WaitGroup
	stopClients := make(chan struct{})
	numClients := 20
	
	for i := 0; i < numClients; i++ {
		connWg.Add(1)
		go func(id int) {
			defer connWg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return // Expected during shutdown
			}
			defer conn.Close()
			
			// Keep sending data until stopped
			for {
				select {
				case <-stopClients:
					return
				default:
					data := fmt.Sprintf("client-%d", id)
					conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
					if _, err := conn.Write([]byte(data)); err != nil {
						return
					}
					
					buf := make([]byte, len(data))
					conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					if _, err := conn.Read(buf); err != nil {
						return
					}
					
					time.Sleep(5 * time.Millisecond)
				}
			}
		}(i)
	}
	
	// Let connections establish
	time.Sleep(100 * time.Millisecond)
	
	// Check active connections
	activeConns := proxy.GetActiveConnections()
	if activeConns == 0 {
		t.Error("Expected active connections during load")
	}
	t.Logf("Active connections during load: %d", activeConns)
	
	// Initiate shutdown while connections are active
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- proxy.Shutdown(ctx)
	}()
	
	// Stop clients after a short delay
	time.Sleep(100 * time.Millisecond)
	close(stopClients)
	
	// Wait for clients to finish
	connWg.Wait()
	
	// Wait for shutdown to complete
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("Shutdown timed out")
	}
	
	// Verify no active connections
	if activeConns := proxy.GetActiveConnections(); activeConns != 0 {
		t.Errorf("Active connections after shutdown: %d", activeConns)
	}
	
	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("Goroutine leak after concurrent shutdown: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// mockHandler implements ProxyHandler for testing
type mockHandler struct{}

func (h *mockHandler) HandleProtocolNegotiation(ctx context.Context, clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	// Simple pass-through for testing
	return clientConn, backendConn, nil
}

func (h *mockHandler) GetProtocolName() string {
	return "Mock"
}

// TestPostgresProxyGoroutineLeaks tests PostgreSQL proxy for goroutine leaks
func TestPostgresProxyGoroutineLeaks(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend PostgreSQL mock server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock PostgreSQL server
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read SSL request
				buf := make([]byte, 8)
				n, err := c.Read(buf)
				if err != nil || n != 8 {
					return
				}
				// Respond with 'N' (no SSL)
				c.Write([]byte{'N'})
				// Echo subsequent data
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	
	// Create PostgreSQL proxy
	proxy := NewPostgresProxy(backendListener.Addr().String(), nil)
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Test multiple connections
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Send non-SSL request
			data := []byte{0, 0, 0, 8, 0, 0, 0, 0}
			if _, err := conn.Write(data); err != nil {
				return
			}
			
			// Read response
			buf := make([]byte, 1)
			_, _ = conn.Read(buf) // Ignore error as connection may be closed
		}()
	}
	
	wg.Wait()
	
	// Shutdown proxy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxy.Shutdown(ctx)
	
	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("PostgreSQL proxy goroutine leak: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestMySQLProxyGoroutineLeaks tests MySQL proxy for goroutine leaks
func TestMySQLProxyGoroutineLeaks(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend MySQL mock server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock MySQL server
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Send initial handshake packet (simplified)
				handshake := make([]byte, 100)
				handshake[0] = 10 // Protocol version
				copy(handshake[1:], "5.7.0\x00") // Version string
				c.Write(handshake)
				
				// Read client response and echo
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	
	// Create MySQL proxy
	proxy := NewMySQLProxy(backendListener.Addr().String(), nil)
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Test multiple connections
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Read handshake
			buf := make([]byte, 100)
			_, _ = conn.Read(buf) // Ignore error as handshake may not complete
			
			// Send some data
			_, _ = conn.Write([]byte("test")) // Ignore error as connection may be closed
		}()
	}
	
	wg.Wait()
	
	// Shutdown proxy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxy.Shutdown(ctx)
	
	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("MySQL proxy goroutine leak: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestRedisProxyGoroutineLeaks tests Redis proxy for goroutine leaks
func TestRedisProxyGoroutineLeaks(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend Redis mock server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock Redis server
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					// Simple PONG response for any command
					c.Write([]byte("+PONG\r\n"))
					_ = n // Ignore command content for simplicity
				}
			}(conn)
		}
	}()
	
	// Create Redis proxy
	proxy := NewRedisProxy(backendListener.Addr().String(), nil)
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Test multiple connections
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Send PING command
			if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
				return // Connection may be closed
			}
			
			// Read response
			buf := make([]byte, 10)
			_, _ = conn.Read(buf) // Ignore error as connection may be closed
		}()
	}
	
	wg.Wait()
	
	// Shutdown proxy
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxy.Shutdown(ctx)
	
	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("Redis proxy goroutine leak: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// BenchmarkProxyThroughput benchmarks the proxy throughput
func BenchmarkProxyThroughput(b *testing.B) {
	// Create backend server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Echo backend
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	
	// Create proxy
	handler := &mockHandler{}
	proxy := NewBaseProxy(backendListener.Addr().String(), nil, handler)
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
	}()
	
	// Create client connection
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		b.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()
	
	// Benchmark data transfer
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	buf := make([]byte, len(data))
	
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(data); err != nil {
			b.Fatalf("Write failed: %v", err)
		}
		if _, err := conn.Read(buf); err != nil {
			b.Fatalf("Read failed: %v", err)
		}
	}
}