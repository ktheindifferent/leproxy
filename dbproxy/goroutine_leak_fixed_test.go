package dbproxy

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestMongoDBProxyGoroutineLeaksFixed tests MongoDB proxy for goroutine leaks after fix
func TestMongoDBProxyGoroutineLeaksFixed(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend MongoDB mock server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock MongoDB server that simulates both copy directions failing
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Simulate a server that closes connection after initial read
				buf := make([]byte, 1024)
				c.Read(buf)
				c.Close() // Abrupt close to trigger error in both directions
			}(conn)
		}
	}()
	
	// Create MongoDB proxy
	proxy := NewMongoDBProxy(backendListener.Addr().String(), nil)
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Test multiple connections that will fail
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Send some data
			conn.Write([]byte("test"))
			
			// Try to read - should fail due to backend closing
			buf := make([]byte, 10)
			conn.Read(buf)
		}()
	}
	
	wg.Wait()
	
	// Close listener to stop proxy
	listener.Close()
	
	// Wait for cleanup
	time.Sleep(1 * time.Second)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("MongoDB proxy goroutine leak after fix: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
		
		// Print stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Logf("Current goroutine stack traces:\n%s", buf[:stackLen])
	}
}

// TestRedisProxyGoroutineLeaksFixed tests Redis proxy for goroutine leaks after fix
func TestRedisProxyGoroutineLeaksFixed(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend Redis mock server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock Redis server that simulates both copy directions failing
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Simulate a server that closes connection after initial read
				buf := make([]byte, 1024)
				c.Read(buf)
				c.Close() // Abrupt close to trigger error in both directions
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
	
	// Test multiple connections that will fail
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Send PING command
			conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
			
			// Try to read - should fail due to backend closing
			buf := make([]byte, 10)
			conn.Read(buf)
		}()
	}
	
	wg.Wait()
	
	// Close listener to stop proxy
	listener.Close()
	
	// Wait for cleanup
	time.Sleep(1 * time.Second)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("Redis proxy goroutine leak after fix: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
		
		// Print stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Logf("Current goroutine stack traces:\n%s", buf[:stackLen])
	}
}

// TestAllProxiesGoroutineLeaks tests all fixed proxies for goroutine leaks
func TestAllProxiesGoroutineLeaks(t *testing.T) {
	proxies := []struct {
		name    string
		factory func(string) interface{ Serve(net.Listener) error }
	}{
		{"AMQP", func(backend string) interface{ Serve(net.Listener) error } {
			return NewAMQPProxy(backend, nil)
		}},
		{"Cassandra", func(backend string) interface{ Serve(net.Listener) error } {
			return NewCassandraProxy(backend, nil)
		}},
		{"Elasticsearch", func(backend string) interface{ Serve(net.Listener) error } {
			return NewElasticsearchProxy(backend, nil)
		}},
		{"FTP", func(backend string) interface{ Serve(net.Listener) error } {
			return NewFTPProxy(backend, nil)
		}},
		{"Kafka", func(backend string) interface{ Serve(net.Listener) error } {
			return NewKafkaProxy(backend, nil)
		}},
		{"LDAP", func(backend string) interface{ Serve(net.Listener) error } {
			return NewLDAPProxy(backend, nil)
		}},
		{"Memcached", func(backend string) interface{ Serve(net.Listener) error } {
			return NewMemcachedProxy(backend, nil)
		}},
		{"MongoDB", func(backend string) interface{ Serve(net.Listener) error } {
			return NewMongoDBProxy(backend, nil)
		}},
		{"MSSQL", func(backend string) interface{ Serve(net.Listener) error } {
			return NewMSSQLProxy(backend, nil)
		}},
		{"Redis", func(backend string) interface{ Serve(net.Listener) error } {
			return NewRedisProxy(backend, nil)
		}},
		{"SMTP", func(backend string) interface{ Serve(net.Listener) error } {
			return NewSMTPProxy(backend, nil)
		}},
	}
	
	for _, p := range proxies {
		t.Run(p.name, func(t *testing.T) {
			runtime.GC()
			initialGoroutines := runtime.NumGoroutine()
			
			// Create backend that simulates failure
			backendListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to create backend listener: %v", err)
			}
			defer backendListener.Close()
			
			// Mock backend that closes connections
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					
					conn, err := backendListener.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						// Close connection immediately to trigger errors
						c.Close()
					}(conn)
				}
			}()
			
			// Create proxy
			proxy := p.factory(backendListener.Addr().String())
			
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
					
					// Send some data
					conn.Write([]byte("test"))
					
					// Read should fail
					buf := make([]byte, 10)
					conn.Read(buf)
				}()
			}
			
			wg.Wait()
			
			// Cleanup
			cancel()
			listener.Close()
			backendListener.Close()
			
			// Wait for cleanup
			time.Sleep(500 * time.Millisecond)
			runtime.GC()
			
			// Check for goroutine leaks
			finalGoroutines := runtime.NumGoroutine()
			goroutineDiff := finalGoroutines - initialGoroutines
			
			if goroutineDiff > 3 { // Allow small variance
				t.Errorf("%s proxy goroutine leak: initial=%d, final=%d, diff=%d",
					p.name, initialGoroutines, finalGoroutines, goroutineDiff)
			}
		})
	}
}

// TestBidirectionalCopyErrorHandling tests that both goroutines complete when errors occur
func TestBidirectionalCopyErrorHandling(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create backend that will cause errors in both directions
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	defer backendListener.Close()
	
	// Mock backend that causes errors
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Read once then close to cause EOF in both directions
				buf := make([]byte, 10)
				c.Read(buf)
				c.Close()
			}(conn)
		}
	}()
	
	// Test with base proxy
	handler := &mockHandler{}
	proxy := NewBaseProxy(backendListener.Addr().String(), nil, handler)
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	// Start proxy
	go proxy.Serve(listener)
	
	// Create connections that will experience errors
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Write data
			conn.Write([]byte("test"))
			
			// Read will fail
			io.Copy(io.Discard, conn)
		}()
	}
	
	wg.Wait()
	
	// Close listener
	listener.Close()
	
	// Wait for cleanup
	time.Sleep(1 * time.Second)
	runtime.GC()
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 2 {
		t.Errorf("Bidirectional copy goroutine leak: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
		
		// Print stack traces for debugging
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Logf("Current goroutine stack traces:\n%s", buf[:stackLen])
	}
}

// mockHandler implements ProxyHandler for testing
type mockHandler struct{}

func (h *mockHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (h *mockHandler) GetProtocolName() string {
	return "Mock"
}