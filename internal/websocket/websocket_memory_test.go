package websocket

import (
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMemoryLeak checks for memory leaks under sustained load
func TestMemoryLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}
	
	// Create echo server
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, _ := w.(http.Hijacker)
		conn, _, _ := hijacker.Hijack()
		defer conn.Close()
		
		// Send WebSocket upgrade response
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"\r\n"
		conn.Write([]byte(response))
		
		// Echo messages with small delay
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				time.Sleep(10 * time.Millisecond)
				conn.Write(buf[:n])
			}
		}
	}))
	defer wsServer.Close()
	
	// Create proxy with short timeouts
	proxy, err := New(Config{
		Target:       strings.Replace(wsServer.URL, "http://", "ws://", 1),
		IdleTimeout:  2 * time.Second,
		PingInterval: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	// Force GC and get baseline memory
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	
	// Run sustained load
	iterations := 100
	connectionsPerIteration := 10
	
	for i := 0; i < iterations; i++ {
		var wg sync.WaitGroup
		
		for j := 0; j < connectionsPerIteration; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				
				conn, err := net.Dial("tcp", strings.TrimPrefix(proxyServer.URL, "http://"))
				if err != nil {
					return
				}
				defer conn.Close()
				
				// Send WebSocket upgrade
				upgradeReq := "GET / HTTP/1.1\r\n" +
					"Host: localhost\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"\r\n"
				conn.Write([]byte(upgradeReq))
				
				// Read response
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				
				if n > 0 && strings.Contains(string(buf[:n]), "101") {
					// Send and receive a few messages
					for k := 0; k < 5; k++ {
						testData := []byte("Test message")
						conn.Write(testData)
						conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
						conn.Read(buf)
					}
				}
			}()
		}
		
		wg.Wait()
		
		// Check memory periodically
		if i%20 == 0 && i > 0 {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			
			// Memory should not grow significantly
			memGrowth := float64(m.Alloc-baseline.Alloc) / float64(baseline.Alloc)
			if memGrowth > 2.0 { // Allow up to 2x growth
				t.Errorf("Excessive memory growth at iteration %d: baseline=%d MB, current=%d MB, growth=%.2fx",
					i, baseline.Alloc/1024/1024, m.Alloc/1024/1024, memGrowth)
			}
		}
	}
	
	// Final memory check
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	
	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	
	memGrowth := float64(final.Alloc-baseline.Alloc) / float64(baseline.Alloc)
	if memGrowth > 1.5 { // Final check should show minimal growth
		t.Errorf("Memory leak detected: baseline=%d MB, final=%d MB, growth=%.2fx",
			baseline.Alloc/1024/1024, final.Alloc/1024/1024, memGrowth)
	}
	
	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	if finalGoroutines > 50 { // Reasonable upper bound
		t.Errorf("Too many goroutines remaining: %d", finalGoroutines)
	}
}

// TestGoroutineLeakUnderLoad verifies no goroutine leaks under heavy load
func TestGoroutineLeakUnderLoad(t *testing.T) {
	// Create echo server
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, _ := w.(http.Hijacker)
		conn, _, _ := hijacker.Hijack()
		defer conn.Close()
		
		// Send WebSocket upgrade response
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"\r\n"
		conn.Write([]byte(response))
		
		// Read and discard data
		buf := make([]byte, 1024)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}))
	defer wsServer.Close()
	
	// Create proxy
	proxy, err := New(Config{
		Target:      strings.Replace(wsServer.URL, "http://", "ws://", 1),
		IdleTimeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	// Get baseline goroutine count
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()
	
	// Create many connections rapidly
	numConnections := 200
	var wg sync.WaitGroup
	
	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("tcp", strings.TrimPrefix(proxyServer.URL, "http://"))
			if err != nil {
				return
			}
			
			// Send WebSocket upgrade
			upgradeReq := "GET / HTTP/1.1\r\n" +
				"Host: localhost\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"\r\n"
			conn.Write([]byte(upgradeReq))
			
			// Abruptly close connection
			conn.Close()
		}()
		
		// Small delay between connections
		if i%10 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	
	wg.Wait()
	
	// Wait for cleanup
	time.Sleep(3 * time.Second)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	
	// Check final goroutine count
	finalGoroutines := runtime.NumGoroutine()
	goroutineLeak := finalGoroutines - baselineGoroutines
	
	if goroutineLeak > 10 {
		t.Errorf("Goroutine leak detected under load: baseline=%d, final=%d, leak=%d",
			baselineGoroutines, finalGoroutines, goroutineLeak)
	}
}