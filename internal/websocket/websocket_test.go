package websocket

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/artyom/leproxy/internal/ratelimit"
)

// TestGoroutineCleanup verifies that goroutines are properly cleaned up
func TestGoroutineCleanup(t *testing.T) {
	// Create a test WebSocket server
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketRequest(r) {
			http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
			return
		}
		
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
			return
		}
		
		conn, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		
		// Send WebSocket upgrade response
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"\r\n"
		conn.Write([]byte(response))
		
		// Echo server
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				conn.Write(buf[:n])
			}
		}
	}))
	defer wsServer.Close()
	
	// Create WebSocket proxy
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
	
	// Get initial goroutine count
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Connect multiple clients
	numClients := 10
	var wg sync.WaitGroup
	
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			
			// Create WebSocket client connection
			req, _ := http.NewRequest("GET", proxyServer.URL, nil)
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "Upgrade")
			
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Logf("Client %d: Failed to connect: %v", clientID, err)
				return
			}
			defer resp.Body.Close()
			
			// Keep connection open for a short time
			time.Sleep(500 * time.Millisecond)
		}(i)
	}
	
	wg.Wait()
	
	// Wait for connections to close and goroutines to clean up
	time.Sleep(3 * time.Second)
	
	// Force garbage collection and check goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	
	// Allow for some variance but check for leaks
	goroutineDiff := finalGoroutines - initialGoroutines
	if goroutineDiff > 2 {
		t.Errorf("Potential goroutine leak detected: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestIdleTimeout verifies that idle connections are closed
func TestIdleTimeout(t *testing.T) {
	var serverConnClosed atomic.Bool
	
	// Create a test WebSocket server
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, _ := w.(http.Hijacker)
		conn, _, _ := hijacker.Hijack()
		defer func() {
			conn.Close()
			serverConnClosed.Store(true)
		}()
		
		// Send WebSocket upgrade response
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"\r\n"
		conn.Write([]byte(response))
		
		// Wait for connection to be closed by timeout
		buf := make([]byte, 1)
		conn.Read(buf)
	}))
	defer wsServer.Close()
	
	// Create proxy with short idle timeout
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
	
	// Connect client
	req, _ := http.NewRequest("GET", proxyServer.URL, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer resp.Body.Close()
	
	// Wait for idle timeout
	time.Sleep(2 * time.Second)
	
	// Check that connection was closed
	if !serverConnClosed.Load() {
		t.Error("Connection was not closed after idle timeout")
	}
}

// TestMaxMessageSize verifies message size limits
func TestMaxMessageSize(t *testing.T) {
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
		
		// Echo large messages
		io.Copy(conn, conn)
	}))
	defer wsServer.Close()
	
	// Create proxy with small message size limit
	proxy, err := New(Config{
		Target:         strings.Replace(wsServer.URL, "http://", "ws://", 1),
		MaxMessageSize: 1024, // 1KB limit
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	// Connect and try to send large message
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxyServer.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	
	// Send WebSocket upgrade request
	upgradeReq := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"\r\n"
	conn.Write([]byte(upgradeReq))
	
	// Read upgrade response
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if line == "\r\n" {
			break
		}
	}
	
	// Try to send message larger than limit
	largeMessage := make([]byte, 2048) // 2KB > 1KB limit
	for i := range largeMessage {
		largeMessage[i] = byte('A' + (i % 26))
	}
	
	conn.Write(largeMessage)
	
	// Connection should be closed due to size limit
	time.Sleep(100 * time.Millisecond)
	
	// Try to write again, should fail
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Error("Expected connection to be closed after exceeding message size limit")
	}
}

// TestConnectionLimitPerIP verifies per-IP connection limits
func TestConnectionLimitPerIP(t *testing.T) {
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
		
		// Keep connection open
		time.Sleep(1 * time.Second)
	}))
	defer wsServer.Close()
	
	// Create proxy with low connection limit
	proxy, err := New(Config{
		Target:       strings.Replace(wsServer.URL, "http://", "ws://", 1),
		MaxConnPerIP: 2,
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	// Try to create more connections than allowed
	var connections []*http.Response
	successCount := 0
	
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", proxyServer.URL, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("X-Forwarded-For", "192.168.1.100") // Same IP
		
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusSwitchingProtocols {
			successCount++
			connections = append(connections, resp)
		}
	}
	
	// Clean up connections
	for _, resp := range connections {
		resp.Body.Close()
	}
	
	if successCount > 2 {
		t.Errorf("Expected max 2 connections per IP, but got %d", successCount)
	}
}

// TestRateLimiting verifies rate limiting functionality
func TestRateLimiting(t *testing.T) {
	// Create echo server
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer wsServer.Close()
	
	// Create rate limiter
	limiter, err := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: 2,
		Burst:             2,
		Enabled:           true,
	})
	if err != nil {
		t.Fatalf("Failed to create rate limiter: %v", err)
	}
	
	// Create proxy with rate limiter
	proxy, err := New(Config{
		Target:      strings.Replace(wsServer.URL, "http://", "ws://", 1),
		RateLimiter: limiter,
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	// Make rapid requests
	successCount := 0
	rateLimitedCount := 0
	
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", proxyServer.URL, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("X-Forwarded-For", "192.168.1.101")
		
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			if resp.StatusCode == http.StatusSwitchingProtocols {
				successCount++
			} else if resp.StatusCode == http.StatusTooManyRequests {
				rateLimitedCount++
			}
			resp.Body.Close()
		}
	}
	
	if rateLimitedCount == 0 {
		t.Error("Expected some requests to be rate limited, but none were")
	}
	
	if successCount == 0 {
		t.Error("Expected some requests to succeed, but none did")
	}
}

// TestPingPongKeepalive verifies ping/pong mechanism
func TestPingPongKeepalive(t *testing.T) {
	pingReceived := make(chan bool, 1)
	
	// Create server that expects ping frames
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
		
		// Wait for ping frame
		buf := make([]byte, 10)
		n, err := conn.Read(buf)
		if err == nil && n >= 2 {
			// Check for ping frame (0x89)
			if buf[0] == 0x89 {
				pingReceived <- true
				// Send pong response
				conn.Write([]byte{0x8A, 0x00})
			}
		}
		
		// Keep connection open
		time.Sleep(2 * time.Second)
	}))
	defer wsServer.Close()
	
	// Create proxy with short ping interval
	proxy, err := New(Config{
		Target:       strings.Replace(wsServer.URL, "http://", "ws://", 1),
		PingInterval: 500 * time.Millisecond,
		PongTimeout:  200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	// Connect client
	req, _ := http.NewRequest("GET", proxyServer.URL, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer resp.Body.Close()
	
	// Wait for ping to be sent
	select {
	case <-pingReceived:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("Ping frame was not received within timeout")
	}
}

// TestConcurrentConnections tests handling of many concurrent connections
func TestConcurrentConnections(t *testing.T) {
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
		
		// Echo messages
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				conn.Write(buf[:n])
			}
		}
	}))
	defer wsServer.Close()
	
	// Create proxy
	proxy, err := New(Config{
		Target:      strings.Replace(wsServer.URL, "http://", "ws://", 1),
		IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	// Track goroutines before test
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create many concurrent connections
	numConnections := 50
	var wg sync.WaitGroup
	successCount := atomic.Int32{}
	
	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// Create connection
			conn, err := net.Dial("tcp", strings.TrimPrefix(proxyServer.URL, "http://"))
			if err != nil {
				return
			}
			defer conn.Close()
			
			// Send WebSocket upgrade
			upgradeReq := fmt.Sprintf("GET / HTTP/1.1\r\n"+
				"Host: localhost\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"X-Forwarded-For: 192.168.1.%d\r\n"+
				"\r\n", id%250+1)
			conn.Write([]byte(upgradeReq))
			
			// Read response
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err == nil && n > 0 && strings.Contains(string(buf[:n]), "101 Switching Protocols") {
				successCount.Add(1)
				
				// Send some data
				testData := fmt.Sprintf("Test message from client %d", id)
				conn.Write([]byte(testData))
				
				// Read echo
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				conn.Read(buf)
			}
		}(i)
	}
	
	wg.Wait()
	
	if successCount.Load() < int32(float64(numConnections)*0.8) {
		t.Errorf("Too few successful connections: %d/%d", successCount.Load(), numConnections)
	}
	
	// Wait for cleanup
	time.Sleep(2 * time.Second)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	
	// Check for goroutine leaks
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 5 {
		t.Errorf("Potential goroutine leak after concurrent connections: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// TestContextCancellation verifies proper handling of context cancellation
func TestContextCancellation(t *testing.T) {
	// Create a slow server
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
		
		// Slow drip of data
		for i := 0; i < 100; i++ {
			time.Sleep(100 * time.Millisecond)
			conn.Write([]byte{byte(i)})
		}
	}))
	defer wsServer.Close()
	
	// Create proxy
	proxy, err := New(Config{
		Target: strings.Replace(wsServer.URL, "http://", "ws://", 1),
	})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Track goroutines
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create proxy server
	server := &http.Server{
		Handler: proxy,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	
	go server.Serve(listener)
	defer server.Close()
	
	// Connect client
	proxyURL := fmt.Sprintf("http://%s", listener.Addr().String())
	req, _ := http.NewRequest("GET", proxyURL, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
		}
	}()
	
	// Let connection establish
	time.Sleep(500 * time.Millisecond)
	
	// Cancel context
	cancel()
	
	// Wait for cleanup
	time.Sleep(1 * time.Second)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	
	// Check goroutines cleaned up
	finalGoroutines := runtime.NumGoroutine()
	goroutineDiff := finalGoroutines - initialGoroutines
	
	if goroutineDiff > 3 {
		t.Errorf("Goroutines not cleaned up after context cancellation: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, goroutineDiff)
	}
}

// BenchmarkWebSocketProxy benchmarks the WebSocket proxy performance
func BenchmarkWebSocketProxy(b *testing.B) {
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
		
		// Echo messages
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				conn.Write(buf[:n])
			}
		}
	}))
	defer wsServer.Close()
	
	// Create proxy
	proxy, err := New(Config{
		Target:      strings.Replace(wsServer.URL, "http://", "ws://", 1),
		BufferSize:  64 * 1024,
		IdleTimeout: 30 * time.Second,
	})
	if err != nil {
		b.Fatalf("Failed to create proxy: %v", err)
	}
	
	// Create proxy server
	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create connection
			conn, err := net.Dial("tcp", strings.TrimPrefix(proxyServer.URL, "http://"))
			if err != nil {
				b.Fatalf("Failed to connect: %v", err)
			}
			
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
				// Send test data
				testData := []byte("Benchmark test message")
				conn.Write(testData)
				
				// Read echo
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				conn.Read(buf)
			}
			
			conn.Close()
		}
	})
}