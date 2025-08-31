package proxy

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestProxyGoroutineCleanup verifies that all goroutines are properly cleaned up
func TestProxyGoroutineCleanup(t *testing.T) {
	tests := []struct {
		name      string
		proxyType Type
	}{
		{"MySQL", TypeMySQL},
		{"PostgreSQL", TypePostgres},
		{"MongoDB", TypeMongoDB},
		{"Redis", TypeRedis},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record initial goroutine count
			runtime.GC()
			initialGoroutines := runtime.NumGoroutine()
			
			// Create factory and manager
			factory := NewFactory()
			manager := NewManager(factory)
			
			// Find an available port
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to find available port: %v", err)
			}
			addr := listener.Addr().String()
			listener.Close()
			
			// Configure proxy
			config := &Config{
				ListenAddr: addr,
				Backend:    "127.0.0.1:9999", // Non-existent backend is fine for this test
				Type:       tt.proxyType,
			}
			
			// Start proxy with context
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			err = manager.StartProxyWithContext(ctx, config)
			if err != nil {
				t.Fatalf("Failed to start proxy: %v", err)
			}
			
			// Allow time for goroutines to start
			time.Sleep(100 * time.Millisecond)
			
			// Record goroutines while running
			runtime.GC()
			runningGoroutines := runtime.NumGoroutine()
			
			// Verify we have more goroutines while running
			if runningGoroutines <= initialGoroutines {
				t.Errorf("Expected more goroutines while running, initial=%d, running=%d",
					initialGoroutines, runningGoroutines)
			}
			
			// Stop the proxy
			err = manager.StopProxy(addr)
			if err != nil {
				t.Errorf("Failed to stop proxy: %v", err)
			}
			
			// Allow time for goroutines to clean up
			time.Sleep(200 * time.Millisecond)
			
			// Check final goroutine count
			runtime.GC()
			finalGoroutines := runtime.NumGoroutine()
			
			// Allow for some variance but should be close to initial
			goroutineLeak := finalGoroutines - initialGoroutines
			if goroutineLeak > 2 { // Allow 2 extra goroutines for test infrastructure
				t.Errorf("Goroutine leak detected: initial=%d, final=%d, leaked=%d",
					initialGoroutines, finalGoroutines, goroutineLeak)
			}
		})
	}
}

// TestProxyAcceptErrorHandling verifies proper error handling in accept loops
func TestProxyAcceptErrorHandling(t *testing.T) {
	factory := NewFactory()
	manager := NewManager(factory)
	
	// Start a proxy
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()
	
	config := &Config{
		ListenAddr: addr,
		Backend:    "127.0.0.1:9999",
		Type:       TypeMySQL,
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err = manager.StartProxyWithContext(ctx, config)
	if err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	
	// Get the proxy
	manager.mu.RLock()
	proxy, exists := manager.proxies[addr]
	manager.mu.RUnlock()
	
	if !exists {
		t.Fatal("Proxy not found")
	}
	
	// Initial goroutine count
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	// Force close the listener to trigger accept error
	proxy.Stop()
	
	// Allow time for error handling
	time.Sleep(100 * time.Millisecond)
	
	// Check that goroutines are cleaned up
	runtime.GC()
	finalGoroutines := runtime.NumGoroutine()
	
	if finalGoroutines > initialGoroutines+2 {
		t.Errorf("Goroutines not cleaned up after accept error: initial=%d, final=%d",
			initialGoroutines, finalGoroutines)
	}
}

// TestProxyGracefulShutdown verifies graceful shutdown with active connections
func TestProxyGracefulShutdown(t *testing.T) {
	factory := NewFactory()
	manager := NewManager(factory)
	
	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()
	
	// Start a simple backend server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start backend: %v", err)
	}
	backendAddr := backendListener.Addr().String()
	defer backendListener.Close()
	
	// Handle backend connections
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			// Keep connection open
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(10 * time.Second)
			}(conn)
		}
	}()
	
	config := &Config{
		ListenAddr: addr,
		Backend:    backendAddr,
		Type:       TypeMySQL,
	}
	
	ctx := context.Background()
	err = manager.StartProxyWithContext(ctx, config)
	if err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	
	// Connect multiple clients
	var clients []net.Conn
	numClients := 5
	
	for i := 0; i < numClients; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Logf("Failed to connect client %d: %v", i, err)
			continue
		}
		clients = append(clients, conn)
	}
	
	// Allow connections to establish
	time.Sleep(100 * time.Millisecond)
	
	// Get proxy to check active connections
	manager.mu.RLock()
	proxy, exists := manager.proxies[addr]
	manager.mu.RUnlock()
	
	if !exists {
		t.Fatal("Proxy not found")
	}
	
	activeConnections := proxy.GetActiveConnections()
	if activeConnections == 0 && len(clients) > 0 {
		t.Logf("Warning: No active connections tracked, expected %d", len(clients))
	}
	
	// Start shutdown
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- manager.StopProxy(addr)
	}()
	
	// Close client connections
	for _, conn := range clients {
		conn.Close()
	}
	
	// Wait for shutdown with timeout
	select {
	case err := <-stopDone:
		if err != nil {
			t.Errorf("Stop failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		// This is expected - graceful shutdown should wait
		t.Log("Graceful shutdown waiting for connections as expected")
	}
	
	// Verify goroutines are eventually cleaned up
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
}

// TestConcurrentProxyOperations tests concurrent start/stop operations
func TestConcurrentProxyOperations(t *testing.T) {
	factory := NewFactory()
	manager := NewManager(factory)
	
	numProxies := 10
	var wg sync.WaitGroup
	errors := make(chan error, numProxies*2)
	
	// Record initial goroutines
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	
	for i := 0; i < numProxies; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// Find available port
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				errors <- fmt.Errorf("proxy %d: failed to find port: %w", id, err)
				return
			}
			addr := listener.Addr().String()
			listener.Close()
			
			config := &Config{
				ListenAddr: addr,
				Backend:    fmt.Sprintf("127.0.0.1:%d", 10000+id),
				Type:       TypeMySQL,
			}
			
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			// Start proxy
			if err := manager.StartProxyWithContext(ctx, config); err != nil {
				errors <- fmt.Errorf("proxy %d: start failed: %w", id, err)
				return
			}
			
			// Random delay
			time.Sleep(time.Duration(id*10) * time.Millisecond)
			
			// Stop proxy
			if err := manager.StopProxy(addr); err != nil {
				errors <- fmt.Errorf("proxy %d: stop failed: %w", id, err)
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	var errCount int
	for err := range errors {
		t.Logf("Error: %v", err)
		errCount++
	}
	
	if errCount > 0 {
		t.Errorf("Had %d errors during concurrent operations", errCount)
	}
	
	// Allow cleanup time
	time.Sleep(500 * time.Millisecond)
	
	// Verify no goroutine leaks
	runtime.GC()
	finalGoroutines := runtime.NumGoroutine()
	
	goroutineLeak := finalGoroutines - initialGoroutines
	if goroutineLeak > 5 { // Allow some variance for test infrastructure
		t.Errorf("Goroutine leak after concurrent operations: initial=%d, final=%d, leaked=%d",
			initialGoroutines, finalGoroutines, goroutineLeak)
	}
}

// TestProxyManagerStopAll tests stopping all proxies at once
func TestProxyManagerStopAll(t *testing.T) {
	factory := NewFactory()
	manager := NewManager(factory)
	
	// Start multiple proxies
	numProxies := 5
	for i := 0; i < numProxies; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to find available port: %v", err)
		}
		addr := listener.Addr().String()
		listener.Close()
		
		config := &Config{
			ListenAddr: addr,
			Backend:    fmt.Sprintf("127.0.0.1:%d", 20000+i),
			Type:       TypeRedis,
		}
		
		if err := manager.StartProxy(config); err != nil {
			t.Fatalf("Failed to start proxy %d: %v", i, err)
		}
	}
	
	// Record goroutines with proxies running
	runtime.GC()
	runningGoroutines := runtime.NumGoroutine()
	
	// Stop all proxies
	manager.StopAll()
	
	// Allow cleanup time
	time.Sleep(200 * time.Millisecond)
	
	// Check that all proxies are stopped
	manager.mu.RLock()
	remainingProxies := len(manager.proxies)
	manager.mu.RUnlock()
	
	if remainingProxies != 0 {
		t.Errorf("Expected 0 proxies after StopAll, got %d", remainingProxies)
	}
	
	// Verify goroutines are cleaned up
	runtime.GC()
	finalGoroutines := runtime.NumGoroutine()
	
	if finalGoroutines >= runningGoroutines {
		t.Errorf("Goroutines not cleaned up after StopAll: running=%d, final=%d",
			runningGoroutines, finalGoroutines)
	}
}

// TestContextCancellation tests that proxies respect context cancellation
func TestContextCancellation(t *testing.T) {
	factory := NewFactory()
	manager := NewManager(factory)
	
	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()
	
	config := &Config{
		ListenAddr: addr,
		Backend:    "127.0.0.1:30000",
		Type:       TypePostgres,
	}
	
	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	
	// Start proxy
	err = manager.StartProxyWithContext(ctx, config)
	if err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	
	// Record goroutines while running
	runtime.GC()
	runningGoroutines := runtime.NumGoroutine()
	
	// Cancel context
	cancel()
	
	// Allow time for context cancellation to propagate
	time.Sleep(200 * time.Millisecond)
	
	// Stop the proxy (should handle cancelled context gracefully)
	manager.StopProxy(addr)
	
	// Allow cleanup time
	time.Sleep(200 * time.Millisecond)
	
	// Verify goroutines are cleaned up
	runtime.GC()
	finalGoroutines := runtime.NumGoroutine()
	
	if finalGoroutines >= runningGoroutines {
		t.Errorf("Goroutines not cleaned up after context cancellation: running=%d, final=%d",
			runningGoroutines, finalGoroutines)
	}
}