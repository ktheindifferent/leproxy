package dbproxy

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// TestSimpleGoroutineLeakFix tests if basic proxy properly cleans up goroutines
func TestSimpleGoroutineLeakFix(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)
	
	// Create a simple echo backend
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create backend listener: %v", err)
	}
	
	// Backend that immediately closes connection
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			// Close immediately to trigger errors
			conn.Close()
		}
	}()
	
	// Create proxy
	handler := &mockHandler{}
	proxy := NewBaseProxy(backendListener.Addr().String(), nil, handler)
	
	// Create a single client connection
	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create client listener: %v", err)
	}
	
	// Start proxy in background
	go proxy.Serve(clientListener)
	
	// Create a single connection
	conn, err := net.Dial("tcp", clientListener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	
	// Write some data (will fail due to backend closing)
	conn.Write([]byte("test"))
	
	// Wait a bit for error to propagate
	time.Sleep(100 * time.Millisecond)
	
	// Close connection
	conn.Close()
	
	// Close listeners
	clientListener.Close()
	backendListener.Close()
	
	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	
	// Check goroutine count
	finalGoroutines := runtime.NumGoroutine()
	t.Logf("Final goroutines: %d", finalGoroutines)
	
	diff := finalGoroutines - initialGoroutines
	if diff > 2 {
		t.Errorf("Goroutine leak detected: initial=%d, final=%d, diff=%d",
			initialGoroutines, finalGoroutines, diff)
		
		// Print stack traces
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, true)
		t.Logf("Stack traces:\n%s", buf[:stackLen])
	}
}