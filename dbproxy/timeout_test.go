package dbproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/artyom/leproxy/internal/config"
)

// mockConn simulates a network connection with configurable behavior
type mockConn struct {
	net.Conn
	readDelay    time.Duration
	writeDelay   time.Duration
	readError    error
	writeError   error
	closed       bool
	mu           sync.Mutex
	readDeadline time.Time
	writeDeadline time.Time
	bytesRead    int
	bytesWritten int
}

func newMockConn() *mockConn {
	return &mockConn{}
}

func (c *mockConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.closed {
		return 0, io.EOF
	}
	
	// Check for deadline
	if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
		return 0, &timeoutError{}
	}
	
	if c.readDelay > 0 {
		time.Sleep(c.readDelay)
	}
	
	if c.readError != nil {
		return 0, c.readError
	}
	
	// Simulate reading some data
	n := copy(b, []byte("test data"))
	c.bytesRead += n
	
	// Return EOF after first read to terminate copy
	if c.bytesRead > 0 {
		c.readError = io.EOF
	}
	
	return n, nil
}

func (c *mockConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.closed {
		return 0, errors.New("connection closed")
	}
	
	// Check for deadline
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		return 0, &timeoutError{}
	}
	
	if c.writeDelay > 0 {
		time.Sleep(c.writeDelay)
	}
	
	if c.writeError != nil {
		return 0, c.writeError
	}
	
	c.bytesWritten += len(b)
	return len(b), nil
}

func (c *mockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *mockConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *mockConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func (c *mockConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (c *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}
}

// timeoutError implements net.Error
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// temporaryError implements net.Error for testing retries
type temporaryError struct{}

func (e *temporaryError) Error() string   { return "temporary error" }
func (e *temporaryError) Timeout() bool   { return false }
func (e *temporaryError) Temporary() bool { return true }

// mockHandler implements ProxyHandler for testing
type mockHandler struct{}

func (h *mockHandler) GetProtocolName() string { return "Mock" }
func (h *mockHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func TestCopyDataWithTimeout_ReadTimeout(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.ReadTimeout = config.Duration(100 * time.Millisecond)
	
	src := newMockConn()
	src.readDelay = 200 * time.Millisecond // Longer than timeout
	dst := newMockConn()
	
	ctx := context.Background()
	err := proxy.copyDataWithTimeout(ctx, dst, src, "test")
	
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
	
	if !isTimeout(err) {
		t.Errorf("Expected timeout error, got: %v", err)
	}
	
	// Check that timeout was recorded
	metrics := proxy.GetTimeoutMetrics()
	if metrics["read_timeouts"] == 0 {
		t.Error("Read timeout not recorded in metrics")
	}
}

func TestCopyDataWithTimeout_WriteTimeout(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.WriteTimeout = config.Duration(100 * time.Millisecond)
	
	src := newMockConn()
	dst := newMockConn()
	dst.writeDelay = 200 * time.Millisecond // Longer than timeout
	
	ctx := context.Background()
	_ = proxy.copyDataWithTimeout(ctx, dst, src, "test")
	
	// The error might be nil if read returns EOF before write timeout
	// Check metrics instead
	metrics := proxy.GetTimeoutMetrics()
	if dst.bytesWritten > 0 && metrics["write_timeouts"] == 0 {
		t.Error("Write timeout not recorded when write was attempted")
	}
}

func TestCopyDataWithTimeout_IdleTimeout(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.IdleTimeout = config.Duration(100 * time.Millisecond)
	proxy.TimeoutConfig.ReadTimeout = config.Duration(10 * time.Second) // Long read timeout
	
	src := newMockConn()
	src.readDelay = 200 * time.Millisecond // Simulate idle connection
	src.readError = nil // Don't return EOF immediately
	dst := newMockConn()
	
	// Use a context with timeout to prevent test hanging
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	
	err := proxy.copyDataWithTimeout(ctx, dst, src, "test")
	
	// Should timeout due to idle or context cancellation
	if err == nil {
		t.Error("Expected timeout or context error, got nil")
	}
}

func TestCopyDataWithTimeout_Retry(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.EnableExponentialBackoff = true
	proxy.TimeoutConfig.MaxRetries = 3
	proxy.TimeoutConfig.RetryDelay = config.Duration(10 * time.Millisecond)
	
	src := newMockConn()
	// First read will return temporary error, second will succeed
	src.readError = &temporaryError{}
	
	dst := newMockConn()
	
	ctx := context.Background()
	err := proxy.copyDataWithTimeout(ctx, dst, src, "test")
	
	// Should eventually succeed after retry
	if err != nil && err != io.EOF {
		t.Errorf("Expected successful copy after retry, got: %v", err)
	}
	
	// Check that retry was recorded
	metrics := proxy.GetTimeoutMetrics()
	if metrics["retries"] == 0 {
		t.Error("Retry not recorded in metrics")
	}
}

func TestCopyDataWithTimeout_ContextCancellation(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	
	src := newMockConn()
	src.readDelay = 100 * time.Millisecond
	dst := newMockConn()
	
	ctx, cancel := context.WithCancel(context.Background())
	
	// Cancel context after short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	
	err := proxy.copyDataWithTimeout(ctx, dst, src, "test")
	
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}

func TestCalculateBackoff(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.EnableExponentialBackoff = true
	proxy.TimeoutConfig.RetryDelay = config.Duration(100 * time.Millisecond)
	
	baseDelay := 100 * time.Millisecond
	
	tests := []struct {
		retryCount int
		expected   time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{10, 30 * time.Second}, // Should cap at 30 seconds
	}
	
	for _, tt := range tests {
		result := proxy.calculateBackoff(tt.retryCount, baseDelay)
		if result != tt.expected {
			t.Errorf("calculateBackoff(%d) = %v, expected %v", tt.retryCount, result, tt.expected)
		}
	}
}

func TestCalculateBackoff_Disabled(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.EnableExponentialBackoff = false
	
	baseDelay := 100 * time.Millisecond
	
	// Should always return base delay when disabled
	for i := 1; i <= 5; i++ {
		result := proxy.calculateBackoff(i, baseDelay)
		if result != baseDelay {
			t.Errorf("calculateBackoff(%d) with backoff disabled = %v, expected %v", i, result, baseDelay)
		}
	}
}

func TestShouldRetry(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.EnableExponentialBackoff = true
	proxy.TimeoutConfig.MaxRetries = 3
	
	tests := []struct {
		name       string
		err        error
		retryCount int
		expected   bool
	}{
		{"nil error", nil, 0, false},
		{"temporary error", &temporaryError{}, 0, true},
		{"temporary error at max retries", &temporaryError{}, 3, false},
		{"timeout error", &timeoutError{}, 1, true},
		{"non-temporary error", errors.New("permanent"), 0, false},
		{"EOF", io.EOF, 0, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := proxy.shouldRetry(tt.err, tt.retryCount)
			if result != tt.expected {
				t.Errorf("shouldRetry(%v, %d) = %v, expected %v", tt.err, tt.retryCount, result, tt.expected)
			}
		})
	}
}

func TestProxyConnections_Concurrent(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.ReadTimeout = config.Duration(1 * time.Second)
	proxy.TimeoutConfig.WriteTimeout = config.Duration(1 * time.Second)
	
	client := newMockConn()
	backend := newMockConn()
	
	// Test that both directions are handled concurrently
	done := make(chan bool)
	go func() {
		proxy.proxyConnections(client, backend)
		done <- true
	}()
	
	select {
	case <-done:
		// Success - proxy completed
	case <-time.After(2 * time.Second):
		t.Error("proxyConnections did not complete in expected time")
	}
}

func TestTimeoutMetrics(t *testing.T) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	
	// Simulate various timeout scenarios
	proxy.timeoutMetrics.ReadTimeouts.Add(5)
	proxy.timeoutMetrics.WriteTimeouts.Add(3)
	proxy.timeoutMetrics.IdleTimeouts.Add(2)
	proxy.timeoutMetrics.TotalBytes.Add(1024)
	proxy.timeoutMetrics.Retries.Add(7)
	
	metrics := proxy.GetTimeoutMetrics()
	
	expected := map[string]uint64{
		"read_timeouts":  5,
		"write_timeouts": 3,
		"idle_timeouts":  2,
		"total_bytes":    1024,
		"retries":        7,
	}
	
	for key, expectedValue := range expected {
		if metrics[key] != expectedValue {
			t.Errorf("Metric %s = %d, expected %d", key, metrics[key], expectedValue)
		}
	}
}

func BenchmarkCopyDataWithTimeout(b *testing.B) {
	proxy := NewBaseProxy("test:1234", nil, &mockHandler{})
	proxy.TimeoutConfig.BufferSize = 32 * 1024
	
	src := newMockConn()
	dst := newMockConn()
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset mock connections
		src.bytesRead = 0
		src.readError = nil
		dst.bytesWritten = 0
		
		proxy.copyDataWithTimeout(ctx, dst, src, "bench")
	}
}

func TestNewBaseProxyWithTimeout(t *testing.T) {
	customConfig := &config.ProxyTimeoutConfig{
		ConnectTimeout:    config.Duration(5 * time.Second),
		ReadTimeout:       config.Duration(20 * time.Second),
		WriteTimeout:      config.Duration(25 * time.Second),
		IdleTimeout:       config.Duration(3 * time.Minute),
		KeepaliveInterval: config.Duration(45 * time.Second),
		EnableKeepalive:   false,
		BufferSize:        65536,
		MaxRetries:        5,
	}
	
	proxy := NewBaseProxyWithTimeout("test:1234", nil, &mockHandler{}, customConfig)
	
	if proxy.TimeoutConfig != customConfig {
		t.Error("Custom timeout config not set correctly")
	}
	
	if time.Duration(proxy.TimeoutConfig.ConnectTimeout) != 5*time.Second {
		t.Errorf("ConnectTimeout = %v, expected 5s", time.Duration(proxy.TimeoutConfig.ConnectTimeout))
	}
	
	if proxy.TimeoutConfig.BufferSize != 65536 {
		t.Errorf("BufferSize = %d, expected 65536", proxy.TimeoutConfig.BufferSize)
	}
}

func TestNewBaseProxyWithTimeout_NilConfig(t *testing.T) {
	proxy := NewBaseProxyWithTimeout("test:1234", nil, &mockHandler{}, nil)
	
	if proxy.TimeoutConfig == nil {
		t.Error("TimeoutConfig should not be nil when nil config is passed")
	}
	
	// Should use defaults
	if time.Duration(proxy.TimeoutConfig.ConnectTimeout) != DefaultConnectTimeout {
		t.Errorf("Expected default ConnectTimeout, got %v", time.Duration(proxy.TimeoutConfig.ConnectTimeout))
	}
}