package dbproxy

import (
	"net"
	"testing"
	"time"
)

func TestMongoDBProxy(t *testing.T) {
	// Create a test listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Create proxy without TLS
	proxy := NewMongoDBProxy("127.0.0.1:27017", nil)

	// Start proxy in background
	go func() {
		_ = proxy.Serve(listener)
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Test that proxy is listening
	addr := listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()
}

func TestMongoDBProxyWithTLS(t *testing.T) {
	// Create a test listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Create a temporary certificate manager
	certManager := NewCertManager(t.TempDir())
	tlsConfig, err := certManager.GetTLSConfig("localhost")
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	// Create proxy with TLS
	proxy := NewMongoDBProxy("127.0.0.1:27017", tlsConfig)

	// Start proxy in background
	go func() {
		_ = proxy.Serve(listener)
	}()

	// Give the proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Test that proxy is listening
	addr := listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()
}

func TestPrefixConn(t *testing.T) {
	// Create a mock connection
	mockConn := &mockNetConn{
		data: []byte("world"),
	}

	// Create prefixConn with prefix "hello"
	prefixConn := &prefixConn{
		Conn:   mockConn,
		prefix: []byte("hello"),
		read:   false,
	}

	// Test reading with buffer larger than prefix
	buf := make([]byte, 10)
	n, err := prefixConn.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected 5 bytes, got %d", n)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(buf[:n]))
	}

	// Test second read gets data from underlying connection
	n, err = prefixConn.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected 5 bytes, got %d", n)
	}
	if string(buf[:n]) != "world" {
		t.Errorf("Expected 'world', got '%s'", string(buf[:n]))
	}
}

func TestPrefixConnSmallBuffer(t *testing.T) {
	// Create a mock connection
	mockConn := &mockNetConn{
		data: []byte("!"),
	}

	// Create prefixConn with longer prefix
	prefixConn := &prefixConn{
		Conn:   mockConn,
		prefix: []byte("hello"),
		read:   false,
	}

	// Test reading with buffer smaller than prefix
	buf := make([]byte, 3)
	n, err := prefixConn.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 3 {
		t.Errorf("Expected 3 bytes, got %d", n)
	}
	if string(buf) != "hel" {
		t.Errorf("Expected 'hel', got '%s'", string(buf))
	}

	// Second read should get remaining prefix
	n, err = prefixConn.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 2 {
		t.Errorf("Expected 2 bytes, got %d", n)
	}
	if string(buf[:n]) != "lo" {
		t.Errorf("Expected 'lo', got '%s'", string(buf[:n]))
	}

	// Third read should get data from underlying connection
	n, err = prefixConn.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("Expected 1 byte, got %d", n)
	}
	if string(buf[:n]) != "!" {
		t.Errorf("Expected '!', got '%s'", string(buf[:n]))
	}
}

// mockNetConn is a mock implementation of net.Conn for testing
type mockNetConn struct {
	data []byte
	pos  int
}

func (m *mockNetConn) Read(b []byte) (int, error) {
	if m.pos >= len(m.data) {
		return 0, nil
	}
	n := copy(b, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockNetConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *mockNetConn) Close() error {
	return nil
}

func (m *mockNetConn) LocalAddr() net.Addr {
	return nil
}

func (m *mockNetConn) RemoteAddr() net.Addr {
	return nil
}

func (m *mockNetConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockNetConn) SetWriteDeadline(t time.Time) error {
	return nil
}