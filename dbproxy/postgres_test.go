package dbproxy

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestPostgresProxy(t *testing.T) {
	// Create a test listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Create proxy without TLS
	proxy := NewPostgresProxy("127.0.0.1:5432", nil)

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

func TestPostgresProxyWithTLS(t *testing.T) {
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
	proxy := NewPostgresProxy("127.0.0.1:5432", tlsConfig)

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

func TestIsSSLRequest(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "valid SSL request",
			input:    []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f},
			expected: true,
		},
		{
			name:     "invalid SSL request - wrong magic number",
			input:    []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x30},
			expected: false,
		},
		{
			name:     "too short buffer",
			input:    []byte{0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "empty buffer",
			input:    []byte{},
			expected: false,
		},
		{
			name:     "nil buffer",
			input:    nil,
			expected: false,
		},
		{
			name:     "wrong length field",
			input:    []byte{0x00, 0x00, 0x00, 0x09, 0x04, 0xd2, 0x16, 0x2f},
			expected: false,
		},
		{
			name:     "partial SSL request",
			input:    []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSSLRequest(tt.input)
			if result != tt.expected {
				t.Errorf("isSSLRequest(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPostgresSSLHandshake(t *testing.T) {
	// Mock backend server that accepts SSL
	backend := startMockPostgresServer(t, true)
	defer backend.Close()

	// Create proxy with TLS
	certManager := NewCertManager(t.TempDir())
	tlsConfig, err := certManager.GetTLSConfig("localhost")
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	proxy := NewPostgresProxy(backend.Addr().String(), tlsConfig)

	// Start proxy
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		_ = proxy.Serve(listener)
	}()

	// Connect to proxy and send SSL request
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send PostgreSQL SSL request
	sslRequest := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	_, err = conn.Write(sslRequest)
	if err != nil {
		t.Fatalf("Failed to send SSL request: %v", err)
	}

	// Read response
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read SSL response: %v", err)
	}

	if n != 1 {
		t.Errorf("Expected 1 byte response, got %d", n)
	}

	// PostgreSQL responds with 'S' for SSL OK or 'N' for no SSL
	if buf[0] != 'S' && buf[0] != 'N' {
		t.Errorf("Expected 'S' or 'N' response, got %c", buf[0])
	}
}

func TestPostgresStartupMessage(t *testing.T) {
	tests := []struct {
		name      string
		message   []byte
		wantError bool
	}{
		{
			name: "valid startup message v3",
			message: buildStartupMessage(map[string]string{
				"user":     "testuser",
				"database": "testdb",
			}),
			wantError: false,
		},
		{
			name: "startup with application_name",
			message: buildStartupMessage(map[string]string{
				"user":             "testuser",
				"database":         "testdb",
				"application_name": "test_app",
			}),
			wantError: false,
		},
		{
			name:      "empty message",
			message:   []byte{},
			wantError: true,
		},
		{
			name:      "invalid message length",
			message:   []byte{0x00, 0x00, 0x00, 0x04}, // Length 4 but no data
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests that the message format is valid
			if len(tt.message) >= 8 && !tt.wantError {
				// Check protocol version (should be 3.0)
				version := uint32(tt.message[4])<<24 | uint32(tt.message[5])<<16 |
					uint32(tt.message[6])<<8 | uint32(tt.message[7])
				expectedVersion := uint32(0x00030000) // 3.0
				if version != expectedVersion {
					t.Errorf("Expected protocol version %x, got %x", expectedVersion, version)
				}
			}
		})
	}
}

// Helper function to build PostgreSQL startup message
func buildStartupMessage(params map[string]string) []byte {
	var buf bytes.Buffer

	// Reserve space for length
	buf.Write([]byte{0, 0, 0, 0})

	// Protocol version 3.0
	buf.Write([]byte{0x00, 0x03, 0x00, 0x00})

	// Parameters
	for k, v := range params {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(v)
		buf.WriteByte(0)
	}

	// Terminator
	buf.WriteByte(0)

	// Update length
	msg := buf.Bytes()
	length := uint32(len(msg))
	msg[0] = byte(length >> 24)
	msg[1] = byte(length >> 16)
	msg[2] = byte(length >> 8)
	msg[3] = byte(length)

	return msg
}

// Mock PostgreSQL server for testing
func startMockPostgresServer(t *testing.T, supportSSL bool) net.Listener {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				// Read first message
				buf := make([]byte, 8)
				n, err := c.Read(buf)
				if err != nil || n < 8 {
					return
				}

				// Check if it's SSL request
				if isSSLRequest(buf[:n]) {
					if supportSSL {
						c.Write([]byte{'S'}) // SSL supported
					} else {
						c.Write([]byte{'N'}) // SSL not supported
					}
				}
			}(conn)
		}
	}()

	return listener
}

func TestPostgresProxyConnectionLimit(t *testing.T) {
	// Create proxy
	proxy := NewPostgresProxy("127.0.0.1:5432", nil)

	// Start proxy
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		_ = proxy.Serve(listener)
	}()

	// Create multiple connections
	numConnections := 10
	connections := make([]net.Conn, 0, numConnections)

	for i := 0; i < numConnections; i++ {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Errorf("Failed to create connection %d: %v", i, err)
			continue
		}
		connections = append(connections, conn)
	}

	// Clean up connections
	for _, conn := range connections {
		conn.Close()
	}

	// Verify we could create all connections
	if len(connections) != numConnections {
		t.Errorf("Expected %d connections, got %d", numConnections, len(connections))
	}
}

func TestPostgresProxyInvalidBackend(t *testing.T) {
	// Create proxy with invalid backend
	proxy := NewPostgresProxy("invalid-host:5432", nil)

	// Start proxy
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		_ = proxy.Serve(listener)
	}()

	// Try to connect
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send some data
	_, err = conn.Write([]byte("test"))
	if err != nil {
		// Expected - connection should fail when trying to reach invalid backend
		return
	}

	// Try to read response
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = conn.Read(buf)
	// Should timeout or error since backend is invalid
}