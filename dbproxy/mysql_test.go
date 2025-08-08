package dbproxy

import (
	"net"
	"testing"
	"time"
)

func TestMySQLProxy(t *testing.T) {
	// Create a test listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Create proxy without TLS
	proxy := NewMySQLProxy("127.0.0.1:3306", nil)

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

func TestMySQLProxyWithTLS(t *testing.T) {
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
	proxy := NewMySQLProxy("127.0.0.1:3306", tlsConfig)

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

func TestMySQLSupportsSSL(t *testing.T) {
	proxy := &MySQLProxy{}

	// Test case: valid MySQL handshake with SSL support
	handshake := make([]byte, 100)
	// Simplified handshake packet structure
	handshake[5] = 0 // null terminator for version string
	// Set capability flags at expected offset
	capabilityOffset := 6 + 4 + 8 + 1
	handshake[capabilityOffset] = 0x00
	handshake[capabilityOffset+1] = 0x08 // SSL flag (0x0800)

	if !proxy.supportsSSL(handshake) {
		t.Error("Expected SSL support to be detected")
	}

	// Test case: handshake without SSL support
	handshake[capabilityOffset+1] = 0x00 // No SSL flag
	if proxy.supportsSSL(handshake) {
		t.Error("Expected no SSL support")
	}
}

func TestMySQLIsSSLRequest(t *testing.T) {
	proxy := &MySQLProxy{}

	// Test case: valid SSL request packet
	packet := make([]byte, 36)
	packet[4] = 0x00
	packet[5] = 0x08 // SSL flag (0x0800)
	packet[6] = 0x00
	packet[7] = 0x00

	if !proxy.isSSLRequest(packet) {
		t.Error("Expected SSL request to be detected")
	}

	// Test case: packet without SSL request
	packet[5] = 0x00 // No SSL flag
	if proxy.isSSLRequest(packet) {
		t.Error("Expected no SSL request")
	}
}