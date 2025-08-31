package dbproxy

import (
	"net"
	"testing"
	"time"
)

func TestRedisProxy(t *testing.T) {
	// Create a test listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Create proxy without TLS
	proxy := NewRedisProxy("127.0.0.1:6379", nil)

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

func TestRedisProxyWithTLS(t *testing.T) {
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
	proxy := NewRedisProxy("127.0.0.1:6379", tlsConfig)

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

func TestRedisIsStartTLSCommand(t *testing.T) {
	proxy := &RedisProxy{}

	testCases := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "RESP array STARTTLS command",
			data:     []byte("*1\r\n$8\r\nSTARTTLS\r\n"),
			expected: true,
		},
		{
			name:     "Simple STARTTLS command",
			data:     []byte("STARTTLS\r\n"),
			expected: true,
		},
		{
			name:     "Lowercase starttls",
			data:     []byte("starttls\r\n"),
			expected: true,
		},
		{
			name:     "Not STARTTLS command",
			data:     []byte("GET key\r\n"),
			expected: false,
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := proxy.isStartTLSCommand(tc.data)
			if result != tc.expected {
				t.Errorf("Expected %v for %s, got %v", tc.expected, tc.name, result)
			}
		})
	}
}