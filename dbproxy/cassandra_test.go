package dbproxy

import (
	"bytes"
	"crypto/tls"
	"testing"
)

func TestNewCassandraProxy(t *testing.T) {
	tests := []struct {
		name      string
		backend   string
		tlsConfig *tls.Config
	}{
		{
			name:      "proxy without TLS",
			backend:   "cassandra.example.com:9042",
			tlsConfig: nil,
		},
		{
			name:      "proxy with TLS",
			backend:   "secure-cassandra.example.com:9042",
			tlsConfig: &tls.Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := NewCassandraProxy(tt.backend, tt.tlsConfig)
			if proxy == nil {
				t.Error("Expected non-nil proxy")
			}
			if proxy.backend != tt.backend {
				t.Errorf("Expected backend %s, got %s", tt.backend, proxy.backend)
			}
		})
	}
}

func TestIsCQLStartupMessage(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid CQL v3 startup",
			data:     []byte{0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "valid CQL v4 startup",
			data:     []byte{0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "valid CQL v5 startup",
			data:     []byte{0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "invalid version",
			data:     []byte{0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "invalid opcode",
			data:     []byte{0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x03, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "response frame (bit 7 set)",
			data:     []byte{0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCQLStartupMessage(tt.data)
			if result != tt.expected {
				t.Errorf("isCQLStartupMessage(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestIsCassandraProtocol(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid v3 request",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "valid v4 request",
			data:     []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "valid v5 request",
			data:     []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "valid response (0x80 + version)",
			data:     []byte{0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "invalid version 0",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "invalid version 6",
			data:     []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x03, 0x00},
			expected: false,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCassandraProtocol(tt.data)
			if result != tt.expected {
				t.Errorf("isCassandraProtocol(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestExtractCassandraVersion(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint8
	}{
		{
			name:     "version 3",
			data:     []byte{0x03, 0x00, 0x00, 0x00},
			expected: 0x03,
		},
		{
			name:     "version 4",
			data:     []byte{0x04, 0x00, 0x00, 0x00},
			expected: 0x04,
		},
		{
			name:     "version 5",
			data:     []byte{0x05, 0x00, 0x00, 0x00},
			expected: 0x05,
		},
		{
			name:     "response version (0x80 masked)",
			data:     []byte{0x83, 0x00, 0x00, 0x00},
			expected: 0x03,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCassandraVersion(tt.data)
			if result != tt.expected {
				t.Errorf("extractCassandraVersion(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestGetCassandraOpcode(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint8
	}{
		{
			name:     "STARTUP opcode",
			data:     []byte{0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: 0x01,
		},
		{
			name:     "OPTIONS opcode",
			data:     []byte{0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: 0x05,
		},
		{
			name:     "QUERY opcode",
			data:     []byte{0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: 0x07,
		},
		{
			name:     "PREPARE opcode",
			data:     []byte{0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: 0x09,
		},
		{
			name:     "EXECUTE opcode",
			data:     []byte{0x03, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: 0x0A,
		},
		{
			name:     "BATCH opcode",
			data:     []byte{0x03, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: 0x0D,
		},
		{
			name:     "too short",
			data:     []byte{0x03, 0x00},
			expected: 0,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCassandraOpcode(tt.data)
			if result != tt.expected {
				t.Errorf("getCassandraOpcode(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestIsCassandraRequest(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid request",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "response frame",
			data:     []byte{0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "version 4 request",
			data:     []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "too short",
			data:     []byte{0x03},
			expected: false,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCassandraRequest(tt.data)
			if result != tt.expected {
				t.Errorf("isCassandraRequest(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestIsCassandraResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid response v3",
			data:     []byte{0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "valid response v4",
			data:     []byte{0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "request frame",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "invalid version in response",
			data:     []byte{0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x83},
			expected: false,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCassandraResponse(tt.data)
			if result != tt.expected {
				t.Errorf("isCassandraResponse(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestIsCassandraStartup(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid STARTUP",
			data:     []byte{0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "OPTIONS not STARTUP",
			data:     []byte{0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "QUERY not STARTUP",
			data:     []byte{0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x03, 0x00},
			expected: false,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCassandraStartup(tt.data)
			if result != tt.expected {
				t.Errorf("isCassandraStartup(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestIsCassandraOptions(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid OPTIONS",
			data:     []byte{0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "STARTUP not OPTIONS",
			data:     []byte{0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "QUERY not OPTIONS",
			data:     []byte{0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x03, 0x00},
			expected: false,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCassandraOptions(tt.data)
			if result != tt.expected {
				t.Errorf("isCassandraOptions(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestIsCassandraSupported(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid SUPPORTED response",
			data:     []byte{0x83, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "READY not SUPPORTED",
			data:     []byte{0x83, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "request frame not response",
			data:     []byte{0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x83, 0x00},
			expected: false,
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCassandraSupported(tt.data)
			if result != tt.expected {
				t.Errorf("isCassandraSupported(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestHasCassandraSSLFlag(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		expected bool
	}{
		{
			name: "body with SSL flag",
			body: buildCassandraStartupBody(map[string]string{
				"CQL_VERSION": "3.4.4",
				"SSL":         "true",
			}),
			expected: true,
		},
		{
			name: "body without SSL flag",
			body: buildCassandraStartupBody(map[string]string{
				"CQL_VERSION": "3.4.4",
			}),
			expected: false,
		},
		{
			name: "body with SSL false",
			body: buildCassandraStartupBody(map[string]string{
				"CQL_VERSION": "3.4.4",
				"SSL":         "false",
			}),
			expected: false,
		},
		{
			name:     "empty body",
			body:     []byte{},
			expected: false,
		},
		{
			name:     "malformed body",
			body:     []byte{0xFF, 0xFF, 0xFF},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasCassandraSSLFlag(tt.body)
			if result != tt.expected {
				t.Errorf("hasCassandraSSLFlag() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsSSLRequired(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "SUPPORTED response with SSL",
			data: buildCassandraSupportedResponse([]string{"SSL", "CQL_VERSION"}),
			expected: true,
		},
		{
			name: "SUPPORTED response without SSL",
			data: buildCassandraSupportedResponse([]string{"CQL_VERSION", "COMPRESSION"}),
			expected: false,
		},
		{
			name:     "not a SUPPORTED response",
			data:     []byte{0x83, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSSLRequired(tt.data)
			if result != tt.expected {
				t.Errorf("isSSLRequired(%v) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

// Helper function to build Cassandra STARTUP body
func buildCassandraStartupBody(options map[string]string) []byte {
	var buf bytes.Buffer
	
	// Write map size
	buf.Write([]byte{0x00, byte(len(options))})
	
	// Write key-value pairs
	for k, v := range options {
		// Key length and value
		buf.Write([]byte{0x00, byte(len(k))})
		buf.WriteString(k)
		
		// Value length and value
		buf.Write([]byte{0x00, byte(len(v))})
		buf.WriteString(v)
	}
	
	return buf.Bytes()
}

// Helper function to build Cassandra SUPPORTED response
func buildCassandraSupportedResponse(options []string) []byte {
	var buf bytes.Buffer
	
	// Frame header
	buf.Write([]byte{0x83, 0x00, 0x06, 0x00}) // v3 response, SUPPORTED opcode
	
	// Body length placeholder
	bodyStart := buf.Len()
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	
	// Multimap with one key "OPTIONS"
	buf.Write([]byte{0x00, 0x01}) // Map size 1
	
	// Key "OPTIONS"
	buf.Write([]byte{0x00, 0x07}) // Key length
	buf.WriteString("OPTIONS")
	
	// List of option values
	buf.Write([]byte{0x00, byte(len(options))}) // List size
	for _, opt := range options {
		buf.Write([]byte{0x00, byte(len(opt))})
		buf.WriteString(opt)
	}
	
	// Update body length
	body := buf.Bytes()
	bodyLen := uint32(len(body) - 8) // Subtract header size
	body[bodyStart] = byte(bodyLen >> 24)
	body[bodyStart+1] = byte(bodyLen >> 16)
	body[bodyStart+2] = byte(bodyLen >> 8)
	body[bodyStart+3] = byte(bodyLen)
	
	return body
}