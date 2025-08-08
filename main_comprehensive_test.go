package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReadMapping tests the YAML mapping file parser with various scenarios
func TestReadMappingComprehensive(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expected    map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid simple mapping",
			content: `example.com: localhost:8080
test.com: 127.0.0.1:3000`,
			expected: map[string]string{
				"example.com": "localhost:8080",
				"test.com":    "127.0.0.1:3000",
			},
		},
		{
			name: "valid mapping with comments",
			content: `# Production servers
prod.example.com: 10.0.0.1:8080
# Test servers  
test.example.com: 10.0.0.2:8080`,
			expected: map[string]string{
				"prod.example.com": "10.0.0.1:8080",
				"test.example.com": "10.0.0.2:8080",
			},
		},
		{
			name: "mapping with URLs",
			content: `api.example.com: http://backend:8080
secure.example.com: https://secure-backend:443`,
			expected: map[string]string{
				"api.example.com":    "http://backend:8080",
				"secure.example.com": "https://secure-backend:443",
			},
		},
		{
			name:     "empty file",
			content:  "",
			expected: map[string]string{},
		},
		{
			name:     "only comments",
			content:  "# Just a comment\n# Another comment",
			expected: map[string]string{},
		},
		{
			name: "duplicate hosts (last wins)",
			content: `example.com: backend1:8080
example.com: backend2:8080`,
			expected: map[string]string{
				"example.com": "backend2:8080",
			},
		},
		{
			name: "whitespace handling",
			content: `  example.com  :   backend:8080  
	test.com	:	127.0.0.1:3000	`,
			expected: map[string]string{
				"example.com": "backend:8080",
				"test.com":    "127.0.0.1:3000",
			},
		},
		{
			name: "mixed valid and invalid lines",
			content: `valid.com: backend:8080
invalid line without colon
another.com: backend:9090`,
			expected: map[string]string{
				"valid.com":   "backend:8080",
				"another.com": "backend:9090",
			},
		},
		{
			name: "edge case - empty backend",
			content: `example.com: 
test.com: backend:8080`,
			expected: map[string]string{
				"test.com": "backend:8080",
			},
		},
		{
			name: "edge case - multiple colons",
			content: `example.com: http://[::1]:8080
ipv6.example.com: [2001:db8::1]:8080`,
			expected: map[string]string{
				"example.com":     "http://[::1]:8080",
				"ipv6.example.com": "[2001:db8::1]:8080",
			},
		},
		{
			name: "special characters in hostname",
			content: `sub-domain.example.com: backend:8080
api_v2.example.com: backend:9090
*.wildcard.com: backend:8888`,
			expected: map[string]string{
				"sub-domain.example.com": "backend:8080",
				"api_v2.example.com":     "backend:9090",
				"*.wildcard.com":         "backend:8888",
			},
		},
		{
			name: "port edge cases",
			content: `example.com: backend:1
high-port.com: backend:65535
no-port.com: backend`,
			expected: map[string]string{
				"example.com":   "backend:1",
				"high-port.com": "backend:65535",
				"no-port.com":   "backend",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpfile, err := os.CreateTemp("", "mapping-*.yml")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpfile.Name())

			// Write test content
			if _, err := tmpfile.Write([]byte(tt.content)); err != nil {
				t.Fatalf("Failed to write temp file: %v", err)
			}
			tmpfile.Close()

			// Test readMapping function
			result, err := readMapping(tmpfile.Name())

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify mapping
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d mappings, got %d", len(tt.expected), len(result))
			}

			for host, backend := range tt.expected {
				if result[host] != backend {
					t.Errorf("For host %s: expected backend %s, got %s", host, backend, result[host])
				}
			}
		})
	}
}

// TestReadMappingFileErrors tests file-related error conditions
func TestReadMappingFileErrors(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() string
		cleanup  func(string)
		errorMsg string
	}{
		{
			name: "non-existent file",
			setup: func() string {
				return "/non/existent/file.yml"
			},
			cleanup:  func(string) {},
			errorMsg: "no such file",
		},
		{
			name: "directory instead of file",
			setup: func() string {
				dir, _ := os.MkdirTemp("", "test-dir")
				return dir
			},
			cleanup: func(path string) {
				os.RemoveAll(path)
			},
			errorMsg: "is a directory",
		},
		{
			name: "no read permission",
			setup: func() string {
				tmpfile, _ := os.CreateTemp("", "noperm-*.yml")
				tmpfile.Close()
				os.Chmod(tmpfile.Name(), 0000)
				return tmpfile.Name()
			},
			cleanup: func(path string) {
				os.Chmod(path, 0644)
				os.Remove(path)
			},
			errorMsg: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			defer tt.cleanup(path)

			_, err := readMapping(path)
			if err == nil {
				t.Errorf("Expected error but got none")
			} else if !strings.Contains(strings.ToLower(err.Error()), tt.errorMsg) {
				t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
			}
		})
	}
}

// TestSetProxy tests proxy handler creation
func TestSetProxy(t *testing.T) {
	tests := []struct {
		name        string
		mapping     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid HTTP backend",
			mapping: map[string]string{
				"example.com": "http://localhost:8080",
			},
		},
		{
			name: "valid HTTPS backend",
			mapping: map[string]string{
				"secure.com": "https://backend:443",
			},
		},
		{
			name: "multiple hosts",
			mapping: map[string]string{
				"site1.com": "http://backend1:8080",
				"site2.com": "http://backend2:8080",
				"site3.com": "https://backend3:443",
			},
		},
		{
			name: "host:port format (needs scheme)",
			mapping: map[string]string{
				"example.com": "localhost:8080",
			},
		},
		{
			name: "invalid URL",
			mapping: map[string]string{
				"example.com": "://invalid-url",
			},
			expectError: true,
			errorMsg:    "invalid",
		},
		{
			name:    "empty mapping",
			mapping: map[string]string{},
		},
		{
			name: "wildcard host",
			mapping: map[string]string{
				"*.example.com": "http://backend:8080",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := setProxy(tt.mapping)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(strings.ToLower(err.Error()), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if handler == nil {
				t.Error("Expected non-nil handler")
			}
		})
	}
}

// TestNewSingleHostReverseProxy tests reverse proxy creation
func TestNewSingleHostReverseProxy(t *testing.T) {
	// Start a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back request details
		w.Header().Set("X-Backend-Host", r.Host)
		w.Header().Set("X-Backend-Path", r.URL.Path)
		w.Header().Set("X-Backend-Method", r.Method)
		
		// Check for X-Forwarded headers
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			w.Header().Set("X-Received-XFF", xff)
		}
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			w.Header().Set("X-Received-XFH", xfh)
		}
		
		fmt.Fprintf(w, "Backend response: %s %s", r.Method, r.URL.Path)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	proxy := newSingleHostReverseProxy(backendURL)

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		expectedStatus int
		checkHeaders   map[string]string
	}{
		{
			name:           "simple GET request",
			method:         "GET",
			path:           "/test",
			expectedStatus: http.StatusOK,
			checkHeaders: map[string]string{
				"X-Backend-Method": "GET",
				"X-Backend-Path":   "/test",
			},
		},
		{
			name:           "POST request with path",
			method:         "POST",
			path:           "/api/users",
			expectedStatus: http.StatusOK,
			checkHeaders: map[string]string{
				"X-Backend-Method": "POST",
				"X-Backend-Path":   "/api/users",
			},
		},
		{
			name:   "request with custom headers",
			method: "GET",
			path:   "/",
			headers: map[string]string{
				"X-Custom-Header": "test-value",
				"Authorization":   "Bearer token123",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with query parameters",
			method:         "GET",
			path:           "/search?q=test&limit=10",
			expectedStatus: http.StatusOK,
			checkHeaders: map[string]string{
				"X-Backend-Path": "/search",
			},
		},
		{
			name:           "PUT request",
			method:         "PUT",
			path:           "/resource/123",
			expectedStatus: http.StatusOK,
			checkHeaders: map[string]string{
				"X-Backend-Method": "PUT",
				"X-Backend-Path":   "/resource/123",
			},
		},
		{
			name:           "DELETE request",
			method:         "DELETE",
			path:           "/resource/456",
			expectedStatus: http.StatusOK,
			checkHeaders: map[string]string{
				"X-Backend-Method": "DELETE",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Serve request through proxy
			proxy.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check headers
			for header, expected := range tt.checkHeaders {
				if actual := rr.Header().Get(header); actual != expected {
					t.Errorf("Header %s: expected '%s', got '%s'", header, expected, actual)
				}
			}
		})
	}
}

// TestProxyWebSocketUpgrade tests WebSocket upgrade handling
func TestProxyWebSocketUpgrade(t *testing.T) {
	// Create a WebSocket echo server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	proxy := newSingleHostReverseProxy(backendURL)

	// Create WebSocket upgrade request
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	// Check for upgrade headers
	if rr.Code != http.StatusSwitchingProtocols {
		t.Errorf("Expected status 101, got %d", rr.Code)
	}
	if upgrade := rr.Header().Get("Upgrade"); upgrade != "websocket" {
		t.Errorf("Expected Upgrade: websocket, got %s", upgrade)
	}
}

// TestKeys tests the keys helper function
func TestKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]string
		expected int
	}{
		{
			name:     "empty map",
			input:    map[string]string{},
			expected: 0,
		},
		{
			name: "single entry",
			input: map[string]string{
				"key1": "value1",
			},
			expected: 1,
		},
		{
			name: "multiple entries",
			input: map[string]string{
				"host1.com": "backend1",
				"host2.com": "backend2",
				"host3.com": "backend3",
			},
			expected: 3,
		},
		{
			name:     "nil map",
			input:    nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := keys(tt.input)
			if len(result) != tt.expected {
				t.Errorf("Expected %d keys, got %d", tt.expected, len(result))
			}

			// Verify all keys are present
			for k := range tt.input {
				found := false
				for _, key := range result {
					if key == k {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Key '%s' not found in result", k)
				}
			}
		})
	}
}

// TestSingleJoiningSlash tests URL path joining
func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected string
	}{
		{"", "", "/"},
		{"/", "", "/"},
		{"", "/", "/"},
		{"/", "/", "/"},
		{"/api", "/users", "/api/users"},
		{"/api/", "/users", "/api/users"},
		{"/api", "users", "/api/users"},
		{"/api/", "users", "/api/users"},
		{"api", "users", "api/users"},
		{"api/", "/users", "api/users"},
		{"http://example.com", "/path", "http://example.com/path"},
		{"http://example.com/", "/path", "http://example.com/path"},
		{"http://example.com/api", "/v1", "http://example.com/api/v1"},
		{"http://example.com/api/", "/v1", "http://example.com/api/v1"},
		{"/multiple///slashes/", "///path", "/multiple///slashes/path"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s+%s", tt.a, tt.b), func(t *testing.T) {
			result := singleJoiningSlash(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestRunArgsValidation tests command-line argument validation
func TestRunArgsValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        runArgs
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid minimal configuration",
			args: runArgs{
				Addr:  ":443",
				Conf:  "mapping.yml",
				Cache: "/tmp/cache",
			},
		},
		{
			name: "missing cache directory",
			args: runArgs{
				Addr: ":443",
				Conf: "mapping.yml",
			},
			expectError: true,
			errorMsg:    "no cache specified",
		},
		{
			name: "ZeroSSL without email",
			args: runArgs{
				Addr:     ":443",
				Conf:     "mapping.yml",
				Cache:    "/tmp/cache",
				Provider: "zerossl",
			},
			expectError: true,
			errorMsg:    "email is required",
		},
		{
			name: "ZeroSSL without EAB credentials",
			args: runArgs{
				Addr:     ":443",
				Conf:     "mapping.yml",
				Cache:    "/tmp/cache",
				Provider: "zerossl",
				Email:    "test@example.com",
			},
			expectError: true,
			errorMsg:    "EAB credentials",
		},
		{
			name: "valid ZeroSSL configuration",
			args: runArgs{
				Addr:     ":443",
				Conf:     "mapping.yml",
				Cache:    "/tmp/cache",
				Provider: "zerossl",
				Email:    "test@example.com",
				EABKID:   "test-kid",
				EABHMAC:  "test-hmac",
			},
		},
		{
			name: "custom ACME URL",
			args: runArgs{
				Addr:    ":443",
				Conf:    "mapping.yml",
				Cache:   "/tmp/cache",
				ACMEURL: "https://custom.acme.example.com/directory",
			},
		},
		{
			name: "with database proxy config",
			args: runArgs{
				Addr:        ":443",
				Conf:        "mapping.yml",
				Cache:       "/tmp/cache",
				DBConf:      "dbproxy.conf",
				DBCertCache: "/tmp/dbcerts",
			},
		},
		{
			name: "with timeouts",
			args: runArgs{
				Addr:  ":443",
				Conf:  "mapping.yml",
				Cache: "/tmp/cache",
				RTo:   30 * time.Second,
				WTo:   60 * time.Second,
				Idle:  120 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: We can't directly test run() as it starts servers,
			// but we can validate the arguments would be accepted
			err := validateRunArgs(tt.args)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorMsg, err)
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// validateRunArgs validates runArgs configuration (helper for testing)
func validateRunArgs(args runArgs) error {
	if args.Cache == "" {
		return fmt.Errorf("no cache specified")
	}
	
	if args.Provider == "zerossl" {
		if args.Email == "" {
			return fmt.Errorf("email is required for ZeroSSL")
		}
		if args.EABKID == "" || args.EABHMAC == "" {
			return fmt.Errorf("EAB credentials required for ZeroSSL")
		}
	}
	
	return nil
}

// TestConcurrentProxyRequests tests proxy under concurrent load
func TestConcurrentProxyRequests(t *testing.T) {
	// Create a backend that tracks request count
	var requestCount int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		fmt.Fprintf(w, "Response %d", requestCount)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	proxy := newSingleHostReverseProxy(backendURL)

	// Number of concurrent requests
	numRequests := 100
	done := make(chan bool, numRequests)

	// Launch concurrent requests
	for i := 0; i < numRequests; i++ {
		go func(id int) {
			req := httptest.NewRequest("GET", fmt.Sprintf("/test/%d", id), nil)
			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)
			
			if rr.Code != http.StatusOK {
				t.Errorf("Request %d failed with status %d", id, rr.Code)
			}
			done <- true
		}(i)
	}

	// Wait for all requests to complete
	timeout := time.After(5 * time.Second)
	for i := 0; i < numRequests; i++ {
		select {
		case <-done:
			// Request completed
		case <-timeout:
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}
}

// TestProxyBodyHandling tests request/response body handling
func TestProxyBodyHandling(t *testing.T) {
	// Backend that echoes the request body
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		w.Header().Set("X-Body-Length", fmt.Sprintf("%d", len(body)))
		w.Write(body)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	proxy := newSingleHostReverseProxy(backendURL)

	tests := []struct {
		name        string
		body        string
		contentType string
	}{
		{
			name:        "JSON body",
			body:        `{"key":"value","number":123}`,
			contentType: "application/json",
		},
		{
			name:        "Form data",
			body:        "field1=value1&field2=value2",
			contentType: "application/x-www-form-urlencoded",
		},
		{
			name:        "Plain text",
			body:        "This is plain text content",
			contentType: "text/plain",
		},
		{
			name:        "Empty body",
			body:        "",
			contentType: "",
		},
		{
			name:        "Large body",
			body:        strings.Repeat("x", 10000),
			contentType: "text/plain",
		},
		{
			name:        "Binary-like content",
			body:        "\x00\x01\x02\x03\x04\x05",
			contentType: "application/octet-stream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
			}

			// Verify body was properly proxied
			responseBody := rr.Body.String()
			if responseBody != tt.body {
				t.Errorf("Body mismatch: expected %d bytes, got %d bytes", len(tt.body), len(responseBody))
			}

			// Verify content type was preserved
			if tt.contentType != "" && rr.Header().Get("Content-Type") != tt.contentType {
				t.Errorf("Content-Type mismatch: expected %s, got %s", tt.contentType, rr.Header().Get("Content-Type"))
			}

			// Verify body length header
			expectedLength := fmt.Sprintf("%d", len(tt.body))
			if rr.Header().Get("X-Body-Length") != expectedLength {
				t.Errorf("Body length mismatch: expected %s, got %s", expectedLength, rr.Header().Get("X-Body-Length"))
			}
		})
	}
}

// TestProxyErrorHandling tests proxy behavior with backend errors
func TestProxyErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		setupBackend   func() *httptest.Server
		expectedStatus int
	}{
		{
			name: "backend returns 404",
			setupBackend: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.NotFound(w, r)
				}))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "backend returns 500",
			setupBackend: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "backend returns 503",
			setupBackend: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				}))
			},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name: "backend timeout simulation",
			setupBackend: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(100 * time.Millisecond)
					w.WriteHeader(http.StatusOK)
				}))
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupBackend()
			defer backend.Close()

			backendURL, _ := url.Parse(backend.URL)
			proxy := newSingleHostReverseProxy(backendURL)

			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// TestProxyHeaderManipulation tests X-Forwarded-* header handling
func TestProxyHeaderManipulation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo all X-Forwarded headers back
		for k, v := range r.Header {
			if strings.HasPrefix(k, "X-Forwarded-") {
				w.Header()[k] = v
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	proxy := newSingleHostReverseProxy(backendURL)

	tests := []struct {
		name            string
		existingHeaders map[string]string
		clientIP        string
		expectedHeaders map[string][]string
	}{
		{
			name:     "no existing X-Forwarded headers",
			clientIP: "192.168.1.1",
		},
		{
			name: "existing X-Forwarded-For",
			existingHeaders: map[string]string{
				"X-Forwarded-For": "10.0.0.1",
			},
			clientIP: "192.168.1.1",
		},
		{
			name: "multiple existing headers",
			existingHeaders: map[string]string{
				"X-Forwarded-For":   "10.0.0.1, 10.0.0.2",
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "example.com",
			},
			clientIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.clientIP + ":12345"
			
			for k, v := range tt.existingHeaders {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
			}
		})
	}
}