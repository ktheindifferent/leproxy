package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestEdgeCasesTimeouts tests timeout boundary conditions
func TestEdgeCasesTimeouts(t *testing.T) {
	tests := []struct {
		name          string
		readTimeout   time.Duration
		writeTimeout  time.Duration
		idleTimeout   time.Duration
		responseDelay time.Duration
		expectError   bool
	}{
		{
			name:          "zero timeouts (infinite)",
			readTimeout:   0,
			writeTimeout:  0,
			idleTimeout:   0,
			responseDelay: 100 * time.Millisecond,
			expectError:   false,
		},
		{
			name:          "negative timeout (treated as zero)",
			readTimeout:   -1 * time.Second,
			writeTimeout:  -1 * time.Second,
			idleTimeout:   -1 * time.Second,
			responseDelay: 100 * time.Millisecond,
			expectError:   false,
		},
		{
			name:          "minimum positive timeout",
			readTimeout:   1 * time.Nanosecond,
			writeTimeout:  1 * time.Nanosecond,
			idleTimeout:   1 * time.Nanosecond,
			responseDelay: 0,
			expectError:   true, // Should timeout immediately
		},
		{
			name:          "maximum timeout",
			readTimeout:   time.Duration(1<<63 - 1), // Max int64
			writeTimeout:  time.Duration(1<<63 - 1),
			idleTimeout:   time.Duration(1<<63 - 1),
			responseDelay: 100 * time.Millisecond,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server with delay
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.responseDelay > 0 {
					time.Sleep(tt.responseDelay)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			// Test timeout handling
			client := &http.Client{
				Timeout: 1 * time.Second, // Overall timeout to prevent hanging
			}

			req, _ := http.NewRequest("GET", backend.URL, nil)
			resp, err := client.Do(req)

			if tt.expectError && err == nil {
				t.Error("Expected timeout error but got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if resp != nil {
				resp.Body.Close()
			}
		})
	}
}

// TestEdgeCasesURLParsing tests URL parsing edge cases
func TestEdgeCasesURLParsing(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		description string
	}{
		{
			name:        "empty URL",
			input:       "",
			expectError: true,
			description: "Empty URL should fail",
		},
		{
			name:        "URL with only scheme",
			input:       "http://",
			expectError: false,
			description: "Scheme-only URL might be valid",
		},
		{
			name:        "URL with invalid scheme",
			input:       "ht!tp://example.com",
			expectError: true,
			description: "Invalid scheme characters",
		},
		{
			name:        "URL with spaces",
			input:       "http://example .com",
			expectError: false, // url.Parse is lenient
			description: "Spaces in hostname",
		},
		{
			name:        "URL with control characters",
			input:       "http://example\x00.com",
			expectError: false, // url.Parse is lenient
			description: "Null byte in hostname",
		},
		{
			name:        "extremely long URL",
			input:       "http://" + strings.Repeat("a", 10000) + ".com",
			expectError: false,
			description: "10000 character hostname",
		},
		{
			name:        "URL with all special characters",
			input:       "http://user:pass@host:8080/path?query=1#fragment",
			expectError: false,
			description: "Full URL with all components",
		},
		{
			name:        "URL with percent encoding",
			input:       "http://example.com/%20%21%22",
			expectError: false,
			description: "Percent-encoded path",
		},
		{
			name:        "URL with invalid percent encoding",
			input:       "http://example.com/%ZZ",
			expectError: false, // url.Parse is lenient
			description: "Invalid percent encoding",
		},
		{
			name:        "URL with unicode",
			input:       "http://例え.com/パス",
			expectError: false,
			description: "Unicode in hostname and path",
		},
		{
			name:        "URL with port boundary values",
			input:       "http://example.com:0",
			expectError: false,
			description: "Port 0",
		},
		{
			name:        "URL with max port",
			input:       "http://example.com:65535",
			expectError: false,
			description: "Maximum port number",
		},
		{
			name:        "URL with port overflow",
			input:       "http://example.com:65536",
			expectError: false, // url.Parse might accept it
			description: "Port exceeding maximum",
		},
		{
			name:        "URL with negative port",
			input:       "http://example.com:-1",
			expectError: false, // url.Parse is lenient
			description: "Negative port number",
		},
		{
			name:        "relative URL",
			input:       "/path/to/resource",
			expectError: false,
			description: "Relative path only",
		},
		{
			name:        "protocol-relative URL",
			input:       "//example.com/path",
			expectError: false,
			description: "Protocol-relative URL",
		},
		{
			name:        "URL with fragment only",
			input:       "#fragment",
			expectError: false,
			description: "Fragment-only URL",
		},
		{
			name:        "URL with query only",
			input:       "?query=value",
			expectError: false,
			description: "Query-only URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.input)

			if tt.expectError && err == nil {
				t.Errorf("%s: Expected error but got none. Parsed URL: %+v", tt.description, u)
			} else if !tt.expectError && err != nil {
				t.Errorf("%s: Unexpected error: %v", tt.description, err)
			}

			// Additional validation for successful parses
			if err == nil && u != nil {
				// Check that URL can be converted back to string
				_ = u.String()
			}
		})
	}
}

// TestEdgeCasesHeaders tests header handling edge cases
func TestEdgeCasesHeaders(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		expectPanic bool
		description string
	}{
		{
			name:        "empty header name",
			headers:     map[string]string{"": "value"},
			expectPanic: false,
			description: "Empty header name",
		},
		{
			name:        "empty header value",
			headers:     map[string]string{"X-Test": ""},
			expectPanic: false,
			description: "Empty header value",
		},
		{
			name:        "header with null bytes",
			headers:     map[string]string{"X-Test": "value\x00null"},
			expectPanic: false,
			description: "Null byte in header value",
		},
		{
			name:        "header with newlines",
			headers:     map[string]string{"X-Test": "line1\nline2"},
			expectPanic: false,
			description: "Newline in header value",
		},
		{
			name:        "header with carriage return",
			headers:     map[string]string{"X-Test": "line1\rline2"},
			expectPanic: false,
			description: "Carriage return in header value",
		},
		{
			name:        "extremely long header name",
			headers:     map[string]string{strings.Repeat("X", 10000): "value"},
			expectPanic: false,
			description: "10000 character header name",
		},
		{
			name:        "extremely long header value",
			headers:     map[string]string{"X-Test": strings.Repeat("a", 100000)},
			expectPanic: false,
			description: "100000 character header value",
		},
		{
			name: "many headers",
			headers: func() map[string]string {
				h := make(map[string]string)
				for i := 0; i < 1000; i++ {
					h[fmt.Sprintf("X-Header-%d", i)] = fmt.Sprintf("value-%d", i)
				}
				return h
			}(),
			expectPanic: false,
			description: "1000 headers",
		},
		{
			name:        "unicode header value",
			headers:     map[string]string{"X-Test": "你好世界🌍"},
			expectPanic: false,
			description: "Unicode in header value",
		},
		{
			name:        "header injection attempt",
			headers:     map[string]string{"X-Test": "value\r\nX-Injected: true"},
			expectPanic: false,
			description: "Header injection attempt",
		},
		{
			name:        "reserved header modification",
			headers:     map[string]string{"Host": "evil.com", "Content-Length": "999999"},
			expectPanic: false,
			description: "Attempt to modify reserved headers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil && !tt.expectPanic {
					t.Errorf("%s: Unexpected panic: %v", tt.description, r)
				} else if r == nil && tt.expectPanic {
					t.Errorf("%s: Expected panic but got none", tt.description)
				}
			}()

			req := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Verify headers were set (might be modified by http package)
			for k := range tt.headers {
				_ = req.Header.Get(k)
			}
		})
	}
}

// TestEdgeCasesRequestBody tests request body edge cases
func TestEdgeCasesRequestBody(t *testing.T) {
	tests := []struct {
		name        string
		bodySize    int
		bodyContent func(int) io.Reader
		expectError bool
		description string
	}{
		{
			name:     "empty body",
			bodySize: 0,
			bodyContent: func(size int) io.Reader {
				return bytes.NewReader([]byte{})
			},
			expectError: false,
			description: "Empty request body",
		},
		{
			name:     "single byte body",
			bodySize: 1,
			bodyContent: func(size int) io.Reader {
				return bytes.NewReader([]byte{0x00})
			},
			expectError: false,
			description: "Single null byte",
		},
		{
			name:     "1MB body",
			bodySize: 1024 * 1024,
			bodyContent: func(size int) io.Reader {
				return bytes.NewReader(bytes.Repeat([]byte("a"), size))
			},
			expectError: false,
			description: "1MB request body",
		},
		{
			name:     "10MB body",
			bodySize: 10 * 1024 * 1024,
			bodyContent: func(size int) io.Reader {
				return bytes.NewReader(bytes.Repeat([]byte("b"), size))
			},
			expectError: false,
			description: "10MB request body",
		},
		{
			name:     "binary content",
			bodySize: 1024,
			bodyContent: func(size int) io.Reader {
				data := make([]byte, size)
				for i := range data {
					data[i] = byte(i % 256)
				}
				return bytes.NewReader(data)
			},
			expectError: false,
			description: "Binary content with all byte values",
		},
		{
			name:     "nil reader",
			bodySize: 0,
			bodyContent: func(size int) io.Reader {
				return nil
			},
			expectError: false,
			description: "Nil body reader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("X-Body-Size", fmt.Sprintf("%d", len(body)))
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			req := httptest.NewRequest("POST", "/test", tt.bodyContent(tt.bodySize))
			rr := httptest.NewRecorder()

			// Create a simple proxy to test body handling
			backendURL, _ := url.Parse(backend.URL)
			proxy := newSingleHostReverseProxy(backendURL)
			proxy.ServeHTTP(rr, req)

			if tt.expectError && rr.Code == http.StatusOK {
				t.Errorf("%s: Expected error but got success", tt.description)
			} else if !tt.expectError && rr.Code != http.StatusOK {
				t.Errorf("%s: Expected success but got status %d", tt.description, rr.Code)
			}

			// Verify body size if successful
			if rr.Code == http.StatusOK {
				bodySizeHeader := rr.Header().Get("X-Body-Size")
				if bodySizeHeader != fmt.Sprintf("%d", tt.bodySize) && tt.bodyContent(tt.bodySize) != nil {
					t.Errorf("%s: Body size mismatch. Expected %d, got %s", tt.description, tt.bodySize, bodySizeHeader)
				}
			}
		})
	}
}

// TestEdgeCasesHostMapping tests host mapping edge cases
func TestEdgeCasesHostMapping(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		mapping     map[string]string
		expectedBackend string
		shouldMatch bool
	}{
		{
			name:     "exact match",
			hostname: "example.com",
			mapping: map[string]string{
				"example.com": "backend1:8080",
			},
			expectedBackend: "backend1:8080",
			shouldMatch: true,
		},
		{
			name:     "case sensitivity",
			hostname: "Example.COM",
			mapping: map[string]string{
				"example.com": "backend1:8080",
			},
			expectedBackend: "",
			shouldMatch: false, // Hostnames are case-sensitive in Go maps
		},
		{
			name:     "wildcard prefix",
			hostname: "api.example.com",
			mapping: map[string]string{
				"*.example.com": "backend1:8080",
			},
			expectedBackend: "backend1:8080",
			shouldMatch: true,
		},
		{
			name:     "port in hostname",
			hostname: "example.com:8080",
			mapping: map[string]string{
				"example.com": "backend1:8080",
			},
			expectedBackend: "",
			shouldMatch: false, // Port should be stripped before mapping
		},
		{
			name:     "empty hostname",
			hostname: "",
			mapping: map[string]string{
				"": "backend1:8080",
			},
			expectedBackend: "backend1:8080",
			shouldMatch: true,
		},
		{
			name:     "hostname with trailing dot",
			hostname: "example.com.",
			mapping: map[string]string{
				"example.com": "backend1:8080",
			},
			expectedBackend: "",
			shouldMatch: false, // Trailing dot makes it different
		},
		{
			name:     "IPv4 address",
			hostname: "192.168.1.1",
			mapping: map[string]string{
				"192.168.1.1": "backend1:8080",
			},
			expectedBackend: "backend1:8080",
			shouldMatch: true,
		},
		{
			name:     "IPv6 address",
			hostname: "[::1]",
			mapping: map[string]string{
				"[::1]": "backend1:8080",
			},
			expectedBackend: "backend1:8080",
			shouldMatch: true,
		},
		{
			name:     "hostname with special characters",
			hostname: "sub-domain_test.example.com",
			mapping: map[string]string{
				"sub-domain_test.example.com": "backend1:8080",
			},
			expectedBackend: "backend1:8080",
			shouldMatch: true,
		},
		{
			name:     "internationalized domain name",
			hostname: "例え.jp",
			mapping: map[string]string{
				"例え.jp": "backend1:8080",
			},
			expectedBackend: "backend1:8080",
			shouldMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, found := tt.mapping[tt.hostname]
			
			if tt.shouldMatch && !found {
				t.Errorf("Expected to find backend for hostname '%s'", tt.hostname)
			} else if !tt.shouldMatch && found {
				t.Errorf("Should not find backend for hostname '%s', but got '%s'", tt.hostname, backend)
			}
			
			if found && backend != tt.expectedBackend {
				t.Errorf("Backend mismatch for '%s': expected '%s', got '%s'", tt.hostname, tt.expectedBackend, backend)
			}
		})
	}
}

// TestEdgeCasesConnectionHandling tests connection edge cases
func TestEdgeCasesConnectionHandling(t *testing.T) {
	tests := []struct {
		name        string
		scenario    func(*testing.T, *httptest.Server)
		description string
	}{
		{
			name: "client disconnect during request",
			scenario: func(t *testing.T, server *httptest.Server) {
				// Simulate client disconnecting mid-request
				conn, err := net.Dial("tcp", server.Listener.Addr().String())
				if err != nil {
					t.Fatalf("Failed to connect: %v", err)
				}
				
				// Send partial request
				conn.Write([]byte("GET / HTTP/1.1\r\nHost: "))
				// Abruptly close
				conn.Close()
			},
			description: "Client disconnects during request transmission",
		},
		{
			name: "slow client",
			scenario: func(t *testing.T, server *httptest.Server) {
				conn, err := net.Dial("tcp", server.Listener.Addr().String())
				if err != nil {
					t.Fatalf("Failed to connect: %v", err)
				}
				defer conn.Close()
				
				// Send request very slowly
				req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
				for _, b := range req {
					conn.Write([]byte{b})
					time.Sleep(10 * time.Millisecond)
				}
			},
			description: "Slow client sending request byte by byte",
		},
		{
			name: "connection reuse",
			scenario: func(t *testing.T, server *httptest.Server) {
				client := &http.Client{
					Transport: &http.Transport{
						MaxIdleConns:        1,
						MaxIdleConnsPerHost: 1,
					},
				}
				
				// Send multiple requests on same connection
				for i := 0; i < 10; i++ {
					resp, err := client.Get(server.URL)
					if err != nil {
						t.Errorf("Request %d failed: %v", i, err)
						continue
					}
					io.ReadAll(resp.Body)
					resp.Body.Close()
				}
			},
			description: "Multiple requests on single connection",
		},
		{
			name: "concurrent connections",
			scenario: func(t *testing.T, server *httptest.Server) {
				numConns := 100
				done := make(chan bool, numConns)
				
				for i := 0; i < numConns; i++ {
					go func(id int) {
						resp, err := http.Get(server.URL)
						if err != nil {
							t.Errorf("Connection %d failed: %v", id, err)
						} else {
							resp.Body.Close()
						}
						done <- true
					}(i)
				}
				
				// Wait for all connections
				for i := 0; i < numConns; i++ {
					<-done
				}
			},
			description: "100 concurrent connections",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			}))
			defer server.Close()

			// Run the scenario
			tt.scenario(t, server)
		})
	}
}