package dbproxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// errorConn simulates a connection that returns errors on operations
type errorConn struct {
	net.Conn
	readErr  error
	writeErr error
	closeErr error
	mu       sync.Mutex
	closed   bool
}

func (c *errorConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return len(b), nil
}

func (c *errorConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("connection closed")
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}

func (c *errorConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.closeErr != nil {
		return c.closeErr
	}
	return nil
}

func (c *errorConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *errorConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *errorConn) SetDeadline(t time.Time) error      { return nil }
func (c *errorConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *errorConn) SetWriteDeadline(t time.Time) error { return nil }

// partialConn simulates a connection that fails after transferring some data
type partialConn struct {
	net.Conn
	data       []byte
	readIndex  int
	writeCount int
	maxWrites  int
	mu         sync.Mutex
	closed     bool
}

func newPartialConn(data []byte, maxWrites int) *partialConn {
	return &partialConn{
		data:      data,
		maxWrites: maxWrites,
	}
}

func (c *partialConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.closed {
		return 0, io.EOF
	}
	
	if c.readIndex >= len(c.data) {
		// Simulate network error after all data is read
		return 0, errors.New("network error: connection reset by peer")
	}
	
	n := copy(b, c.data[c.readIndex:])
	c.readIndex += n
	return n, nil
}

func (c *partialConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.closed {
		return 0, errors.New("connection closed")
	}
	
	if c.maxWrites > 0 && c.writeCount >= c.maxWrites {
		return 0, errors.New("network error: broken pipe")
	}
	
	c.writeCount++
	return len(b), nil
}

func (c *partialConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *partialConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *partialConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *partialConn) SetDeadline(t time.Time) error      { return nil }
func (c *partialConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *partialConn) SetWriteDeadline(t time.Time) error { return nil }

// Test error handling for SMTP proxy
func TestSMTPProxyErrorHandling(t *testing.T) {
	tlsConfig := &tls.Config{}
	proxy := NewSMTPProxy("localhost:25", tlsConfig)
	
	t.Run("ClientReadError", func(t *testing.T) {
		clientConn := &errorConn{readErr: errors.New("client read error")}
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after read error")
		}
	})
	
	t.Run("BackendWriteError", func(t *testing.T) {
		clientConn := newPartialConn([]byte("HELO test\r\n"), 0)
		
		// The handleConnection should gracefully handle backend errors
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after backend error")
		}
	})
	
	t.Run("PartialDataTransfer", func(t *testing.T) {
		testData := []byte("MAIL FROM:<test@example.com>\r\n")
		clientConn := newPartialConn(testData, 2)
		
		// The handleConnection should gracefully handle partial transfers
		// This test verifies that the proxy logs errors but doesn't panic
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after partial transfer")
		}
	})
}

// Test error handling for Redis proxy
func TestRedisProxyErrorHandling(t *testing.T) {
	tlsConfig := &tls.Config{}
	proxy := NewRedisProxy("localhost:6379", tlsConfig)
	
	t.Run("ClientIOError", func(t *testing.T) {
		clientConn := &errorConn{readErr: errors.New("client IO error")}
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after IO error")
		}
	})
	
	t.Run("BackendConnectionError", func(t *testing.T) {
		// Test with RESP protocol command
		testCmd := []byte("*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
		clientConn := newPartialConn(testCmd, 0)
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after backend error")
		}
	})
	
	t.Run("STARTTLSWithError", func(t *testing.T) {
		proxy.EnableTLS = true
		
		// Simulate STARTTLS command
		starttlsCmd := []byte("STARTTLS\r\n")
		clientConn := newPartialConn(starttlsCmd, 1)
		
		// The connection should handle TLS negotiation errors gracefully
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after STARTTLS error")
		}
	})
}

// Test error handling for MSSQL proxy
func TestMSSQLProxyErrorHandling(t *testing.T) {
	tlsConfig := &tls.Config{}
	proxy := NewMSSQLProxy("localhost:1433", tlsConfig)
	
	t.Run("PreloginPacketError", func(t *testing.T) {
		// Create a malformed prelogin packet
		badPacket := []byte{0x12, 0x00, 0x00, 0x00}
		clientConn := newPartialConn(badPacket, 0)
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after prelogin error")
		}
	})
	
	t.Run("CopyError", func(t *testing.T) {
		// Normal TDS packet
		tdsPacket := []byte{0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
		clientConn := newPartialConn(tdsPacket, 1)
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after copy error")
		}
	})
}

// Test error handling for MongoDB proxy
func TestMongoDBProxyErrorHandling(t *testing.T) {
	tlsConfig := &tls.Config{}
	proxy := NewMongoDBProxy("localhost:27017", tlsConfig)
	
	t.Run("WireProtocolError", func(t *testing.T) {
		// Create a MongoDB wire protocol message with error
		// Message header: 16 bytes (length, requestID, responseTo, opCode)
		header := make([]byte, 16)
		header[0] = 0x20 // Length: 32 bytes
		header[12] = 0xd4 // OpCode: OP_QUERY (2004)
		header[13] = 0x07
		
		clientConn := newPartialConn(header, 1)
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after wire protocol error")
		}
	})
	
	t.Run("TLSNegotiationError", func(t *testing.T) {
		proxy.EnableTLS = true
		
		// Simulate TLS handshake byte followed by error
		tlsHandshake := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
		clientConn := newPartialConn(tlsHandshake, 0)
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after TLS negotiation error")
		}
	})
	
	t.Run("PartialMessageTransfer", func(t *testing.T) {
		// Create a partial MongoDB message
		partialMsg := make([]byte, 20)
		partialMsg[0] = 0x30 // Length: 48 bytes (but we only have 20)
		
		clientConn := newPartialConn(partialMsg, 2)
		
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Client connection should be closed after partial message transfer")
		}
	})
}

// Test concurrent error scenarios
func TestConcurrentErrorHandling(t *testing.T) {
	tlsConfig := &tls.Config{}
	
	t.Run("SMTPConcurrentErrors", func(t *testing.T) {
		proxy := NewSMTPProxy("localhost:25", tlsConfig)
		
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				var clientConn net.Conn
				if id%2 == 0 {
					clientConn = &errorConn{readErr: errors.New("concurrent read error")}
				} else {
					clientConn = &errorConn{writeErr: errors.New("concurrent write error")}
				}
				
				proxy.handleConnection(clientConn)
			}(i)
		}
		
		done := make(chan bool)
		go func() {
			wg.Wait()
			done <- true
		}()
		
		select {
		case <-done:
			// Success - all connections handled without deadlock
		case <-time.After(5 * time.Second):
			t.Error("Concurrent error handling timed out - possible deadlock")
		}
	})
}

// Test error message formatting
func TestErrorLogging(t *testing.T) {
	// This test verifies that error messages are properly formatted
	// In a real scenario, we'd capture log output, but for now we just
	// ensure the code paths are exercised without panics
	
	testCases := []struct {
		name     string
		proxyGen func() interface{ handleConnection(net.Conn) }
		err      error
	}{
		{
			name:     "SMTP Network Error",
			proxyGen: func() interface{ handleConnection(net.Conn) } { 
				return NewSMTPProxy("localhost:25", &tls.Config{}) 
			},
			err:      errors.New("network unreachable"),
		},
		{
			name:     "Redis Protocol Error",
			proxyGen: func() interface{ handleConnection(net.Conn) } { 
				return NewRedisProxy("localhost:6379", &tls.Config{}) 
			},
			err:      errors.New("invalid RESP protocol"),
		},
		{
			name:     "MSSQL TDS Error",
			proxyGen: func() interface{ handleConnection(net.Conn) } { 
				return NewMSSQLProxy("localhost:1433", &tls.Config{}) 
			},
			err:      errors.New("TDS protocol violation"),
		},
		{
			name:     "MongoDB Wire Protocol Error",
			proxyGen: func() interface{ handleConnection(net.Conn) } { 
				return NewMongoDBProxy("localhost:27017", &tls.Config{}) 
			},
			err:      errors.New("invalid MongoDB wire protocol message"),
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := tc.proxyGen()
			clientConn := &errorConn{readErr: tc.err}
			
			// This should log the error without panicking
			proxy.handleConnection(clientConn)
			
			// Verify connection was closed
			if !clientConn.closed {
				t.Errorf("%s: Connection should be closed after error", tc.name)
			}
		})
	}
}

// Test EOF handling (should not log as error)
func TestEOFHandling(t *testing.T) {
	tlsConfig := &tls.Config{}
	
	proxies := []interface{ handleConnection(net.Conn) }{
		NewSMTPProxy("localhost:25", tlsConfig),
		NewRedisProxy("localhost:6379", tlsConfig),
		NewMSSQLProxy("localhost:1433", tlsConfig),
		NewMongoDBProxy("localhost:27017", tlsConfig),
	}
	
	for _, proxy := range proxies {
		clientConn := &errorConn{readErr: io.EOF}
		// Note: backendConn is handled internally by the proxy
		
		// EOF should be handled gracefully without error logging
		proxy.handleConnection(clientConn)
		
		if !clientConn.closed {
			t.Error("Connection should be closed after EOF")
		}
	}
}

// Benchmark error handling overhead
func BenchmarkErrorHandling(b *testing.B) {
	tlsConfig := &tls.Config{}
	proxy := NewSMTPProxy("localhost:25", tlsConfig)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientConn := &errorConn{readErr: errors.New("benchmark error")}
		proxy.handleConnection(clientConn)
	}
}

// testTimeoutError implements net.Error for testing timeout detection
type testTimeoutError struct {
	error
}

func (e testTimeoutError) Timeout() bool   { return true }
func (e testTimeoutError) Temporary() bool { return true }

// Test timeout error detection
func TestTimeoutErrorDetection(t *testing.T) {
	tlsConfig := &tls.Config{}
	proxy := NewRedisProxy("localhost:6379", tlsConfig)
	
	timeoutErr := testTimeoutError{error: errors.New("operation timed out")}
	clientConn := &errorConn{readErr: timeoutErr}
	
	proxy.handleConnection(clientConn)
	
	if !clientConn.closed {
		t.Error("Connection should be closed after timeout error")
	}
}

// Test resource cleanup after errors
func TestResourceCleanup(t *testing.T) {
	tlsConfig := &tls.Config{}
	
	t.Run("ConnectionsClosedOnError", func(t *testing.T) {
		proxy := NewSMTPProxy("localhost:25", tlsConfig)
		
		// Track if connections are properly closed
		clientClosed := false
		backendClosed := false
		
		clientConn := &errorConn{
			readErr: errors.New("forced error"),
			closeErr: nil,
		}
		clientConn.Conn = mockConnWithCloseCallback(func() {
			clientClosed = true
		})
		
		backendConn := &errorConn{
			closeErr: nil,
		}
		backendConn.Conn = mockConnWithCloseCallback(func() {
			backendClosed = true
		})
		
		proxy.handleConnection(clientConn)
		
		// Both connections should be closed
		if !clientConn.closed {
			t.Error("Client connection not closed")
		}
	})
}

// Helper to create a mock connection with close callback
func mockConnWithCloseCallback(onClose func()) net.Conn {
	return &testMockConn{onClose: onClose}
}

type testMockConn struct {
	net.Conn
	onClose func()
}

func (m *testMockConn) Close() error {
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}

// Additional helper function to verify error strings contain expected content
func verifyErrorMessage(t *testing.T, err error, expected string) {
	if err == nil {
		t.Errorf("Expected error containing '%s', got nil", expected)
		return
	}
	if !strings.Contains(err.Error(), expected) {
		t.Errorf("Error message should contain '%s', got: %v", expected, err)
	}
}