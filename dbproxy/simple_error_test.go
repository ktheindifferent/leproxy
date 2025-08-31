package dbproxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// simpleErrorConn is a minimal connection that returns errors
type simpleErrorConn struct {
	closed bool
}

func (c *simpleErrorConn) Read(b []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}
	// Simulate a network error after some delay
	time.Sleep(10 * time.Millisecond)
	return 0, errors.New("simulated read error")
}

func (c *simpleErrorConn) Write(b []byte) (int, error) {
	if c.closed {
		return 0, errors.New("connection closed")
	}
	return len(b), nil
}

func (c *simpleErrorConn) Close() error {
	c.closed = true
	return nil
}

func (c *simpleErrorConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *simpleErrorConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *simpleErrorConn) SetDeadline(t time.Time) error     { return nil }
func (c *simpleErrorConn) SetReadDeadline(t time.Time) error { return nil }
func (c *simpleErrorConn) SetWriteDeadline(t time.Time) error { return nil }

// Test that io.Copy errors are properly handled and logged
func TestSimpleErrorHandling(t *testing.T) {
	tlsConfig := &tls.Config{}

	t.Run("SMTP Error Handling", func(t *testing.T) {
		proxy := NewSMTPProxy("localhost:25", tlsConfig)
		conn := &simpleErrorConn{}
		
		// This should complete without panic and log the error
		proxy.handleConnection(conn)
		
		if !conn.closed {
			t.Error("Connection should be closed after error")
		}
	})

	t.Run("Redis Error Handling", func(t *testing.T) {
		proxy := NewRedisProxy("localhost:6379", tlsConfig)
		conn := &simpleErrorConn{}
		
		// This should complete without panic and log the error
		proxy.handleConnection(conn)
		
		if !conn.closed {
			t.Error("Connection should be closed after error")
		}
	})

	t.Run("MSSQL Error Handling", func(t *testing.T) {
		proxy := NewMSSQLProxy("localhost:1433", tlsConfig)
		conn := &simpleErrorConn{}
		
		// This should complete without panic and log the error
		proxy.handleConnection(conn)
		
		if !conn.closed {
			t.Error("Connection should be closed after error")
		}
	})

	t.Run("MongoDB Error Handling", func(t *testing.T) {
		proxy := NewMongoDBProxy("localhost:27017", tlsConfig)
		conn := &simpleErrorConn{}
		
		// This should complete without panic and log the error
		proxy.handleConnection(conn)
		
		if !conn.closed {
			t.Error("Connection should be closed after error")
		}
	})
}