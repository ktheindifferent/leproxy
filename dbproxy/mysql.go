package dbproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MySQLProxy handles MySQL protocol proxying with optional TLS support
type MySQLProxy struct {
	*BaseProxy
}

// NewMySQLProxy creates a new MySQL proxy instance
func NewMySQLProxy(backend string, tlsConfig *tls.Config) *MySQLProxy {
	handler := &mysqlHandler{}
	base := NewBaseProxy(backend, tlsConfig, handler)
	proxy := &MySQLProxy{
		BaseProxy: base,
	}
	handler.proxy = proxy
	return proxy
}

// mysqlHandler implements ProxyHandler for MySQL
type mysqlHandler struct {
	proxy *MySQLProxy
}

func (h *mysqlHandler) GetProtocolName() string {
	return "MySQL"
}

func (h *mysqlHandler) HandleProtocolNegotiation(ctx context.Context, clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	// Create a channel to signal completion
	done := make(chan struct{})
	defer close(done)
	
	// Monitor context cancellation
	go func() {
		select {
		case <-ctx.Done():
			clientConn.Close()
			backendConn.Close()
		case <-done:
		}
	}()
	
	// Set read timeout for handshake
	if err := backendConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to set read deadline: %w", err)
	}
	
	// MySQL initial handshake from server
	handshakeBuf := make([]byte, 4096)
	n, err := backendConn.Read(handshakeBuf)
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read MySQL handshake: %w", err)
	}
	
	// Reset deadline after read
	if err := backendConn.SetReadDeadline(time.Time{}); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to reset read deadline: %w", err)
	}
	
	// Check if server supports SSL (capability flag 0x0800)
	if h.proxy.EnableTLS && h.proxy.supportsSSL(handshakeBuf[:n]) {
		// Send modified handshake to client with SSL capability
		if err := h.proxy.writeWithTimeout(clientConn, handshakeBuf[:n], 10*time.Second); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to send handshake to client: %w", err)
		}
		
		// Wait for SSL request packet from client
		sslReqBuf := make([]byte, 36)
		if err := h.proxy.readWithTimeout(clientConn, sslReqBuf, 10*time.Second); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read SSL request: %w", err)
		}
		
		// Check if client requested SSL
		if h.proxy.isSSLRequest(sslReqBuf) {
			// Upgrade client connection to TLS
			tlsConn := tls.Server(clientConn, h.proxy.TLSConfig)
			// Set handshake timeout
			if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to set TLS deadline: %w", err)
			}
			if err := tlsConn.Handshake(); err != nil {
				return clientConn, backendConn, fmt.Errorf("TLS handshake failed: %w", err)
			}
			// Reset deadline after handshake
			if err := tlsConn.SetDeadline(time.Time{}); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to reset TLS deadline: %w", err)
			}
			clientConn = tlsConn
			
			// Forward SSL request to backend
			if err := h.proxy.writeWithTimeout(backendConn, sslReqBuf, 10*time.Second); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward SSL request: %w", err)
			}
		}
	} else {
		// No TLS, just forward the handshake
		if err := h.proxy.writeWithTimeout(clientConn, handshakeBuf[:n], 10*time.Second); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to send handshake to client: %w", err)
		}
	}
	
	return clientConn, backendConn, nil
}

func (p *MySQLProxy) readWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := conn.Read(buf)
	if resetErr := conn.SetReadDeadline(time.Time{}); resetErr != nil {
		return resetErr
	}
	return err
}

func (p *MySQLProxy) writeWithTimeout(conn net.Conn, data []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := conn.Write(data)
	if resetErr := conn.SetWriteDeadline(time.Time{}); resetErr != nil {
		return resetErr
	}
	return err
}

func (p *MySQLProxy) supportsSSL(handshake []byte) bool {
	// MySQL handshake packet structure:
	// 4 bytes: packet header
	// 1 byte: protocol version
	// null-terminated server version string
	// 4 bytes: connection id
	// 8 bytes: auth plugin data part 1
	// 1 byte: filler
	// 2 bytes: capability flags (lower)
	
	if len(handshake) < 30 {
		return false
	}

	// Find null terminator after version string
	versionEnd := bytes.IndexByte(handshake[5:], 0)
	if versionEnd == -1 {
		return false
	}

	capabilityOffset := 5 + versionEnd + 1 + 4 + 8 + 1
	if len(handshake) < capabilityOffset+2 {
		return false
	}

	// Read capability flags (little-endian)
	capabilities := binary.LittleEndian.Uint16(handshake[capabilityOffset:])
	
	// CLIENT_SSL flag is 0x0800
	return (capabilities & 0x0800) != 0
}

func (p *MySQLProxy) isSSLRequest(packet []byte) bool {
	// SSL request packet has capability flags with CLIENT_SSL set
	if len(packet) < 8 {
		return false
	}

	// Read capability flags from packet (after 4-byte header)
	capabilities := binary.LittleEndian.Uint32(packet[4:8])
	
	// CLIENT_SSL flag is 0x0800
	return (capabilities & 0x0800) != 0
}

// MySQLConnectionPool manages a pool of backend connections for MySQL
type MySQLConnectionPool struct {
	mu          sync.RWMutex
	connections map[string]*mysqlPooledConn
	maxConns    int
	backend     string
	timeout     time.Duration
}

type mysqlPooledConn struct {
	conn     net.Conn
	lastUsed time.Time
	inUse    atomic.Bool
}

// NewMySQLConnectionPool creates a new connection pool
func NewMySQLConnectionPool(backend string, maxConns int, timeout time.Duration) *MySQLConnectionPool {
	return &MySQLConnectionPool{
		connections: make(map[string]*mysqlPooledConn),
		maxConns:    maxConns,
		backend:     backend,
		timeout:     timeout,
	}
}

// GetConnection gets or creates a connection from the pool
func (p *MySQLConnectionPool) GetConnection(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Try to find an idle connection
	for id, pc := range p.connections {
		if !pc.inUse.Load() && time.Since(pc.lastUsed) < p.timeout {
			pc.inUse.Store(true)
			pc.lastUsed = time.Now()
			return pc.conn, nil
		}
		// Remove stale connections
		if time.Since(pc.lastUsed) >= p.timeout {
			pc.conn.Close()
			delete(p.connections, id)
		}
	}
	
	// Create new connection if under limit
	if len(p.connections) < p.maxConns {
		d := &net.Dialer{
			Timeout: 10 * time.Second,
		}
		conn, err := d.DialContext(ctx, "tcp", p.backend)
		if err != nil {
			return nil, err
		}
		pc := &mysqlPooledConn{
			conn:     conn,
			lastUsed: time.Now(),
		}
		pc.inUse.Store(true)
		p.connections[fmt.Sprintf("%p", conn)] = pc
		return conn, nil
	}
	
	return nil, fmt.Errorf("connection pool exhausted")
}

// ReleaseConnection returns a connection to the pool
func (p *MySQLConnectionPool) ReleaseConnection(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	id := fmt.Sprintf("%p", conn)
	if pc, ok := p.connections[id]; ok {
		pc.inUse.Store(false)
		pc.lastUsed = time.Now()
	}
}

// Close closes all connections in the pool
func (p *MySQLConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	for _, pc := range p.connections {
		pc.conn.Close()
	}
	p.connections = make(map[string]*mysqlPooledConn)
	return nil
}