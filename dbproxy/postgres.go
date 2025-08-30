// Package dbproxy provides TLS proxy support for various database protocols
package dbproxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PostgresProxy handles PostgreSQL protocol proxying with optional TLS support
type PostgresProxy struct {
	*BaseProxy
}

// NewPostgresProxy creates a new PostgreSQL proxy instance
func NewPostgresProxy(backend string, tlsConfig *tls.Config) *PostgresProxy {
	handler := &postgresHandler{}
	base := NewBaseProxy(backend, tlsConfig, handler)
	proxy := &PostgresProxy{
		BaseProxy: base,
	}
	handler.proxy = proxy
	return proxy
}

// postgresHandler implements ProxyHandler for PostgreSQL
type postgresHandler struct {
	proxy *PostgresProxy
}

func (h *postgresHandler) GetProtocolName() string {
	return "PostgreSQL"
}

func (h *postgresHandler) HandleProtocolNegotiation(ctx context.Context, clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	if h.proxy.EnableTLS {
		return h.proxy.handleSSLNegotiation(ctx, clientConn, backendConn)
	}
	return clientConn, backendConn, nil
}

// handleSSLNegotiation manages the PostgreSQL SSL negotiation protocol
// It intercepts the SSLRequest packet and establishes TLS connections when requested
func (p *PostgresProxy) handleSSLNegotiation(ctx context.Context, clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
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
	// Set read timeout for SSL negotiation
	if err := clientConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to set read deadline: %w", err)
	}
	
	// Read the initial packet which might be an SSL request
	buf := make([]byte, 8)
	n, err := clientConn.Read(buf)
	
	// Reset deadline after read
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to reset read deadline: %w", err)
	}
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read SSL request: %w", err)
	}

	// Check if this is an SSL request packet (80877103 in network byte order)
	if n == 8 && isSSLRequest(buf) {
		if _, err := backendConn.Write(buf); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward SSL request to backend: %w", err)
		}

		response := make([]byte, 1)
		if _, err := backendConn.Read(response); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read SSL response from backend: %w", err)
		}

		if response[0] == 'S' {
			if _, err := clientConn.Write([]byte{'S'}); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to send SSL confirmation to client: %w", err)
			}

			tlsClient := tls.Server(clientConn, p.TLSConfig)
			// Set handshake timeout
			if err := tlsClient.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to set TLS deadline: %w", err)
			}
			if err := tlsClient.Handshake(); err != nil {
				return clientConn, backendConn, fmt.Errorf("TLS handshake with client failed: %w", err)
			}
			// Reset deadline after handshake
			if err := tlsClient.SetDeadline(time.Time{}); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to reset TLS deadline: %w", err)
			}
			clientConn = tlsClient

			tlsBackend := tls.Client(backendConn, &tls.Config{
				InsecureSkipVerify: true,
			})
			// Set handshake timeout
			if err := tlsBackend.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to set backend TLS deadline: %w", err)
			}
			if err := tlsBackend.Handshake(); err != nil {
				return clientConn, backendConn, fmt.Errorf("TLS handshake with backend failed: %w", err)
			}
			// Reset deadline after handshake
			if err := tlsBackend.SetDeadline(time.Time{}); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to reset backend TLS deadline: %w", err)
			}
			backendConn = tlsBackend
		} else {
			if _, err := clientConn.Write(response); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward SSL response: %w", err)
			}
		}
	} else {
		if _, err := backendConn.Write(buf[:n]); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward initial packet: %w", err)
		}
	}

	return clientConn, backendConn, nil
}

// ConnectionPool manages a pool of backend connections for PostgreSQL
type PostgresConnectionPool struct {
	mu          sync.RWMutex
	connections map[string]*postgresPooledConn
	maxConns    int
	backend     string
	timeout     time.Duration
}

type postgresPooledConn struct {
	conn     net.Conn
	lastUsed time.Time
	inUse    atomic.Bool
}

// NewPostgresConnectionPool creates a new connection pool
func NewPostgresConnectionPool(backend string, maxConns int, timeout time.Duration) *PostgresConnectionPool {
	return &PostgresConnectionPool{
		connections: make(map[string]*postgresPooledConn),
		maxConns:    maxConns,
		backend:     backend,
		timeout:     timeout,
	}
}

// GetConnection gets or creates a connection from the pool
func (p *PostgresConnectionPool) GetConnection(ctx context.Context) (net.Conn, error) {
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
		pc := &postgresPooledConn{
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
func (p *PostgresConnectionPool) ReleaseConnection(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	id := fmt.Sprintf("%p", conn)
	if pc, ok := p.connections[id]; ok {
		pc.inUse.Store(false)
		pc.lastUsed = time.Now()
	}
}

// Close closes all connections in the pool
func (p *PostgresConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	for _, pc := range p.connections {
		pc.conn.Close()
	}
	p.connections = make(map[string]*postgresPooledConn)
	return nil
}

const postgresSSLRequestCode = 80877103

func isSSLRequest(buf []byte) bool {
	if len(buf) < 8 {
		return false
	}
	
	length := binary.BigEndian.Uint32(buf[:4])
	if length != 8 {
		return false
	}
	
	code := binary.BigEndian.Uint32(buf[4:8])
	return code == postgresSSLRequestCode
}