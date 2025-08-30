package dbproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RedisProxy handles Redis protocol proxying with optional TLS support
type RedisProxy struct {
	*BaseProxy
}

// NewRedisProxy creates a new Redis proxy instance
func NewRedisProxy(backend string, tlsConfig *tls.Config) *RedisProxy {
	handler := &redisHandler{}
	base := NewBaseProxy(backend, tlsConfig, handler)
	proxy := &RedisProxy{
		BaseProxy: base,
	}
	handler.proxy = proxy
	return proxy
}

// redisHandler implements ProxyHandler for Redis
type redisHandler struct {
	proxy *RedisProxy
}

func (h *redisHandler) GetProtocolName() string {
	return "Redis"
}

func (h *redisHandler) HandleProtocolNegotiation(ctx context.Context, clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	// Handle TLS if enabled
	if h.proxy.EnableTLS {
		return h.handleTLSNegotiation(ctx, clientConn, backendConn)
	}
	return clientConn, backendConn, nil
}

func (h *redisHandler) handleTLSNegotiation(ctx context.Context, clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
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
	
	// Check if client sends STARTTLS command
	clientReader := bufio.NewReader(clientConn)
	
	// Set read deadline for peeking
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to set read deadline: %w", err)
	}
	
	// Peek at the first command
	firstLine, err := clientReader.Peek(64)
	
	// Reset deadline
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to reset read deadline: %w", err)
	}
	
	if err == nil && h.isStartTLSCommand(firstLine) {
		// Read the full STARTTLS command
		_, err := clientReader.ReadString('\n')
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read STARTTLS command: %w", err)
		}
		
		// Send +OK response
		if err := h.proxy.writeWithTimeout(clientConn, []byte("+OK\r\n"), 5*time.Second); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to send STARTTLS response: %w", err)
		}
		
		// Upgrade to TLS
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
		
		// Create new reader for TLS connection
		clientReader = bufio.NewReader(clientConn)
	} else {
		// No STARTTLS, but we can still offer TLS wrapper if client connects with TLS directly
		// Try to detect if this is already a TLS handshake
		if len(firstLine) > 0 && firstLine[0] == 0x16 {
			// Looks like TLS handshake
			tlsConn := tls.Server(clientConn, h.proxy.TLSConfig)
			// Set handshake timeout
			if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to set TLS deadline: %w", err)
			}
			if err := tlsConn.Handshake(); err != nil {
				// Not a TLS connection, continue without TLS
				log.Printf("TLS handshake failed, continuing without TLS: %v", err)
			} else {
				// Reset deadline after handshake
				if err := tlsConn.SetDeadline(time.Time{}); err != nil {
					return clientConn, backendConn, fmt.Errorf("failed to reset TLS deadline: %w", err)
				}
				clientConn = tlsConn
			}
		}
		// If we have buffered data, we need to create a connection that includes it
		if clientReader.Buffered() > 0 {
			buffered, _ := clientReader.Peek(clientReader.Buffered())
			clientConn = NewPrefixConn(clientConn, buffered)
		}
	}
	
	return clientConn, backendConn, nil
}

func (h *redisHandler) isStartTLSCommand(data []byte) bool {
	cmd := strings.ToUpper(string(data))
	return strings.Contains(cmd, "STARTTLS") || strings.Contains(cmd, "*1\r\n$8\r\nSTARTTLS")
}

func (p *RedisProxy) writeWithTimeout(conn net.Conn, data []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err := conn.Write(data)
	if resetErr := conn.SetWriteDeadline(time.Time{}); resetErr != nil {
		return resetErr
	}
	return err
}

// RedisConnectionPool manages a pool of backend connections for Redis
type RedisConnectionPool struct {
	mu          sync.RWMutex
	connections map[string]*redisPooledConn
	maxConns    int
	backend     string
	timeout     time.Duration
	pingTicker  *time.Ticker
	stopPing    chan struct{}
	wg          sync.WaitGroup
}

type redisPooledConn struct {
	conn     net.Conn
	lastUsed time.Time
	inUse    atomic.Bool
}

// NewRedisConnectionPool creates a new connection pool with health checking
func NewRedisConnectionPool(backend string, maxConns int, timeout time.Duration) *RedisConnectionPool {
	pool := &RedisConnectionPool{
		connections: make(map[string]*redisPooledConn),
		maxConns:    maxConns,
		backend:     backend,
		timeout:     timeout,
		pingTicker:  time.NewTicker(30 * time.Second),
		stopPing:    make(chan struct{}),
	}
	
	// Start background health checker
	pool.wg.Add(1)
	go pool.healthChecker()
	
	return pool
}

// healthChecker periodically pings connections to keep them alive
func (p *RedisConnectionPool) healthChecker() {
	defer p.wg.Done()
	
	for {
		select {
		case <-p.stopPing:
			return
		case <-p.pingTicker.C:
			p.pingConnections()
		}
	}
}

// pingConnections sends PING to idle connections
func (p *RedisConnectionPool) pingConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	for id, pc := range p.connections {
		if !pc.inUse.Load() {
			// Send PING command
			if err := pc.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				pc.conn.Close()
				delete(p.connections, id)
				continue
			}
			
			if _, err := pc.conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
				pc.conn.Close()
				delete(p.connections, id)
				continue
			}
			
			// Read PONG response
			if err := pc.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				pc.conn.Close()
				delete(p.connections, id)
				continue
			}
			
			buf := make([]byte, 7) // "+PONG\r\n"
			if _, err := pc.conn.Read(buf); err != nil {
				pc.conn.Close()
				delete(p.connections, id)
			}
			
			// Reset deadlines
			pc.conn.SetDeadline(time.Time{})
		}
	}
}

// GetConnection gets or creates a connection from the pool
func (p *RedisConnectionPool) GetConnection(ctx context.Context) (net.Conn, error) {
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
		pc := &redisPooledConn{
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
func (p *RedisConnectionPool) ReleaseConnection(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	id := fmt.Sprintf("%p", conn)
	if pc, ok := p.connections[id]; ok {
		pc.inUse.Store(false)
		pc.lastUsed = time.Now()
	}
}

// Close closes all connections in the pool
func (p *RedisConnectionPool) Close() error {
	// Stop health checker
	close(p.stopPing)
	p.pingTicker.Stop()
	p.wg.Wait()
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	for _, pc := range p.connections {
		pc.conn.Close()
	}
	p.connections = make(map[string]*redisPooledConn)
	return nil
}