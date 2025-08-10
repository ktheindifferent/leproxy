package dbproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyType represents the type of database proxy
type ProxyType string

const (
	ProxyTypeMySQL      ProxyType = "mysql"
	ProxyTypePostgres   ProxyType = "postgres"
	ProxyTypeMongoDB    ProxyType = "mongodb"
	ProxyTypeRedis      ProxyType = "redis"
	ProxyTypeCassandra  ProxyType = "cassandra"
	ProxyTypeElastic    ProxyType = "elasticsearch"
)

// ConnectionHandler defines the interface for protocol-specific handling
type ConnectionHandler interface {
	// HandleConnection handles a client connection
	HandleConnection(ctx context.Context, client, backend net.Conn) error
	
	// ValidateProtocol validates that the connection speaks the expected protocol
	ValidateProtocol(conn net.Conn) error
	
	// GetDefaultPort returns the default port for this protocol
	GetDefaultPort() int
}

// BaseProxy provides common functionality for all database proxies
type BaseProxy struct {
	// Configuration
	Backend      string
	ListenAddr   string
	ProxyType    ProxyType
	TLSConfig    *tls.Config
	EnableTLS    bool
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	
	// Connection handler for protocol-specific logic
	handler ConnectionHandler
	
	// Connection management
	listener    net.Listener
	connPool    *GenericConnectionPool
	activeConns sync.Map
	
	// Lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	
	// Metrics
	metrics *BaseProxyMetrics
	
	// Configuration options
	maxConnections    int
	connectionTimeout time.Duration
	keepAliveInterval time.Duration
}

// BaseProxyConfig contains configuration for BaseProxy
type BaseProxyConfig struct {
	Backend           string
	ListenAddr        string
	ProxyType         ProxyType
	TLSConfig         *tls.Config
	EnableTLS         bool
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	MaxConnections    int
	ConnectionTimeout time.Duration
	KeepAliveInterval time.Duration
	Handler           ConnectionHandler
}

// NewBaseProxy creates a new base proxy instance
func NewBaseProxy(config *BaseProxyConfig) *BaseProxy {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Set defaults if not provided
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 10 * time.Second
	}
	if config.KeepAliveInterval == 0 {
		config.KeepAliveInterval = 30 * time.Second
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 1000
	}
	
	return &BaseProxy{
		Backend:           config.Backend,
		ListenAddr:        config.ListenAddr,
		ProxyType:         config.ProxyType,
		TLSConfig:         config.TLSConfig,
		EnableTLS:         config.EnableTLS,
		ReadTimeout:       config.ReadTimeout,
		WriteTimeout:      config.WriteTimeout,
		handler:           config.Handler,
		ctx:               ctx,
		cancel:            cancel,
		maxConnections:    config.MaxConnections,
		connectionTimeout: config.ConnectionTimeout,
		keepAliveInterval: config.KeepAliveInterval,
		connPool:          NewGenericConnectionPool(config.Backend, 10),
		metrics:           NewBaseProxyMetrics(),
	}
}

// Start starts the proxy server
func (p *BaseProxy) Start() error {
	listener, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.ListenAddr, err)
	}
	
	p.listener = listener
	
	// Start accepting connections
	p.wg.Add(1)
	go p.acceptLoop()
	
	// Start metrics collection
	p.wg.Add(1)
	go p.collectMetrics()
	
	return nil
}

// Stop stops the proxy server
func (p *BaseProxy) Stop() error {
	// Signal shutdown
	p.cancel()
	
	// Close listener
	if p.listener != nil {
		p.listener.Close()
	}
	
	// Close all active connections
	p.activeConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		return true
	})
	
	// Wait for goroutines to finish
	p.wg.Wait()
	
	// Close connection pool
	p.connPool.Close()
	
	return nil
}

// acceptLoop accepts incoming connections
func (p *BaseProxy) acceptLoop() {
	defer p.wg.Done()
	
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				// Log error and continue
				p.metrics.IncrementErrors()
				continue
			}
		}
		
		// Check connection limit
		if p.metrics.GetActiveConnections() >= int64(p.maxConnections) {
			conn.Close()
			p.metrics.IncrementRejected()
			continue
		}
		
		// Handle connection
		p.wg.Add(1)
		go p.handleClientConnection(conn)
	}
}

// handleClientConnection handles a single client connection
func (p *BaseProxy) handleClientConnection(clientConn net.Conn) {
	defer p.wg.Done()
	
	// Track connection
	connID := p.trackConnection(clientConn)
	defer p.untrackConnection(connID)
	
	// Update metrics
	p.metrics.IncrementConnections()
	defer p.metrics.DecrementActiveConnections()
	
	// Set timeouts
	if p.ReadTimeout > 0 {
		clientConn.SetReadDeadline(time.Now().Add(p.ReadTimeout))
	}
	if p.WriteTimeout > 0 {
		clientConn.SetWriteDeadline(time.Now().Add(p.WriteTimeout))
	}
	
	// Handle TLS if enabled
	if p.EnableTLS {
		tlsConn, err := p.upgradeTLS(clientConn)
		if err != nil {
			p.metrics.IncrementErrors()
			clientConn.Close()
			return
		}
		clientConn = tlsConn
	}
	
	// Validate protocol if handler provides validation
	if p.handler != nil {
		if err := p.handler.ValidateProtocol(clientConn); err != nil {
			p.metrics.IncrementErrors()
			clientConn.Close()
			return
		}
	}
	
	// Connect to backend
	backendConn, err := p.connectToBackend()
	if err != nil {
		p.metrics.IncrementErrors()
		clientConn.Close()
		return
	}
	defer p.returnToPool(backendConn)
	
	// Proxy the connection
	if p.handler != nil {
		// Use protocol-specific handler
		err = p.handler.HandleConnection(p.ctx, clientConn, backendConn)
	} else {
		// Use simple TCP proxying
		err = p.proxyTCP(clientConn, backendConn)
	}
	
	if err != nil {
		p.metrics.IncrementErrors()
	}
}

// upgradeTLS upgrades a connection to TLS
func (p *BaseProxy) upgradeTLS(conn net.Conn) (net.Conn, error) {
	tlsConn := tls.Server(conn, p.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

// connectToBackend establishes a connection to the backend
func (p *BaseProxy) connectToBackend() (net.Conn, error) {
	// Try to get from pool
	conn := p.connPool.Get()
	if conn != nil {
		// Test if connection is alive
		if err := conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err == nil {
			conn.SetReadDeadline(time.Time{})
			return conn, nil
		}
		conn.Close()
	}
	
	// Create new connection
	conn, err := net.DialTimeout("tcp", p.Backend, p.connectionTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to backend %s: %w", p.Backend, err)
	}
	
	// Set keep-alive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(p.keepAliveInterval)
	}
	
	return conn, nil
}

// returnToPool returns a connection to the pool if possible
func (p *BaseProxy) returnToPool(conn net.Conn) {
	if conn == nil {
		return
	}
	
	// Check if connection is still healthy
	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	
	// Try to return to pool
	if !p.connPool.Put(conn) {
		conn.Close()
	}
}

// proxyTCP performs simple TCP proxying
func (p *BaseProxy) proxyTCP(client, backend net.Conn) error {
	errCh := make(chan error, 2)
	
	// Client to backend
	go func() {
		n, err := io.Copy(backend, client)
		p.metrics.AddBytesIn(n)
		errCh <- err
	}()
	
	// Backend to client
	go func() {
		n, err := io.Copy(client, backend)
		p.metrics.AddBytesOut(n)
		errCh <- err
	}()
	
	// Wait for first error or completion
	select {
	case err := <-errCh:
		return err
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// trackConnection tracks an active connection
func (p *BaseProxy) trackConnection(conn net.Conn) string {
	connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())
	p.activeConns.Store(connID, conn)
	return connID
}

// untrackConnection removes a connection from tracking
func (p *BaseProxy) untrackConnection(connID string) {
	p.activeConns.Delete(connID)
}

// collectMetrics periodically collects metrics
func (p *BaseProxy) collectMetrics() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Collect metrics (this could be exported to Prometheus, etc.)
			stats := p.metrics.GetStats()
			_ = stats // Use stats for monitoring/logging
			
		case <-p.ctx.Done():
			return
		}
	}
}

// GetMetrics returns current metrics
func (p *BaseProxy) GetMetrics() map[string]interface{} {
	return p.metrics.GetStats()
}

// BaseProxyMetrics tracks proxy metrics
type BaseProxyMetrics struct {
	totalConnections  int64
	activeConnections int64
	rejectedConnections int64
	bytesIn          int64
	bytesOut         int64
	errors           int64
}

// NewBaseProxyMetrics creates new metrics instance
func NewBaseProxyMetrics() *BaseProxyMetrics {
	return &BaseProxyMetrics{}
}

func (m *BaseProxyMetrics) IncrementConnections() {
	atomic.AddInt64(&m.totalConnections, 1)
	atomic.AddInt64(&m.activeConnections, 1)
}

func (m *BaseProxyMetrics) DecrementActiveConnections() {
	atomic.AddInt64(&m.activeConnections, -1)
}

func (m *BaseProxyMetrics) IncrementRejected() {
	atomic.AddInt64(&m.rejectedConnections, 1)
}

func (m *BaseProxyMetrics) IncrementErrors() {
	atomic.AddInt64(&m.errors, 1)
}

func (m *BaseProxyMetrics) AddBytesIn(n int64) {
	atomic.AddInt64(&m.bytesIn, n)
}

func (m *BaseProxyMetrics) AddBytesOut(n int64) {
	atomic.AddInt64(&m.bytesOut, n)
}

func (m *BaseProxyMetrics) GetActiveConnections() int64 {
	return atomic.LoadInt64(&m.activeConnections)
}

func (m *BaseProxyMetrics) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":    atomic.LoadInt64(&m.totalConnections),
		"active_connections":   atomic.LoadInt64(&m.activeConnections),
		"rejected_connections": atomic.LoadInt64(&m.rejectedConnections),
		"bytes_in":            atomic.LoadInt64(&m.bytesIn),
		"bytes_out":           atomic.LoadInt64(&m.bytesOut),
		"errors":              atomic.LoadInt64(&m.errors),
	}
}

// GenericConnectionPool manages a pool of connections
type GenericConnectionPool struct {
	backend string
	pool    chan net.Conn
	maxSize int
	mu      sync.Mutex
}

// NewGenericConnectionPool creates a new connection pool
func NewGenericConnectionPool(backend string, maxSize int) *GenericConnectionPool {
	return &GenericConnectionPool{
		backend: backend,
		pool:    make(chan net.Conn, maxSize),
		maxSize: maxSize,
	}
}

// Get gets a connection from the pool
func (p *GenericConnectionPool) Get() net.Conn {
	select {
	case conn := <-p.pool:
		return conn
	default:
		return nil
	}
}

// Put returns a connection to the pool
func (p *GenericConnectionPool) Put(conn net.Conn) bool {
	select {
	case p.pool <- conn:
		return true
	default:
		return false
	}
}

// Close closes all connections in the pool
func (p *GenericConnectionPool) Close() {
	close(p.pool)
	for conn := range p.pool {
		conn.Close()
	}
}