package dbproxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// MongoDB Wire Protocol constants
const (
	mongoHeaderSize      = 16
	mongoTLSHandshakeByte = 0x16
	mongoDefaultTimeout   = 10 * time.Second
	
	// MongoDB OpCodes
	opQuery = 2004
	opMsg   = 2013
	opReply = 1
	opInsert = 2002
	opUpdate = 2001
	opDelete = 2006
)

// MongoDBProxyRefactored is an improved version with better structure
type MongoDBProxyRefactored struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
	
	// Connection pooling
	connPool *ConnectionPool
	
	// Metrics
	metrics *ProxyMetrics
}

// ProxyMetrics tracks proxy statistics
type ProxyMetrics struct {
	mu               sync.RWMutex
	totalConnections int64
	activeConnections int64
	bytesIn          int64
	bytesOut         int64
	errors           int64
}

// ConnectionPool manages backend connections
type ConnectionPool struct {
	backend     string
	maxSize     int
	connections chan net.Conn
	mu          sync.Mutex
}

// NewMongoDBProxyRefactored creates a new refactored MongoDB proxy
func NewMongoDBProxyRefactored(backend string, tlsConfig *tls.Config) *MongoDBProxyRefactored {
	return &MongoDBProxyRefactored{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
		connPool:  newConnectionPool(backend, 10),
		metrics:   &ProxyMetrics{},
	}
}

func newConnectionPool(backend string, maxSize int) *ConnectionPool {
	return &ConnectionPool{
		backend:     backend,
		maxSize:     maxSize,
		connections: make(chan net.Conn, maxSize),
	}
}

// Serve starts accepting connections
func (p *MongoDBProxyRefactored) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		
		p.metrics.incrementConnections()
		go p.handleConnection(clientConn)
	}
}

// handleConnection manages a single client connection
func (p *MongoDBProxyRefactored) handleConnection(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		p.metrics.decrementConnections()
	}()

	// Handle TLS if enabled
	clientConn, err := p.handleTLSNegotiation(clientConn)
	if err != nil {
		log.Printf("TLS negotiation failed: %v", err)
		p.metrics.incrementErrors()
		return
	}

	// Connect to backend
	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to backend: %v", err)
		p.metrics.incrementErrors()
		return
	}
	defer backendConn.Close()

	// Start proxying
	if p.EnableTLS {
		p.proxyWithProtocolAwareness(clientConn, backendConn)
	} else {
		p.proxySimple(clientConn, backendConn)
	}
}

// handleTLSNegotiation handles TLS setup if needed
func (p *MongoDBProxyRefactored) handleTLSNegotiation(conn net.Conn) (net.Conn, error) {
	if !p.EnableTLS {
		return conn, nil
	}

	detector := &tlsDetector{conn: conn}
	isTLS, err := detector.detectTLS()
	if err != nil {
		return nil, err
	}

	if isTLS {
		tlsConn := tls.Server(detector, p.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	return detector, nil
}

// tlsDetector wraps a connection to detect and handle TLS
type tlsDetector struct {
	conn      net.Conn
	peeked    []byte
	peekRead  bool
}

func (d *tlsDetector) detectTLS() (bool, error) {
	d.peeked = make([]byte, 1)
	n, err := d.conn.Read(d.peeked)
	if err != nil {
		return false, err
	}
	
	d.peeked = d.peeked[:n]
	return n > 0 && d.peeked[0] == mongoTLSHandshakeByte, nil
}

func (d *tlsDetector) Read(b []byte) (int, error) {
	if !d.peekRead && len(d.peeked) > 0 {
		n := copy(b, d.peeked)
		d.peeked = d.peeked[n:]
		if len(d.peeked) == 0 {
			d.peekRead = true
		}
		return n, nil
	}
	return d.conn.Read(b)
}

func (d *tlsDetector) Write(b []byte) (int, error) {
	return d.conn.Write(b)
}

func (d *tlsDetector) Close() error {
	return d.conn.Close()
}

func (d *tlsDetector) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *tlsDetector) RemoteAddr() net.Addr {
	return d.conn.RemoteAddr()
}

func (d *tlsDetector) SetDeadline(t time.Time) error {
	return d.conn.SetDeadline(t)
}

func (d *tlsDetector) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

func (d *tlsDetector) SetWriteDeadline(t time.Time) error {
	return d.conn.SetWriteDeadline(t)
}

// connectToBackend establishes a connection to the backend
func (p *MongoDBProxyRefactored) connectToBackend() (net.Conn, error) {
	// Try to get from pool first
	select {
	case conn := <-p.connPool.connections:
		// Test if connection is still alive
		if err := conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err == nil {
			conn.SetReadDeadline(time.Time{})
			return conn, nil
		}
		conn.Close()
	default:
	}

	// Create new connection
	return net.DialTimeout("tcp", p.Backend, mongoDefaultTimeout)
}

// proxySimple performs simple TCP proxying
func (p *MongoDBProxyRefactored) proxySimple(client, backend net.Conn) {
	done := make(chan bool, 2)
	
	// Client to backend
	go func() {
		n, _ := io.Copy(backend, client)
		p.metrics.addBytesIn(n)
		done <- true
	}()
	
	// Backend to client
	go func() {
		n, _ := io.Copy(client, backend)
		p.metrics.addBytesOut(n)
		done <- true
	}()
	
	<-done
}

// proxyWithProtocolAwareness performs protocol-aware proxying
func (p *MongoDBProxyRefactored) proxyWithProtocolAwareness(client, backend net.Conn) {
	done := make(chan error, 2)
	
	// Client to backend with protocol parsing
	go p.proxyClientToBackend(client, backend, done)
	
	// Backend to client (simple forwarding)
	go p.proxyBackendToClient(backend, client, done)
	
	<-done
}

// proxyClientToBackend handles client to backend traffic with protocol awareness
func (p *MongoDBProxyRefactored) proxyClientToBackend(client, backend net.Conn, done chan error) {
	reader := &mongoMessageReader{conn: client}
	writer := &mongoMessageWriter{conn: backend}
	
	for {
		msg, err := reader.ReadMessage()
		if err != nil {
			done <- err
			return
		}
		
		// Process message if needed
		if p.EnableTLS {
			msg = p.processClientMessage(msg)
		}
		
		if err := writer.WriteMessage(msg); err != nil {
			done <- err
			return
		}
		
		p.metrics.addBytesIn(int64(len(msg.Header) + len(msg.Body)))
	}
}

// proxyBackendToClient handles backend to client traffic
func (p *MongoDBProxyRefactored) proxyBackendToClient(backend, client net.Conn, done chan error) {
	n, err := io.Copy(client, backend)
	p.metrics.addBytesOut(n)
	done <- err
}

// processClientMessage processes a client message if needed
func (p *MongoDBProxyRefactored) processClientMessage(msg *mongoMessage) *mongoMessage {
	// Check if this is a command that needs modification
	if p.shouldModifyMessage(msg) {
		// Here we could modify the message to add SSL capabilities
		// For now, just return as-is
	}
	return msg
}

// shouldModifyMessage checks if a message needs modification
func (p *MongoDBProxyRefactored) shouldModifyMessage(msg *mongoMessage) bool {
	if !p.EnableTLS {
		return false
	}
	
	// Check for isMaster/hello commands
	return msg.OpCode == opQuery || msg.OpCode == opMsg
}

// mongoMessage represents a MongoDB wire protocol message
type mongoMessage struct {
	Header []byte
	Body   []byte
	OpCode uint32
}

// mongoMessageReader reads MongoDB wire protocol messages
type mongoMessageReader struct {
	conn net.Conn
}

// ReadMessage reads a single MongoDB message
func (r *mongoMessageReader) ReadMessage() (*mongoMessage, error) {
	// Read header
	header := make([]byte, mongoHeaderSize)
	if _, err := io.ReadFull(r.conn, header); err != nil {
		return nil, err
	}
	
	// Parse message length and opcode
	msgLen := binary.LittleEndian.Uint32(header[:4])
	opCode := binary.LittleEndian.Uint32(header[12:16])
	
	// Read body if present
	var body []byte
	if msgLen > mongoHeaderSize {
		body = make([]byte, msgLen-mongoHeaderSize)
		if _, err := io.ReadFull(r.conn, body); err != nil {
			return nil, err
		}
	}
	
	return &mongoMessage{
		Header: header,
		Body:   body,
		OpCode: opCode,
	}, nil
}

// mongoMessageWriter writes MongoDB wire protocol messages
type mongoMessageWriter struct {
	conn net.Conn
}

// WriteMessage writes a MongoDB message
func (w *mongoMessageWriter) WriteMessage(msg *mongoMessage) error {
	if _, err := w.conn.Write(msg.Header); err != nil {
		return err
	}
	
	if len(msg.Body) > 0 {
		if _, err := w.conn.Write(msg.Body); err != nil {
			return err
		}
	}
	
	return nil
}

// Metrics methods
func (m *ProxyMetrics) incrementConnections() {
	m.mu.Lock()
	m.totalConnections++
	m.activeConnections++
	m.mu.Unlock()
}

func (m *ProxyMetrics) decrementConnections() {
	m.mu.Lock()
	m.activeConnections--
	m.mu.Unlock()
}

func (m *ProxyMetrics) incrementErrors() {
	m.mu.Lock()
	m.errors++
	m.mu.Unlock()
}

func (m *ProxyMetrics) addBytesIn(n int64) {
	m.mu.Lock()
	m.bytesIn += n
	m.mu.Unlock()
}

func (m *ProxyMetrics) addBytesOut(n int64) {
	m.mu.Lock()
	m.bytesOut += n
	m.mu.Unlock()
}

// GetStats returns current metrics
func (m *ProxyMetrics) GetStats() map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return map[string]int64{
		"total_connections":  m.totalConnections,
		"active_connections": m.activeConnections,
		"bytes_in":          m.bytesIn,
		"bytes_out":         m.bytesOut,
		"errors":            m.errors,
	}
}