package dbproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
	
	"github.com/artyom/leproxy/internal/config"
	// "github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/metrics"
	"github.com/artyom/leproxy/internal/safegoroutine"
)

const (
	DefaultConnectTimeout    = 10 * time.Second
	DefaultReadTimeout       = 30 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 5 * time.Minute
	DefaultKeepaliveInterval = 30 * time.Second
	DefaultBufferSize        = 32 * 1024 // 32KB
	TLSHandshakeByte         = 0x16
)

type ProxyHandler interface {
	HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error)
	GetProtocolName() string
}

type BaseProxy struct {
	Backend        string
	TLSConfig      *tls.Config
	EnableTLS      bool
	Handler        ProxyHandler
	TimeoutConfig  *config.ProxyTimeoutConfig
	timeoutMetrics *TimeoutMetrics
	connTracker    interface{} // Will be set by proxy package
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	listener       net.Listener
	listenerMu     sync.RWMutex
	closed         atomic.Bool
	proxyType      string // Type as string to avoid import cycle
}

// TimeoutMetrics tracks timeout-related metrics
type TimeoutMetrics struct {
	ReadTimeouts  atomic.Uint64
	WriteTimeouts atomic.Uint64
	IdleTimeouts  atomic.Uint64
	TotalBytes    atomic.Uint64
	Retries       atomic.Uint64
}

func NewBaseProxy(backend string, tlsConfig *tls.Config, handler ProxyHandler) *BaseProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &BaseProxy{
		Backend:        backend,
		TLSConfig:      tlsConfig,
		EnableTLS:      tlsConfig != nil,
		Handler:        handler,
		TimeoutConfig:  defaultTimeoutConfig(),
		timeoutMetrics: &TimeoutMetrics{},
		connTracker:    nil, // Will be set by caller
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

// NewBaseProxyWithTimeout creates a new BaseProxy with custom timeout configuration
func NewBaseProxyWithTimeout(backend string, tlsConfig *tls.Config, handler ProxyHandler, timeoutConfig *config.ProxyTimeoutConfig) *BaseProxy {
	if timeoutConfig == nil {
		timeoutConfig = defaultTimeoutConfig()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &BaseProxy{
		Backend:        backend,
		TLSConfig:      tlsConfig,
		EnableTLS:      tlsConfig != nil,
		Handler:        handler,
		TimeoutConfig:  timeoutConfig,
		timeoutMetrics: &TimeoutMetrics{},
		connTracker:    nil, // Will be set by caller
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

func defaultTimeoutConfig() *config.ProxyTimeoutConfig {
	return &config.ProxyTimeoutConfig{
		ConnectTimeout:           config.Duration(DefaultConnectTimeout),
		ReadTimeout:              config.Duration(DefaultReadTimeout),
		WriteTimeout:             config.Duration(DefaultWriteTimeout),
		IdleTimeout:              config.Duration(DefaultIdleTimeout),
		KeepaliveInterval:        config.Duration(DefaultKeepaliveInterval),
		EnableKeepalive:          true,
		BufferSize:               DefaultBufferSize,
		EnableExponentialBackoff: true,
		MaxRetries:               3,
		RetryDelay:               config.Duration(time.Second),
	}
}

func (p *BaseProxy) Serve(listener net.Listener) error {
	p.listenerMu.Lock()
	p.listener = listener
	p.listenerMu.Unlock()
	
	for {
		// Check if we're shutting down
		select {
		case <-p.shutdownCtx.Done():
			return fmt.Errorf("proxy shutting down")
		default:
		}
		
		clientConn, err := listener.Accept()
		if err != nil {
			// Check if this is due to listener being closed
			if p.closed.Load() {
				return nil
			}
			// Check for temporary errors
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// logger.Warn("Temporary accept error", map[string]interface{}{
				// 	"error": err,
				// 	"protocol": p.Handler.GetProtocolName(),
				// })
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		
		safegoroutine.Go(fmt.Sprintf("%s-handler-%s", p.Handler.GetProtocolName(), clientConn.RemoteAddr()), func() {
			p.handleConnection(clientConn)
		})
	}
}

func (p *BaseProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to %s backend %s: %v", 
			p.Handler.GetProtocolName(), p.Backend, err)
		return
	}
	defer backendConn.Close()

	clientConn, backendConn, err = p.Handler.HandleProtocolNegotiation(clientConn, backendConn)
	if err != nil {
		log.Printf("Protocol negotiation failed for %s: %v", 
			p.Handler.GetProtocolName(), err)
		return
	}

	p.proxyConnections(clientConn, backendConn)
}

func (p *BaseProxy) connectToBackend() (net.Conn, error) {
	timeout := time.Duration(p.TimeoutConfig.ConnectTimeout)
	if timeout == 0 {
		timeout = DefaultConnectTimeout
	}
	
	conn, err := net.DialTimeout("tcp", p.Backend, timeout)
	if err != nil {
		return nil, err
	}
	
	// Configure TCP keepalive if enabled
	if p.TimeoutConfig.EnableKeepalive {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(time.Duration(p.TimeoutConfig.KeepaliveInterval))
		}
	}
	
	return conn, nil
}

func (p *BaseProxy) proxyConnections(clientConn, backendConn net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Copy data with timeout handling
	copyWithTimeout := func(dst, src net.Conn, direction string) {
		defer wg.Done()
		
		err := p.copyDataWithTimeout(ctx, dst, src, direction)
		if err != nil && err != io.EOF && err != context.Canceled {
			log.Printf("%s proxy %s error: %v",
				p.Handler.GetProtocolName(), direction, err)
		}
		
		// Signal the other goroutine to stop
		cancel()
	}
	
	safegoroutine.GoWithContext(ctx, fmt.Sprintf("%s-copy-client-backend", p.Handler.GetProtocolName()), func() {
		copyWithTimeout(backendConn, clientConn, "client->backend")
	})
	safegoroutine.GoWithContext(ctx, fmt.Sprintf("%s-copy-backend-client", p.Handler.GetProtocolName()), func() {
		copyWithTimeout(clientConn, backendConn, "backend->client")
	})
	
	// Wait for both goroutines to complete
	wg.Wait()
}

// copyDataWithTimeout performs data copying with timeout and retry logic
func (p *BaseProxy) copyDataWithTimeout(ctx context.Context, dst, src net.Conn, direction string) error {
	bufferSize := p.TimeoutConfig.BufferSize
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	
	buffer := make([]byte, bufferSize)
	idleTimeout := time.Duration(p.TimeoutConfig.IdleTimeout)
	readTimeout := time.Duration(p.TimeoutConfig.ReadTimeout)
	writeTimeout := time.Duration(p.TimeoutConfig.WriteTimeout)
	
	var (
		totalBytes   int64
		retryCount   int
		retryDelay   = time.Duration(p.TimeoutConfig.RetryDelay)
		lastActivity = time.Now()
	)
	
	for {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Set read deadline
		if readTimeout > 0 {
			src.SetReadDeadline(time.Now().Add(readTimeout))
		}
		
		// Read from source
		n, readErr := src.Read(buffer)
		
		if n > 0 {
			// Set write deadline
			if writeTimeout > 0 {
				dst.SetWriteDeadline(time.Now().Add(writeTimeout))
			}
			
			// Write to destination
			written := 0
			for written < n {
				w, writeErr := dst.Write(buffer[written:n])
				if writeErr != nil {
					if p.shouldRetry(writeErr, retryCount) {
						p.timeoutMetrics.Retries.Add(1)
						retryCount++
						time.Sleep(p.calculateBackoff(retryCount, retryDelay))
						continue
					}
					
					// Track timeout metrics
					if isTimeout(writeErr) {
						p.timeoutMetrics.WriteTimeouts.Add(1)
						metrics.RecordTimeout(p.Handler.GetProtocolName(), "write", direction)
					}
					return writeErr
				}
				written += w
			}
			
			totalBytes += int64(n)
			p.timeoutMetrics.TotalBytes.Add(uint64(n))
			lastActivity = time.Now()
			retryCount = 0 // Reset retry count on successful operation
		}
		
		// Check for idle timeout
		if idleTimeout > 0 && time.Since(lastActivity) > idleTimeout {
			p.timeoutMetrics.IdleTimeouts.Add(1)
			metrics.RecordTimeout(p.Handler.GetProtocolName(), "idle", direction)
			return fmt.Errorf("connection idle timeout exceeded")
		}
		
		if readErr != nil {
			if readErr == io.EOF {
				return nil // Normal termination
			}
			
			if p.shouldRetry(readErr, retryCount) {
				p.timeoutMetrics.Retries.Add(1)
				retryCount++
				time.Sleep(p.calculateBackoff(retryCount, retryDelay))
				continue
			}
			
			// Track timeout metrics
			if isTimeout(readErr) {
				p.timeoutMetrics.ReadTimeouts.Add(1)
				metrics.RecordTimeout(p.Handler.GetProtocolName(), "read", direction)
			}
			
			return readErr
		}
	}
}

// shouldRetry determines if an error is retryable
func (p *BaseProxy) shouldRetry(err error, retryCount int) bool {
	if !p.TimeoutConfig.EnableExponentialBackoff {
		return false
	}
	
	if retryCount >= p.TimeoutConfig.MaxRetries {
		return false
	}
	
	// Check if it's a temporary network error
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary()
	}
	
	return false
}

// calculateBackoff calculates the backoff delay with exponential increase
func (p *BaseProxy) calculateBackoff(retryCount int, baseDelay time.Duration) time.Duration {
	if !p.TimeoutConfig.EnableExponentialBackoff {
		return baseDelay
	}
	
	// Exponential backoff: delay * 2^(retryCount-1)
	delay := baseDelay
	for i := 1; i < retryCount; i++ {
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second // Cap at 30 seconds
			break
		}
	}
	
	return delay
}

// isTimeout checks if an error is a timeout error
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	
	return false
}

// GetTimeoutMetrics returns current timeout metrics
func (p *BaseProxy) GetTimeoutMetrics() map[string]uint64 {
	return map[string]uint64{
		"read_timeouts":  p.timeoutMetrics.ReadTimeouts.Load(),
		"write_timeouts": p.timeoutMetrics.WriteTimeouts.Load(),
		"idle_timeouts":  p.timeoutMetrics.IdleTimeouts.Load(),
		"total_bytes":    p.timeoutMetrics.TotalBytes.Load(),
		"retries":        p.timeoutMetrics.Retries.Load(),
	}
}

// SetProxyType sets the proxy type for metrics and tracking
func (p *BaseProxy) SetProxyType(proxyType string) {
	p.proxyType = proxyType
}

// SetConnectionTracker sets a custom connection tracker
func (p *BaseProxy) SetConnectionTracker(tracker interface{}) {
	if tracker != nil {
		p.connTracker = tracker
	}
}

// IsHealthy checks if the proxy is healthy
func (p *BaseProxy) IsHealthy() bool {
	return !p.closed.Load()
}

// GracefulShutdown performs a graceful shutdown of the proxy
func (p *BaseProxy) GracefulShutdown(timeout time.Duration) error {
	if p.closed.Load() {
		return fmt.Errorf("proxy already closed")
	}
	
	p.closed.Store(true)
	// logger.Info("Starting graceful shutdown", map[string]interface{}{
	// 	"protocol": p.Handler.GetProtocolName(),
	// })
	
	// Close the listener to stop accepting new connections
	p.listenerMu.Lock()
	listener := p.listener
	p.listenerMu.Unlock()
	
	if listener != nil {
		if err := listener.Close(); err != nil {
			// logger.Warn("Error closing listener", map[string]interface{}{
			// 	"error": err,
			// })
		}
	}
	
	// Cancel the shutdown context to signal all goroutines
	p.shutdownCancel()
	
	// Wait for timeout
	time.Sleep(timeout)
	
	return nil
}

// Close immediately closes the proxy without graceful shutdown
func (p *BaseProxy) Close() error {
	return p.GracefulShutdown(1 * time.Second)
}

func (p *BaseProxy) UpgradeToTLS(conn net.Conn) (*tls.Conn, error) {
	if p.TLSConfig == nil {
		return nil, fmt.Errorf("TLS not configured")
	}
	
	tlsConn := tls.Server(conn, p.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	
	return tlsConn, nil
}

func ReadBytes(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func IsTLSHandshake(data []byte) bool {
	return len(data) > 0 && data[0] == TLSHandshakeByte
}

type PrefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

func NewPrefixConn(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{
		Conn:   conn,
		prefix: prefix,
		offset: 0,
	}
}

func (c *PrefixConn) Read(b []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(b, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}