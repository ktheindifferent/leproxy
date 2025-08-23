package websocket

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/artyom/leproxy/internal/metrics"
	"github.com/artyom/leproxy/internal/ratelimit"
)

type WSProxy struct {
	target      *url.URL
	tlsConfig   *tls.Config
	dialTimeout time.Duration
	bufferSize  int
	
	// Timeouts and limits
	idleTimeout      time.Duration
	maxMessageSize   int64
	pingInterval     time.Duration
	pongTimeout      time.Duration
	maxConnPerIP     int
	
	// Connection tracking
	connTracker *ratelimit.ConnectionTracker
	limiter     *ratelimit.Limiter
	
	// Statistics
	stats struct {
		activeConnections int64
		totalConnections  int64
		bytesTransferred  int64
		mu                sync.RWMutex
	}
	
	// Metrics
	wsMetrics *websocketMetrics
}

type Config struct {
	Target         string
	TLSConfig      *tls.Config
	DialTimeout    time.Duration
	BufferSize     int
	IdleTimeout    time.Duration
	MaxMessageSize int64
	PingInterval   time.Duration
	PongTimeout    time.Duration
	MaxConnPerIP   int
	RateLimiter    *ratelimit.Limiter
}

func New(cfg Config) (*WSProxy, error) {
	target, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 32 * 1024 // 32KB
	}
	
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = 10 * 1024 * 1024 // 10MB
	}
	
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = 30 * time.Second
	}
	
	if cfg.PongTimeout <= 0 {
		cfg.PongTimeout = 10 * time.Second
	}
	
	if cfg.MaxConnPerIP <= 0 {
		cfg.MaxConnPerIP = 100
	}
	
	wp := &WSProxy{
		target:         target,
		tlsConfig:      cfg.TLSConfig,
		dialTimeout:    cfg.DialTimeout,
		bufferSize:     cfg.BufferSize,
		idleTimeout:    cfg.IdleTimeout,
		maxMessageSize: cfg.MaxMessageSize,
		pingInterval:   cfg.PingInterval,
		pongTimeout:    cfg.PongTimeout,
		maxConnPerIP:   cfg.MaxConnPerIP,
		limiter:        cfg.RateLimiter,
		connTracker:    ratelimit.NewConnectionTracker(cfg.MaxConnPerIP),
		wsMetrics:      newWebsocketMetrics(),
	}
	
	return wp, nil
}

func (wp *WSProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketRequest(r) {
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
		return
	}
	
	// Get client IP
	clientIP := getClientIP(r)
	
	// Check rate limiting
	if wp.limiter != nil && !wp.limiter.Allow(clientIP) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		wp.wsMetrics.recordRateLimited(clientIP)
		return
	}
	
	// Check connection limit per IP
	if !wp.connTracker.Add(clientIP) {
		http.Error(w, "Too Many Connections", http.StatusTooManyRequests)
		wp.wsMetrics.recordConnectionLimited(clientIP)
		return
	}
	defer wp.connTracker.Remove(clientIP)
	
	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}
	
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()
	
	// Connect to backend
	backendConn, err := wp.connectToBackend(r)
	if err != nil {
		wp.sendErrorResponse(clientConn, http.StatusBadGateway, "Failed to connect to backend")
		return
	}
	defer backendConn.Close()
	
	// Forward the initial HTTP request
	if err := wp.forwardRequest(backendConn, r); err != nil {
		wp.sendErrorResponse(clientConn, http.StatusBadGateway, "Failed to forward request")
		return
	}
	
	// Read and forward the response
	if err := wp.forwardResponse(clientConn, backendConn); err != nil {
		return
	}
	
	// Update statistics and metrics
	atomic.AddInt64(&wp.stats.activeConnections, 1)
	atomic.AddInt64(&wp.stats.totalConnections, 1)
	wp.wsMetrics.recordNewConnection()
	
	defer func() {
		atomic.AddInt64(&wp.stats.activeConnections, -1)
		wp.wsMetrics.recordClosedConnection()
	}()
	
	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Bidirectional proxy with context
	wp.proxyWithContext(ctx, clientConn, backendConn, clientIP)
}

func (wp *WSProxy) connectToBackend(r *http.Request) (net.Conn, error) {
	host := wp.target.Host
	if wp.target.Port() == "" {
		if wp.target.Scheme == "wss" || wp.target.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), wp.dialTimeout)
	defer cancel()
	
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	
	// Upgrade to TLS if needed
	if wp.target.Scheme == "wss" || wp.target.Scheme == "https" {
		tlsConfig := wp.tlsConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				ServerName: wp.target.Hostname(),
			}
		}
		
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		
		return tlsConn, nil
	}
	
	return conn, nil
}

func (wp *WSProxy) forwardRequest(backendConn net.Conn, r *http.Request) error {
	// Modify request headers
	r.URL.Scheme = wp.target.Scheme
	r.URL.Host = wp.target.Host
	r.Host = wp.target.Host
	
	// Remove hop-by-hop headers
	removeHopHeaders(r.Header)
	
	// Add X-Forwarded headers
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		r.Header.Set("X-Forwarded-For", clientIP)
	}
	r.Header.Set("X-Forwarded-Proto", "http")
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	
	// Write request to backend
	return r.Write(backendConn)
}

func (wp *WSProxy) forwardResponse(clientConn, backendConn net.Conn) error {
	// Read response from backend
	resp, err := http.ReadResponse(bufio.NewReader(backendConn), nil)
	if err != nil {
		return err
	}
	
	// Remove hop-by-hop headers
	removeHopHeaders(resp.Header)
	
	// Write response to client
	return resp.Write(clientConn)
}

func (wp *WSProxy) proxyWithContext(ctx context.Context, client, backend net.Conn, clientIP string) {
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Create channels for goroutine coordination
	clientDone := make(chan struct{})
	backendDone := make(chan struct{})
	
	// Setup idle timeout
	idleTimer := time.NewTimer(wp.idleTimeout)
	defer idleTimer.Stop()
	
	// Setup ping ticker
	pingTicker := time.NewTicker(wp.pingInterval)
	defer pingTicker.Stop()
	
	// Client to Backend
	go func() {
		defer wg.Done()
		defer close(clientDone)
		
		n, err := wp.copyWithContext(ctx, backend, client, "client->backend", idleTimer)
		atomic.AddInt64(&wp.stats.bytesTransferred, n)
		wp.wsMetrics.recordBytesTransferred("client->backend", n)
		
		if err != nil && !isClosedError(err) {
			wp.wsMetrics.recordError("copy_error", err)
		}
	}()
	
	// Backend to Client
	go func() {
		defer wg.Done()
		defer close(backendDone)
		
		n, err := wp.copyWithContext(ctx, client, backend, "backend->client", idleTimer)
		atomic.AddInt64(&wp.stats.bytesTransferred, n)
		wp.wsMetrics.recordBytesTransferred("backend->client", n)
		
		if err != nil && !isClosedError(err) {
			wp.wsMetrics.recordError("copy_error", err)
		}
	}()
	
	// Monitor goroutines and handle timeouts
	go func() {
		for {
			select {
			case <-ctx.Done():
				// Context cancelled, close connections
				client.Close()
				backend.Close()
				return
				
			case <-clientDone:
				// Client connection closed, close backend
				backend.Close()
				return
				
			case <-backendDone:
				// Backend connection closed, close client
				client.Close()
				return
				
			case <-idleTimer.C:
				// Idle timeout reached
				wp.wsMetrics.recordTimeout("idle", clientIP)
				client.Close()
				backend.Close()
				return
				
			case <-pingTicker.C:
				// Send ping frame (WebSocket specific)
				if err := wp.sendPing(client); err != nil {
					wp.wsMetrics.recordError("ping_error", err)
					client.Close()
					backend.Close()
					return
				}
			}
		}
	}()
	
	wg.Wait()
}

func (wp *WSProxy) copyWithContext(ctx context.Context, dst, src net.Conn, direction string, idleTimer *time.Timer) (int64, error) {
	buf := make([]byte, wp.bufferSize)
	var total int64
	
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		
		// Set read deadline for timeout
		src.SetReadDeadline(time.Now().Add(wp.idleTimeout))
		
		nr, err := src.Read(buf)
		if nr > 0 {
			// Reset idle timer on activity
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(wp.idleTimeout)
			
			// Check message size limit
			if total+int64(nr) > wp.maxMessageSize {
				return total, fmt.Errorf("message size exceeds limit: %d > %d", total+int64(nr), wp.maxMessageSize)
			}
			
			// Set write deadline
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			
			nw, err := dst.Write(buf[:nr])
			if err != nil {
				return total, err
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
			total += int64(nw)
		}
		
		if err != nil {
			if err == io.EOF || isTimeoutError(err) {
				return total, nil
			}
			return total, err
		}
	}
}

func (wp *WSProxy) sendErrorResponse(conn net.Conn, code int, message string) {
	resp := &http.Response{
		StatusCode: code,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Connection", "close")
	resp.Body = io.NopCloser(strings.NewReader(message))
	
	resp.Write(conn)
}

func (wp *WSProxy) Stats() Stats {
	wp.stats.mu.RLock()
	defer wp.stats.mu.RUnlock()
	
	return Stats{
		ActiveConnections: wp.stats.activeConnections,
		TotalConnections:  wp.stats.totalConnections,
		BytesTransferred:  wp.stats.bytesTransferred,
	}
}

type Stats struct {
	ActiveConnections int64
	TotalConnections  int64
	BytesTransferred  int64
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func removeHopHeaders(header http.Header) {
	hopHeaders := []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}
	
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for common closed connection errors
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	
	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}
	
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return host
}

// sendPing sends a WebSocket ping frame
func (wp *WSProxy) sendPing(conn net.Conn) error {
	// WebSocket ping frame: FIN=1, opcode=0x9 (ping), no payload
	pingFrame := []byte{0x89, 0x00}
	
	conn.SetWriteDeadline(time.Now().Add(wp.pongTimeout))
	_, err := conn.Write(pingFrame)
	return err
}

// websocketMetrics handles metrics for WebSocket connections
type websocketMetrics struct {
	activeConnections   *metrics.Metric
	totalConnections    *metrics.Metric
	bytesTransferred    *metrics.Metric
	errors              *metrics.Metric
	timeouts            *metrics.Metric
	rateLimited         *metrics.Metric
	connectionLimited   *metrics.Metric
}

func newWebsocketMetrics() *websocketMetrics {
	return &websocketMetrics{
		activeConnections: metrics.Register(
			"websocket_active_connections",
			metrics.MetricTypeGauge,
			"Number of active WebSocket connections",
		),
		totalConnections: metrics.Register(
			"websocket_connections_total",
			metrics.MetricTypeCounter,
			"Total number of WebSocket connections",
		),
		bytesTransferred: metrics.Register(
			"websocket_bytes_transferred_total",
			metrics.MetricTypeCounter,
			"Total bytes transferred through WebSocket proxy",
		),
		errors: metrics.Register(
			"websocket_errors_total",
			metrics.MetricTypeCounter,
			"Total number of WebSocket errors",
		),
		timeouts: metrics.Register(
			"websocket_timeouts_total",
			metrics.MetricTypeCounter,
			"Total number of WebSocket timeouts",
		),
		rateLimited: metrics.Register(
			"websocket_rate_limited_total",
			metrics.MetricTypeCounter,
			"Total number of rate limited WebSocket connections",
		),
		connectionLimited: metrics.Register(
			"websocket_connection_limited_total",
			metrics.MetricTypeCounter,
			"Total number of connection limited WebSocket attempts",
		),
	}
}

func (m *websocketMetrics) recordNewConnection() {
	m.activeConnections.Inc()
	m.totalConnections.Inc()
}

func (m *websocketMetrics) recordClosedConnection() {
	m.activeConnections.Dec()
}

func (m *websocketMetrics) recordBytesTransferred(direction string, bytes int64) {
	m.bytesTransferred.WithLabels(map[string]string{
		"direction": direction,
	}).Add(float64(bytes))
}

func (m *websocketMetrics) recordError(errorType string, err error) {
	m.errors.WithLabels(map[string]string{
		"type": errorType,
	}).Inc()
}

func (m *websocketMetrics) recordTimeout(timeoutType string, clientIP string) {
	m.timeouts.WithLabels(map[string]string{
		"type": timeoutType,
	}).Inc()
}

func (m *websocketMetrics) recordRateLimited(clientIP string) {
	m.rateLimited.Inc()
}

func (m *websocketMetrics) recordConnectionLimited(clientIP string) {
	m.connectionLimited.Inc()
}

// WSHandler creates an HTTP handler for WebSocket proxying
func WSHandler(target string, tlsConfig *tls.Config) (http.Handler, error) {
	proxy, err := New(Config{
		Target:    target,
		TLSConfig: tlsConfig,
	})
	if err != nil {
		return nil, err
	}
	
	return proxy, nil
}

// WSMiddleware adds WebSocket support to existing HTTP proxy
func WSMiddleware(next http.Handler, wsTargets map[string]string) http.Handler {
	proxies := make(map[string]*WSProxy)
	
	for path, target := range wsTargets {
		proxy, err := New(Config{Target: target})
		if err != nil {
			continue
		}
		proxies[path] = proxy
	}
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a WebSocket request for a configured path
		if isWebSocketRequest(r) {
			for path, proxy := range proxies {
				if strings.HasPrefix(r.URL.Path, path) {
					proxy.ServeHTTP(w, r)
					return
				}
			}
		}
		
		// Not a WebSocket request or no matching path
		next.ServeHTTP(w, r)
	})
}