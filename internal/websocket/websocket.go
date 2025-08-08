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
	"time"
)

type WSProxy struct {
	target      *url.URL
	tlsConfig   *tls.Config
	dialTimeout time.Duration
	bufferSize  int
	
	// Statistics
	stats struct {
		activeConnections int64
		totalConnections  int64
		bytesTransferred  int64
		mu                sync.RWMutex
	}
}

type Config struct {
	Target      string
	TLSConfig   *tls.Config
	DialTimeout time.Duration
	BufferSize  int
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
	
	return &WSProxy{
		target:      target,
		tlsConfig:   cfg.TLSConfig,
		dialTimeout: cfg.DialTimeout,
		bufferSize:  cfg.BufferSize,
	}, nil
}

func (wp *WSProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketRequest(r) {
		http.Error(w, "Not a WebSocket request", http.StatusBadRequest)
		return
	}
	
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
	
	// Update statistics
	wp.stats.mu.Lock()
	wp.stats.activeConnections++
	wp.stats.totalConnections++
	wp.stats.mu.Unlock()
	
	defer func() {
		wp.stats.mu.Lock()
		wp.stats.activeConnections--
		wp.stats.mu.Unlock()
	}()
	
	// Bidirectional copy
	wp.proxy(clientConn, backendConn)
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

func (wp *WSProxy) proxy(client, backend net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Client to Backend
	go func() {
		defer wg.Done()
		n, _ := wp.copy(backend, client, "client->backend")
		
		wp.stats.mu.Lock()
		wp.stats.bytesTransferred += n
		wp.stats.mu.Unlock()
	}()
	
	// Backend to Client
	go func() {
		defer wg.Done()
		n, _ := wp.copy(client, backend, "backend->client")
		
		wp.stats.mu.Lock()
		wp.stats.bytesTransferred += n
		wp.stats.mu.Unlock()
	}()
	
	wg.Wait()
}

func (wp *WSProxy) copy(dst, src net.Conn, direction string) (int64, error) {
	buf := make([]byte, wp.bufferSize)
	var total int64
	
	for {
		nr, err := src.Read(buf)
		if nr > 0 {
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
			if err == io.EOF {
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