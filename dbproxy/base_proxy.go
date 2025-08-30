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
)

const (
	DefaultConnectTimeout = 10 * time.Second
	DefaultIdleTimeout    = 5 * time.Minute
	DefaultReadTimeout    = 30 * time.Second
	DefaultWriteTimeout   = 30 * time.Second
	TLSHandshakeByte     = 0x16
)

type ProxyHandler interface {
	HandleProtocolNegotiation(ctx context.Context, clientConn, backendConn net.Conn) (net.Conn, net.Conn, error)
	GetProtocolName() string
}

type BaseProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
	Handler   ProxyHandler
	
	// Connection management
	activeConnections int64
	shutdown          chan struct{}
	wg                sync.WaitGroup
	
	// Timeouts
	ConnectTimeout time.Duration
	IdleTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
}

func NewBaseProxy(backend string, tlsConfig *tls.Config, handler ProxyHandler) *BaseProxy {
	return &BaseProxy{
		Backend:        backend,
		TLSConfig:      tlsConfig,
		EnableTLS:      tlsConfig != nil,
		Handler:        handler,
		shutdown:       make(chan struct{}),
		ConnectTimeout: DefaultConnectTimeout,
		IdleTimeout:    DefaultIdleTimeout,
		ReadTimeout:    DefaultReadTimeout,
		WriteTimeout:   DefaultWriteTimeout,
	}
}

func (p *BaseProxy) Serve(listener net.Listener) error {
	for {
		select {
		case <-p.shutdown:
			return nil
		default:
		}
		
		clientConn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.shutdown:
				return nil
			default:
				return fmt.Errorf("failed to accept connection: %w", err)
			}
		}
		
		p.wg.Add(1)
		atomic.AddInt64(&p.activeConnections, 1)
		go p.handleConnection(clientConn)
	}
}

func (p *BaseProxy) handleConnection(clientConn net.Conn) {
	defer p.wg.Done()
	defer atomic.AddInt64(&p.activeConnections, -1)
	defer clientConn.Close()
	
	// Create context with cancellation for this connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Set initial timeouts
	if err := p.setConnectionTimeouts(clientConn); err != nil {
		log.Printf("Failed to set client connection timeouts: %v", err)
		return
	}

	backendConn, err := p.connectToBackendWithContext(ctx)
	if err != nil {
		log.Printf("Failed to connect to %s backend %s: %v", 
			p.Handler.GetProtocolName(), p.Backend, err)
		return
	}
	defer backendConn.Close()
	
	// Set backend connection timeouts
	if err := p.setConnectionTimeouts(backendConn); err != nil {
		log.Printf("Failed to set backend connection timeouts: %v", err)
		return
	}

	clientConn, backendConn, err = p.Handler.HandleProtocolNegotiation(ctx, clientConn, backendConn)
	if err != nil {
		log.Printf("Protocol negotiation failed for %s: %v", 
			p.Handler.GetProtocolName(), err)
		return
	}

	p.proxyConnectionsWithContext(ctx, clientConn, backendConn)
}

func (p *BaseProxy) connectToBackend() (net.Conn, error) {
	return net.DialTimeout("tcp", p.Backend, p.ConnectTimeout)
}

func (p *BaseProxy) connectToBackendWithContext(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: p.ConnectTimeout,
	}
	return d.DialContext(ctx, "tcp", p.Backend)
}

func (p *BaseProxy) setConnectionTimeouts(conn net.Conn) error {
	now := time.Now()
	if err := conn.SetDeadline(now.Add(p.IdleTimeout)); err != nil {
		return err
	}
	return nil
}

func (p *BaseProxy) proxyConnections(clientConn, backendConn net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.proxyConnectionsWithContext(ctx, clientConn, backendConn)
}

func (p *BaseProxy) proxyConnectionsWithContext(ctx context.Context, clientConn, backendConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Channel to signal when either copy operation completes
	done := make(chan struct{})
	stopCopy := make(chan struct{})

	copyData := func(dst, src net.Conn, direction string) {
		defer wg.Done()
		
		buf := make([]byte, 32*1024) // 32KB buffer
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.shutdown:
				return
			case <-stopCopy:
				return
			default:
			}
			
			// Set read deadline for idle timeout
			if err := src.SetReadDeadline(time.Now().Add(p.ReadTimeout)); err != nil {
				log.Printf("%s proxy set read deadline error: %v", 
					p.Handler.GetProtocolName(), err)
				return
			}
			
			n, readErr := src.Read(buf)
			if n > 0 {
				// Set write deadline
				if err := dst.SetWriteDeadline(time.Now().Add(p.WriteTimeout)); err != nil {
					log.Printf("%s proxy set write deadline error: %v", 
						p.Handler.GetProtocolName(), err)
					return
				}
				
				if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
					if writeErr != io.EOF {
						log.Printf("%s proxy %s write error: %v", 
							p.Handler.GetProtocolName(), direction, writeErr)
					}
					return
				}
			}
			
			if readErr != nil {
				if readErr != io.EOF {
					log.Printf("%s proxy %s read error: %v", 
						p.Handler.GetProtocolName(), direction, readErr)
				}
				return
			}
		}
	}

	go copyData(backendConn, clientConn, "client->backend")
	go copyData(clientConn, backendConn, "backend->client")
	
	// Monitor for completion
	go func() {
		wg.Wait()
		close(done)
	}()
	
	// Wait for either completion or shutdown signal
	select {
	case <-done:
		// Both copy operations completed
	case <-p.shutdown:
		// Shutdown requested - stop copy operations
		close(stopCopy)
		// Force close connections to unblock reads
		clientConn.Close()
		backendConn.Close()
		// Wait for goroutines to finish
		<-done
	}
}

// Shutdown gracefully shuts down the proxy
func (p *BaseProxy) Shutdown(ctx context.Context) error {
	close(p.shutdown)
	
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("shutdown timeout exceeded, %d connections still active", 
			atomic.LoadInt64(&p.activeConnections))
	}
}

// GetActiveConnections returns the number of active connections
func (p *BaseProxy) GetActiveConnections() int64 {
	return atomic.LoadInt64(&p.activeConnections)
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