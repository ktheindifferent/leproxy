package dbproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	
	"github.com/artyom/leproxy/internal/safegoroutine"
)

type RedisProxy struct {
	*BaseProxy
}

func NewRedisProxy(backend string, tlsConfig *tls.Config) *RedisProxy {
	return &RedisProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &redisHandler{}),
	}
}

// redisHandler implements ProxyHandler for Redis
type redisHandler struct{}

func (h *redisHandler) GetProtocolName() string {
	return "Redis"
}

func (h *redisHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (p *RedisProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *RedisProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to Redis backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	// Handle TLS if enabled
	if p.EnableTLS {
		// Check if client sends STARTTLS command
		clientReader := bufio.NewReader(clientConn)
		
		// Peek at the first command
		firstLine, err := clientReader.Peek(64)
		if err == nil && p.isStartTLSCommand(firstLine) {
			// Read the full STARTTLS command
			_, err := clientReader.ReadString('\n')
			if err != nil {
				log.Printf("Failed to read STARTTLS command: %v", err)
				return
			}

			// Send +OK response
			if _, err := clientConn.Write([]byte("+OK\r\n")); err != nil {
				log.Printf("Failed to send STARTTLS response: %v", err)
				return
			}

			// Upgrade to TLS
			tlsConn := tls.Server(clientConn, p.TLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake failed: %v", err)
				return
			}
			clientConn = tlsConn
			
			// Create new reader for TLS connection
			clientReader = bufio.NewReader(clientConn)
		} else {
			// No STARTTLS, but we can still offer TLS wrapper if client connects with TLS directly
			if p.EnableTLS {
				// Try to detect TLS handshake (starts with 0x16 for TLS)
				if len(firstLine) > 0 && firstLine[0] == 0x16 {
					tlsConn := tls.Server(clientConn, p.TLSConfig)
					if err := tlsConn.Handshake(); err != nil {
						// Not a TLS connection, continue with plain text
						log.Printf("Client connected without TLS, continuing with plain connection")
					} else {
						clientConn = tlsConn
						clientReader = bufio.NewReader(clientConn)
					}
				}
			}
		}

		// For connections that used a reader, we need to handle buffered data
		if clientReader != nil {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			
			var wg sync.WaitGroup
			wg.Add(2)
			
			safegoroutine.Go(fmt.Sprintf("redis-proxy-reader-%s", clientConn.RemoteAddr()), func() {
				defer wg.Done()
				err := p.proxyWithReaderContext(ctx, clientReader, clientConn, backendConn)
				if err != nil && err != io.EOF && err != context.Canceled {
					log.Printf("Redis client->backend error: %v", err)
				}
				cancel()
			})
			
			safegoroutine.Go(fmt.Sprintf("redis-proxy-backend-%s", clientConn.RemoteAddr()), func() {
				defer wg.Done()
				err := p.copyWithContext(ctx, clientConn, backendConn)
				if err != nil && err != io.EOF && err != context.Canceled {
					log.Printf("Redis backend->client error: %v", err)
				}
				cancel()
			})
			
			// Wait for both goroutines to complete
			wg.Wait()
			return
		}
	}

	// Standard bidirectional copy for non-TLS or after TLS negotiation
	// Use BaseProxy's proxyConnections for proper goroutine management
	p.BaseProxy.proxyConnections(clientConn, backendConn)
}

func (p *RedisProxy) isStartTLSCommand(data []byte) bool {
	// Redis STARTTLS command in RESP protocol
	// Could be: *1\r\n$8\r\nSTARTTLS\r\n
	// Or simple: STARTTLS\r\n
	str := string(data)
	return strings.Contains(strings.ToUpper(str), "STARTTLS")
}

func (p *RedisProxy) proxyWithReaderContext(ctx context.Context, reader *bufio.Reader, client, backend net.Conn) error {
	// First, flush any buffered data
	if reader.Buffered() > 0 {
		buffered, err := reader.Peek(reader.Buffered())
		if err == nil {
			if _, err := backend.Write(buffered); err != nil {
				return err
			}
			reader.Discard(len(buffered))
		}
	}
	
	// Then continue with regular copy with context support
	buffer := make([]byte, 32*1024)
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		n, err := reader.Read(buffer)
		if n > 0 {
			if _, writeErr := backend.Write(buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (p *RedisProxy) copyWithContext(ctx context.Context, dst, src net.Conn) error {
	buffer := make([]byte, 32*1024)
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		n, err := src.Read(buffer)
		if n > 0 {
			if _, writeErr := dst.Write(buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}