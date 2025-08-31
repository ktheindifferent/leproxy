package dbproxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	
	"github.com/artyom/leproxy/internal/safegoroutine"
)

type MongoDBProxy struct {
	*BaseProxy
}

func NewMongoDBProxy(backend string, tlsConfig *tls.Config) *MongoDBProxy {
	return &MongoDBProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &mongodbHandler{}),
	}
}

// mongodbHandler implements ProxyHandler for MongoDB
type mongodbHandler struct{}

func (h *mongodbHandler) GetProtocolName() string {
	return "MongoDB"
}

func (h *mongodbHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (p *MongoDBProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *MongoDBProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// MongoDB can use TLS from the start of the connection
	if p.EnableTLS {
		// Check if client is initiating TLS
		firstByte := make([]byte, 1)
		n, err := clientConn.Read(firstByte)
		if err != nil {
			log.Printf("Failed to read first byte: %v", err)
			return
		}

		// TLS handshake starts with 0x16
		if n > 0 && firstByte[0] == 0x16 {
			// Create a buffer that includes the first byte we read
			buf := &prefixConn{
				Conn:   clientConn,
				prefix: firstByte[:n],
			}
			
			// Upgrade to TLS
			tlsConn := tls.Server(buf, p.TLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake failed: %v", err)
				return
			}
			clientConn = tlsConn
		} else {
			// Not TLS, create a connection with the prefix byte
			clientConn = &prefixConn{
				Conn:   clientConn,
				prefix: firstByte[:n],
			}
		}
	}

	// Connect to backend
	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to MongoDB backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	// Check if we need to handle isMaster command for TLS negotiation
	if p.EnableTLS {
		// MongoDB wire protocol detection
		p.handleWireProtocol(clientConn, backendConn)
	} else {
		// Simple TCP proxy - use BaseProxy's proxyConnections for proper goroutine management
		p.BaseProxy.proxyConnections(clientConn, backendConn)
	}
}

func (p *MongoDBProxy) handleWireProtocol(clientConn, backendConn net.Conn) {
	// MongoDB wire protocol aware proxying
	// This allows us to intercept and modify certain commands if needed
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	var wg sync.WaitGroup
	wg.Add(2)
	
	// Client to backend
	safegoroutine.Go(fmt.Sprintf("mongodb-client-backend-%s", clientConn.RemoteAddr()), func() {
		defer wg.Done()
		for {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			// Read MongoDB message header (16 bytes)
			header := make([]byte, 16)
			if _, err := io.ReadFull(clientConn, header); err != nil {
				if err != io.EOF {
					log.Printf("MongoDB client->backend read error: %v", err)
				}
				cancel()
				return
			}

			// Parse message length (first 4 bytes, little-endian)
			msgLen := binary.LittleEndian.Uint32(header[:4])
			
			// Read the rest of the message
			if msgLen > 16 {
				body := make([]byte, msgLen-16)
				if _, err := io.ReadFull(clientConn, body); err != nil {
					if err != io.EOF {
						log.Printf("MongoDB client->backend body read error: %v", err)
					}
					cancel()
					return
				}
				
				// Check if this is an isMaster/hello command that needs SSL info
				opCode := binary.LittleEndian.Uint32(header[12:16])
				if p.EnableTLS && (opCode == 2004 || opCode == 2013) { // OP_QUERY or OP_MSG
					// Could modify the message here to add SSL capabilities
					// For now, just forward as-is
				}
				
				// Forward the complete message
				if _, err := backendConn.Write(header); err != nil {
					log.Printf("MongoDB client->backend header write error: %v", err)
					cancel()
					return
				}
				if _, err := backendConn.Write(body); err != nil {
					log.Printf("MongoDB client->backend body write error: %v", err)
					cancel()
					return
				}
			} else {
				// Just the header
				if _, err := backendConn.Write(header); err != nil {
					log.Printf("MongoDB client->backend write error: %v", err)
					cancel()
					return
				}
			}
		}
	})
	
	// Backend to client (simpler, just forward)
	safegoroutine.Go(fmt.Sprintf("mongodb-backend-client-%s", clientConn.RemoteAddr()), func() {
		defer wg.Done()
		for {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			buffer := make([]byte, 32*1024)
			n, err := backendConn.Read(buffer)
			if n > 0 {
				if _, writeErr := clientConn.Write(buffer[:n]); writeErr != nil {
					log.Printf("MongoDB backend->client write error: %v", writeErr)
					cancel()
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("MongoDB backend->client read error: %v", err)
				}
				cancel()
				return
			}
		}
	})

	// Wait for both goroutines to complete
	wg.Wait()
}

// prefixConn wraps a connection and prefixes it with some already-read bytes
type prefixConn struct {
	net.Conn
	prefix []byte
	read   bool
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if !c.read && len(c.prefix) > 0 {
		c.read = true
		n := copy(b, c.prefix)
		if n < len(c.prefix) {
			// Save remaining prefix for next read
			newPrefix := make([]byte, len(c.prefix)-n)
			copy(newPrefix, c.prefix[n:])
			c.prefix = newPrefix
			c.read = false
		}
		return n, nil
	}
	return c.Conn.Read(b)
}