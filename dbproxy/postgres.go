// Package dbproxy provides TLS proxy support for various database protocols
package dbproxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

// PostgresProxy handles PostgreSQL protocol proxying with optional TLS support
type PostgresProxy struct {
	*BaseProxy
}

// NewPostgresProxy creates a new PostgreSQL proxy instance
func NewPostgresProxy(backend string, tlsConfig *tls.Config) *PostgresProxy {
	return &PostgresProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &postgresHandler{}),
	}
}

// postgresHandler implements ProxyHandler for PostgreSQL
type postgresHandler struct{}

func (h *postgresHandler) GetProtocolName() string {
	return "PostgreSQL"
}

func (h *postgresHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	// For PostgreSQL, we handle SSL negotiation if needed
	// The base proxy will handle TLS if configured
	return clientConn, backendConn, nil
}

// Serve delegates to BaseProxy.Serve
func (p *PostgresProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}

// handleConnection manages a single client connection to the PostgreSQL backend
func (p *PostgresProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to Postgres backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	if p.EnableTLS {
		clientConn, backendConn, err = p.handleSSLNegotiation(clientConn, backendConn)
		if err != nil {
			log.Printf("SSL negotiation failed: %v", err)
			return
		}
	}

	// Use the BaseProxy's timeout-aware proxy connections
	p.BaseProxy.proxyConnections(clientConn, backendConn)
}

// handleSSLNegotiation manages the PostgreSQL SSL negotiation protocol
// It intercepts the SSLRequest packet and establishes TLS connections when requested
func (p *PostgresProxy) handleSSLNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	// Read the initial packet which might be an SSL request
	buf := make([]byte, 8)
	n, err := clientConn.Read(buf)
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
			if err := tlsClient.Handshake(); err != nil {
				return clientConn, backendConn, fmt.Errorf("TLS handshake with client failed: %w", err)
			}
			clientConn = tlsClient

			tlsBackend := tls.Client(backendConn, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err := tlsBackend.Handshake(); err != nil {
				return clientConn, backendConn, fmt.Errorf("TLS handshake with backend failed: %w", err)
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