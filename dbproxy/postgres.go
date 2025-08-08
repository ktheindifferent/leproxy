// Package dbproxy provides TLS proxy support for various database protocols
package dbproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// PostgresProxy handles PostgreSQL protocol proxying with optional TLS support
type PostgresProxy struct {
	Backend   string      // Backend PostgreSQL server address (host:port)
	TLSConfig *tls.Config // TLS configuration for client connections
	EnableTLS bool        // Whether TLS is enabled for this proxy
}

// NewPostgresProxy creates a new PostgreSQL proxy instance
func NewPostgresProxy(backend string, tlsConfig *tls.Config) *PostgresProxy {
	return &PostgresProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

// Serve starts accepting and handling PostgreSQL client connections
func (p *PostgresProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		// Handle each connection in a separate goroutine
		go p.handleConnection(clientConn)
	}
}

// handleConnection manages a single client connection to the PostgreSQL backend
func (p *PostgresProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Connect to the backend PostgreSQL server
	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to Postgres backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	// Handle SSL/TLS negotiation if enabled
	if p.EnableTLS {
		// handleSSLNegotiation intercepts the PostgreSQL SSL request and establishes TLS
		newClientConn, newBackendConn, err := p.handleSSLNegotiation(clientConn, backendConn)
		if err != nil {
			log.Printf("SSL negotiation failed: %v", err)
			return
		}
		clientConn = newClientConn
		backendConn = newBackendConn
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, backendConn)
		errc <- err
	}()

	<-errc
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

func isSSLRequest(buf []byte) bool {
	if len(buf) < 8 {
		return false
	}
	var length int32
	if err := binary.Read(bytes.NewReader(buf[:4]), binary.BigEndian, &length); err != nil {
		return false
	}
	if length != 8 {
		return false
	}
	var code int32
	if err := binary.Read(bytes.NewReader(buf[4:8]), binary.BigEndian, &code); err != nil {
		return false
	}
	return code == 80877103
}