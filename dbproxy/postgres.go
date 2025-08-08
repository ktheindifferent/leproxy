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

type PostgresProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
}

func NewPostgresProxy(backend string, tlsConfig *tls.Config) *PostgresProxy {
	return &PostgresProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *PostgresProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *PostgresProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to Postgres backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	if p.EnableTLS {
		// handleSSLNegotiation may wrap the connections with TLS
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

func (p *PostgresProxy) handleSSLNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	buf := make([]byte, 8)
	n, err := clientConn.Read(buf)
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read SSL request: %w", err)
	}

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