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

type MySQLProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
}

func NewMySQLProxy(backend string, tlsConfig *tls.Config) *MySQLProxy {
	return &MySQLProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *MySQLProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *MySQLProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to MySQL backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	// MySQL initial handshake from server
	handshakeBuf := make([]byte, 4096)
	n, err := backendConn.Read(handshakeBuf)
	if err != nil {
		log.Printf("Failed to read MySQL handshake: %v", err)
		return
	}

	// Check if server supports SSL (capability flag 0x0800)
	if p.EnableTLS && p.supportsSSL(handshakeBuf[:n]) {
		// Send modified handshake to client with SSL capability
		if _, err := clientConn.Write(handshakeBuf[:n]); err != nil {
			log.Printf("Failed to send handshake to client: %v", err)
			return
		}

		// Wait for SSL request packet from client
		sslReqBuf := make([]byte, 36)
		if _, err := clientConn.Read(sslReqBuf); err != nil {
			log.Printf("Failed to read SSL request: %v", err)
			return
		}

		// Check if client requested SSL
		if p.isSSLRequest(sslReqBuf) {
			// Upgrade client connection to TLS
			tlsConn := tls.Server(clientConn, p.TLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake failed: %v", err)
				return
			}
			clientConn = tlsConn

			// Forward SSL request to backend
			if _, err := backendConn.Write(sslReqBuf); err != nil {
				log.Printf("Failed to forward SSL request: %v", err)
				return
			}
		}
	} else {
		// No TLS, just forward the handshake
		if _, err := clientConn.Write(handshakeBuf[:n]); err != nil {
			log.Printf("Failed to send handshake to client: %v", err)
			return
		}
	}

	// Proxy the connection
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, backendConn)
		errCh <- err
	}()

	// Wait for either direction to finish
	<-errCh
}

func (p *MySQLProxy) supportsSSL(handshake []byte) bool {
	// MySQL handshake packet structure:
	// 4 bytes: packet header
	// 1 byte: protocol version
	// null-terminated server version string
	// 4 bytes: connection id
	// 8 bytes: auth plugin data part 1
	// 1 byte: filler
	// 2 bytes: capability flags (lower)
	
	if len(handshake) < 30 {
		return false
	}

	// Find null terminator after version string
	versionEnd := bytes.IndexByte(handshake[5:], 0)
	if versionEnd == -1 {
		return false
	}

	capabilityOffset := 5 + versionEnd + 1 + 4 + 8 + 1
	if len(handshake) < capabilityOffset+2 {
		return false
	}

	// Read capability flags (little-endian)
	capabilities := binary.LittleEndian.Uint16(handshake[capabilityOffset:])
	
	// CLIENT_SSL flag is 0x0800
	return (capabilities & 0x0800) != 0
}

func (p *MySQLProxy) isSSLRequest(packet []byte) bool {
	// SSL request packet has capability flags with CLIENT_SSL set
	if len(packet) < 8 {
		return false
	}

	// Read capability flags from packet (after 4-byte header)
	capabilities := binary.LittleEndian.Uint32(packet[4:8])
	
	// CLIENT_SSL flag is 0x0800
	return (capabilities & 0x0800) != 0
}