package dbproxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
)

type CassandraProxy struct {
	*BaseProxy
}

func NewCassandraProxy(backend string, tlsConfig *tls.Config) *CassandraProxy {
	return &CassandraProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &cassandraHandler{}),
	}
}

// cassandraHandler implements ProxyHandler for Cassandra
type cassandraHandler struct{}

func (h *cassandraHandler) GetProtocolName() string {
	return "Cassandra"
}

func (h *cassandraHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (p *CassandraProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *CassandraProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to Cassandra backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	if p.EnableTLS {
		wrappedClientConn, wrappedBackendConn, err := p.handleCassandraTLS(clientConn, backendConn)
		if err != nil {
			log.Printf("Cassandra TLS handling failed: %v", err)
			return
		}
		clientConn = wrappedClientConn
		backendConn = wrappedBackendConn
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

func (p *CassandraProxy) handleCassandraTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	header := make([]byte, 9)
	n, err := clientConn.Read(header)
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read CQL header: %w", err)
	}

	if n >= 9 && isCQLStartupMessage(header) {
		if _, err := backendConn.Write(header[:n]); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward startup message: %w", err)
		}

		response := make([]byte, 9)
		n, err := backendConn.Read(response)
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read backend response: %w", err)
		}

		if _, err := clientConn.Write(response[:n]); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward response: %w", err)
		}

		if isSSLRequired(response[:n]) {
			tlsClient := tls.Server(clientConn, p.TLSConfig)
			if err := tlsClient.Handshake(); err != nil {
				return clientConn, backendConn, fmt.Errorf("TLS handshake with client failed: %w", err)
			}

			tlsBackend := tls.Client(backendConn, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err := tlsBackend.Handshake(); err != nil {
				return clientConn, backendConn, fmt.Errorf("TLS handshake with backend failed: %w", err)
			}

			return tlsClient, tlsBackend, nil
		}
	} else {
		if _, err := backendConn.Write(header[:n]); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward initial data: %w", err)
		}
	}

	return clientConn, backendConn, nil
}

func isCQLStartupMessage(data []byte) bool {
	if len(data) < 9 {
		return false
	}
	version := data[0] & 0x7F
	return version >= 3 && version <= 5 && data[3] == 0x01
}

func isSSLRequired(data []byte) bool {
	if len(data) < 9 {
		return false
	}
	return data[3] == 0x03
}

func (p *CassandraProxy) handleImplicitTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	tlsClient := tls.Server(clientConn, p.TLSConfig)
	if err := tlsClient.Handshake(); err != nil {
		return clientConn, backendConn, fmt.Errorf("TLS handshake with client failed: %w", err)
	}

	tlsBackend := tls.Client(backendConn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tlsBackend.Handshake(); err != nil {
		return clientConn, backendConn, fmt.Errorf("TLS handshake with backend failed: %w", err)
	}

	return tlsClient, tlsBackend, nil
}

func isCassandraProtocol(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	version := data[0] & 0x7F
	return version >= 1 && version <= 5
}

func extractCassandraVersion(data []byte) uint8 {
	if len(data) == 0 {
		return 0
	}
	return data[0] & 0x7F
}

func isCassandraRequest(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0]&0x80 == 0
}

func isCassandraResponse(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0]&0x80 != 0
}

func getCassandraOpcode(data []byte) uint8 {
	if len(data) < 4 {
		return 0
	}
	return data[3]
}

func isCassandraStartup(data []byte) bool {
	return getCassandraOpcode(data) == 0x01
}

func isCassandraOptions(data []byte) bool {
	return getCassandraOpcode(data) == 0x05
}

func isCassandraSupported(data []byte) bool {
	return getCassandraOpcode(data) == 0x06
}

func hasCassandraSSLFlag(startupBody []byte) bool {
	return bytes.Contains(startupBody, []byte("SSL"))
}