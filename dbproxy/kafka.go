package dbproxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// KafkaProxy handles Apache Kafka protocol proxying with TLS encryption support
// Supports both plaintext and TLS-encrypted Kafka connections
type KafkaProxy struct {
	Backend   string      // Backend Kafka broker address (host:port)
	TLSConfig *tls.Config // TLS configuration for client-side connections
	EnableTLS bool        // Whether TLS encryption is enabled
}

// NewKafkaProxy creates a new Kafka proxy instance for handling Kafka broker connections
func NewKafkaProxy(backend string, tlsConfig *tls.Config) *KafkaProxy {
	return &KafkaProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

// Serve starts accepting and handling Kafka client connections
// Runs in an infinite loop accepting connections until an error occurs
func (p *KafkaProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		// Handle each Kafka client in a separate goroutine for concurrency
		go p.handleConnection(clientConn)
	}
}

// handleConnection manages a single Kafka client connection
// Establishes TLS if configured and proxies data between client and backend
func (p *KafkaProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Connect to the backend Kafka broker
	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to Kafka backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	// Initialize connection wrappers (may be wrapped with TLS)
	var wrappedClientConn net.Conn = clientConn
	var wrappedBackendConn net.Conn = backendConn

	// Establish TLS connections if enabled
	if p.EnableTLS {
		// Setup TLS for client connection
		tlsClient := tls.Server(clientConn, p.TLSConfig)
		if err := tlsClient.Handshake(); err != nil {
			log.Printf("TLS handshake with Kafka client failed: %v", err)
			return
		}
		wrappedClientConn = tlsClient

		// Setup TLS for backend connection
		// Note: InsecureSkipVerify is used for development; configure proper verification in production
		tlsBackend := tls.Client(backendConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsBackend.Handshake(); err != nil {
			log.Printf("TLS handshake with Kafka backend failed: %v", err)
			return
		}
		wrappedBackendConn = tlsBackend
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(wrappedBackendConn, wrappedClientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(wrappedClientConn, wrappedBackendConn)
		errc <- err
	}()

	<-errc
}

func (p *KafkaProxy) peekAPIKey(data []byte) (int16, error) {
	if len(data) < 6 {
		return 0, fmt.Errorf("insufficient data for Kafka request")
	}
	
	apiKey := binary.BigEndian.Uint16(data[4:6])
	return int16(apiKey), nil
}