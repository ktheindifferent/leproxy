package dbproxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// KafkaProxy handles Apache Kafka protocol proxying with TLS encryption support
// Supports both plaintext and TLS-encrypted Kafka connections
type KafkaProxy struct {
	*BaseProxy
}

// NewKafkaProxy creates a new Kafka proxy instance for handling Kafka broker connections
func NewKafkaProxy(backend string, tlsConfig *tls.Config) *KafkaProxy {
	return &KafkaProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &kafkaHandler{}),
	}
}

// kafkaHandler implements ProxyHandler for Kafka
type kafkaHandler struct{}

func (h *kafkaHandler) GetProtocolName() string {
	return "Kafka"
}

func (h *kafkaHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

// Serve starts accepting and handling Kafka client connections
// Runs in an infinite loop accepting connections until an error occurs
func (p *KafkaProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *KafkaProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Connect to the backend Kafka broker
	backendConn, err := p.connectToBackend()
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