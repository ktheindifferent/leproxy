package dbproxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

type AMQPProxy struct {
	*BaseProxy
}

func NewAMQPProxy(backend string, tlsConfig *tls.Config) *AMQPProxy {
	return &AMQPProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &amqpHandler{}),
	}
}

// amqpHandler implements ProxyHandler for AMQP
type amqpHandler struct{}

func (h *amqpHandler) GetProtocolName() string {
	return "AMQP"
}

func (h *amqpHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (p *AMQPProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *AMQPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to AMQP backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	if p.EnableTLS {
		wrappedClientConn, wrappedBackendConn, err := p.handleAMQPTLS(clientConn, backendConn)
		if err != nil {
			log.Printf("AMQP TLS handling failed: %v", err)
			return
		}
		clientConn = wrappedClientConn
		backendConn = wrappedBackendConn
	}

	// Use BaseProxy's proxyConnections for proper goroutine management
	p.BaseProxy.proxyConnections(clientConn, backendConn)
}

func (p *AMQPProxy) handleAMQPTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	protocolHeader := make([]byte, 8)
	n, err := clientConn.Read(protocolHeader)
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read protocol header: %w", err)
	}

	if n == 8 && isAMQPProtocolHeader(protocolHeader) {
		if bytes.Equal(protocolHeader, []byte("AMQP\x00\x00\x09\x01")) {
			if _, err := backendConn.Write(protocolHeader); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward protocol header: %w", err)
			}

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
	}

	if _, err := backendConn.Write(protocolHeader[:n]); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to forward initial data: %w", err)
	}

	return clientConn, backendConn, nil
}

func isAMQPProtocolHeader(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return bytes.Equal(data[:4], []byte("AMQP"))
}

func (p *AMQPProxy) handleImplicitTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
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