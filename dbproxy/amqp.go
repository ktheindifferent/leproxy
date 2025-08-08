package dbproxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type AMQPProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
}

func NewAMQPProxy(backend string, tlsConfig *tls.Config) *AMQPProxy {
	return &AMQPProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *AMQPProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *AMQPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
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