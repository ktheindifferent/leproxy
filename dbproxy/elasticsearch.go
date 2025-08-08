package dbproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type ElasticsearchProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
}

func NewElasticsearchProxy(backend string, tlsConfig *tls.Config) *ElasticsearchProxy {
	return &ElasticsearchProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *ElasticsearchProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *ElasticsearchProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to Elasticsearch backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	var wrappedClientConn net.Conn = clientConn
	var wrappedBackendConn net.Conn = backendConn

	if p.EnableTLS {
		tlsClient := tls.Server(clientConn, p.TLSConfig)
		if err := tlsClient.Handshake(); err != nil {
			log.Printf("TLS handshake with Elasticsearch client failed: %v", err)
			return
		}
		wrappedClientConn = tlsClient

		tlsBackend := tls.Client(backendConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsBackend.Handshake(); err != nil {
			log.Printf("TLS handshake with Elasticsearch backend failed: %v", err)
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