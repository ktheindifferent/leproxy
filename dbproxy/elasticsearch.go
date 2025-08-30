package dbproxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
)

type ElasticsearchProxy struct {
	*BaseProxy
}

func NewElasticsearchProxy(backend string, tlsConfig *tls.Config) *ElasticsearchProxy {
	return &ElasticsearchProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &elasticsearchHandler{}),
	}
}

// elasticsearchHandler implements ProxyHandler for Elasticsearch
type elasticsearchHandler struct{}

func (h *elasticsearchHandler) GetProtocolName() string {
	return "Elasticsearch"
}

func (h *elasticsearchHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (p *ElasticsearchProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *ElasticsearchProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
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