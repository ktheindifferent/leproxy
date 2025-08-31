package dbproxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

type LDAPProxy struct {
	*BaseProxy
}

func NewLDAPProxy(backend string, tlsConfig *tls.Config) *LDAPProxy {
	return &LDAPProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &ldapHandler{}),
	}
}

// ldapHandler implements ProxyHandler for LDAP
type ldapHandler struct{}

func (h *ldapHandler) GetProtocolName() string {
	return "LDAP"
}

func (h *ldapHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (p *LDAPProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *LDAPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to LDAP backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	var wrappedClientConn net.Conn = clientConn
	var wrappedBackendConn net.Conn = backendConn

	if p.EnableTLS {
		tlsClientConn := tls.Server(clientConn, p.TLSConfig)
		if err := tlsClientConn.Handshake(); err != nil {
			log.Printf("TLS handshake with LDAP client failed: %v", err)
			return
		}
		wrappedClientConn = tlsClientConn

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		tlsBackendConn := tls.Client(backendConn, tlsConfig)
		if err := tlsBackendConn.Handshake(); err != nil {
			log.Printf("TLS handshake with LDAP backend failed: %v", err)
			return
		}
		wrappedBackendConn = tlsBackendConn
	}

	// Use BaseProxy's proxyConnections for proper goroutine management
	p.BaseProxy.proxyConnections(wrappedClientConn, wrappedBackendConn)
}

func (p *LDAPProxy) handleStartTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	messageBuffer := make([]byte, 4096)
	n, err := clientConn.Read(messageBuffer)
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read LDAP message: %w", err)
	}

	if isLDAPStartTLS(messageBuffer[:n]) {
		if _, err := backendConn.Write(messageBuffer[:n]); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward StartTLS to backend: %w", err)
		}

		response := make([]byte, 4096)
		n, err := backendConn.Read(response)
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read StartTLS response: %w", err)
		}

		if _, err := clientConn.Write(response[:n]); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward StartTLS response: %w", err)
		}

		if isStartTLSSuccess(response[:n]) {
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
		if _, err := backendConn.Write(messageBuffer[:n]); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward initial message: %w", err)
		}
	}

	return clientConn, backendConn, nil
}

func isLDAPStartTLS(data []byte) bool {
	if len(data) < 7 {
		return false
	}
	return data[5] == 0x77 && data[6] == 0x80
}

func isStartTLSSuccess(data []byte) bool {
	if len(data) < 14 {
		return false
	}
	for i := 7; i < len(data)-1; i++ {
		if data[i] == 0x0a && data[i+1] == 0x01 && i+2 < len(data) && data[i+2] == 0x00 {
			return true
		}
	}
	return false
}