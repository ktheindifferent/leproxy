package dbproxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	postgresSSLRequestCode = 80877103
	postgresSSLResponseOK  = 'S'
	postgresSSLResponseNo  = 'N'
)

type PostgresProxyRefactored struct {
	*BaseProxy
}

func NewPostgresProxyRefactored(backend string, tlsConfig *tls.Config) *PostgresProxyRefactored {
	handler := &postgresHandler{tlsConfig: tlsConfig}
	return &PostgresProxyRefactored{
		BaseProxy: NewBaseProxy(backend, tlsConfig, handler),
	}
}

func (p *PostgresProxyRefactored) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}

type postgresHandler struct {
	tlsConfig *tls.Config
}

func (h *postgresHandler) GetProtocolName() string {
	return "Postgres"
}

func (h *postgresHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	firstBytes, err := h.readInitialRequest(clientConn)
	if err != nil {
		return nil, nil, err
	}

	clientWithPrefix := NewPrefixConn(clientConn, firstBytes)

	if !h.isSSLRequest(firstBytes) {
		return clientWithPrefix, backendConn, nil
	}

	return h.negotiateSSL(clientWithPrefix, backendConn)
}

func (h *postgresHandler) readInitialRequest(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read initial bytes: %w", err)
	}
	return buf[:n], nil
}

func (h *postgresHandler) isSSLRequest(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	length := binary.BigEndian.Uint32(data[0:4])
	code := binary.BigEndian.Uint32(data[4:8])
	return length == 8 && code == postgresSSLRequestCode
}

func (h *postgresHandler) negotiateSSL(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	sslRequest, err := h.readSSLRequest(clientConn)
	if err != nil {
		return nil, nil, err
	}

	backendResponse, err := h.forwardSSLRequest(backendConn, sslRequest)
	if err != nil {
		return nil, nil, err
	}

	if backendResponse == postgresSSLResponseOK {
		return h.handleSSLEnabled(clientConn, backendConn)
	}

	return h.handleSSLDisabled(clientConn, backendConn, backendResponse)
}

func (h *postgresHandler) readSSLRequest(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 8)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSL request: %w", err)
	}
	return buf, nil
}

func (h *postgresHandler) forwardSSLRequest(backend net.Conn, request []byte) (byte, error) {
	if _, err := backend.Write(request); err != nil {
		return 0, fmt.Errorf("failed to forward SSL request: %w", err)
	}

	response := make([]byte, 1)
	if _, err := io.ReadFull(backend, response); err != nil {
		return 0, fmt.Errorf("failed to read backend SSL response: %w", err)
	}

	return response[0], nil
}

func (h *postgresHandler) handleSSLEnabled(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	if h.tlsConfig == nil {
		return h.sendSSLResponse(clientConn, backendConn, postgresSSLResponseNo)
	}

	if err := h.sendSSLOK(clientConn); err != nil {
		return nil, nil, err
	}

	return h.upgradeBothConnections(clientConn, backendConn)
}

func (h *postgresHandler) handleSSLDisabled(clientConn, backendConn net.Conn, response byte) (net.Conn, net.Conn, error) {
	return h.sendSSLResponse(clientConn, backendConn, response)
}

func (h *postgresHandler) sendSSLResponse(clientConn, backendConn net.Conn, response byte) (net.Conn, net.Conn, error) {
	if _, err := clientConn.Write([]byte{response}); err != nil {
		return nil, nil, fmt.Errorf("failed to send SSL response: %w", err)
	}
	return clientConn, backendConn, nil
}

func (h *postgresHandler) sendSSLOK(conn net.Conn) error {
	_, err := conn.Write([]byte{postgresSSLResponseOK})
	return err
}

func (h *postgresHandler) upgradeBothConnections(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	tlsClient, err := h.upgradeClientConnection(clientConn)
	if err != nil {
		return nil, nil, err
	}

	tlsBackend, err := h.upgradeBackendConnection(backendConn)
	if err != nil {
		return nil, nil, err
	}

	return tlsClient, tlsBackend, nil
}

func (h *postgresHandler) upgradeClientConnection(conn net.Conn) (*tls.Conn, error) {
	tlsConn := tls.Server(conn, h.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("client TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

func (h *postgresHandler) upgradeBackendConnection(conn net.Conn) (*tls.Conn, error) {
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("backend TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}