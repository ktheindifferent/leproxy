package dbproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

type SMTPProxy struct {
	*BaseProxy
}

func NewSMTPProxy(backend string, tlsConfig *tls.Config) *SMTPProxy {
	return &SMTPProxy{
		BaseProxy: NewBaseProxy(backend, tlsConfig, &smtpHandler{}),
	}
}

// smtpHandler implements ProxyHandler for SMTP
type smtpHandler struct{}

func (h *smtpHandler) GetProtocolName() string {
	return "SMTP"
}

func (h *smtpHandler) HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	return clientConn, backendConn, nil
}

func (p *SMTPProxy) Serve(listener net.Listener) error {
	return p.BaseProxy.Serve(listener)
}
func (p *SMTPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to SMTP backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	if p.EnableTLS {
		wrappedClientConn, wrappedBackendConn, err := p.handleSTARTTLS(clientConn, backendConn)
		if err != nil {
			log.Printf("STARTTLS handling failed: %v", err)
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

func (p *SMTPProxy) handleSTARTTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	clientReader := bufio.NewReader(clientConn)
	backendReader := bufio.NewReader(backendConn)
	
	greeting, err := backendReader.ReadString('\n')
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read greeting: %w", err)
	}
	if _, err := clientConn.Write([]byte(greeting)); err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to send greeting: %w", err)
	}

	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read client command: %w", err)
		}

		if _, err := backendConn.Write([]byte(line)); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward command: %w", err)
		}

		response, err := backendReader.ReadString('\n')
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read backend response: %w", err)
		}

		if _, err := clientConn.Write([]byte(response)); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward response: %w", err)
		}

		if strings.HasPrefix(strings.ToUpper(line), "STARTTLS") {
			if strings.HasPrefix(response, "220") {
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

		if strings.HasPrefix(strings.ToUpper(line), "QUIT") {
			break
		}
	}

	return clientConn, backendConn, nil
}

func (p *SMTPProxy) handleImplicitTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
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