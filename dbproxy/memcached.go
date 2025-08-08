package dbproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type MemcachedProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
}

func NewMemcachedProxy(backend string, tlsConfig *tls.Config) *MemcachedProxy {
	return &MemcachedProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *MemcachedProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *MemcachedProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to Memcached backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	var wrappedClientConn net.Conn = clientConn
	var wrappedBackendConn net.Conn = backendConn

	if p.EnableTLS {
		wrappedClientConn, wrappedBackendConn, err = p.handleMemcachedTLS(clientConn, backendConn)
		if err != nil {
			log.Printf("Memcached TLS handling failed: %v", err)
			return
		}
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

func (p *MemcachedProxy) handleMemcachedTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
	firstByte := make([]byte, 1)
	n, err := clientConn.Read(firstByte)
	if err != nil {
		return clientConn, backendConn, fmt.Errorf("failed to read first byte: %w", err)
	}

	isBinary := n == 1 && firstByte[0] == 0x80

	if isBinary {
		header := make([]byte, 23)
		n2, err := clientConn.Read(header)
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read binary header: %w", err)
		}

		fullHeader := append(firstByte, header[:n2]...)
		
		if isBinaryStartTLS(fullHeader) {
			if _, err := backendConn.Write(fullHeader); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward STARTTLS request: %w", err)
			}

			response := make([]byte, 24)
			n, err := backendConn.Read(response)
			if err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to read STARTTLS response: %w", err)
			}

			if _, err := clientConn.Write(response[:n]); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward STARTTLS response: %w", err)
			}

			if isStartTLSSuccessResponse(response[:n]) {
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
			if _, err := backendConn.Write(fullHeader); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward binary header: %w", err)
			}
		}
	} else {
		clientReader := bufio.NewReader(clientConn)
		restOfLine, err := clientReader.ReadString('\n')
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read command: %w", err)
		}

		fullCommand := string(firstByte) + restOfLine
		
		if strings.HasPrefix(strings.ToUpper(fullCommand), "STARTTLS") {
			if _, err := backendConn.Write([]byte(fullCommand)); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward STARTTLS command: %w", err)
			}

			backendReader := bufio.NewReader(backendConn)
			response, err := backendReader.ReadString('\n')
			if err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to read STARTTLS response: %w", err)
			}

			if _, err := clientConn.Write([]byte(response)); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward STARTTLS response: %w", err)
			}

			if strings.HasPrefix(response, "OK") {
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
			if _, err := backendConn.Write([]byte(fullCommand)); err != nil {
				return clientConn, backendConn, fmt.Errorf("failed to forward command: %w", err)
			}
		}
	}

	return clientConn, backendConn, nil
}

func isBinaryStartTLS(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return data[0] == 0x80 && data[1] == 0x21
}

func isStartTLSSuccessResponse(data []byte) bool {
	if len(data) < 24 {
		return false
	}
	return data[0] == 0x81 && data[1] == 0x21 && data[6] == 0x00 && data[7] == 0x00
}

func (p *MemcachedProxy) handleImplicitTLS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
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