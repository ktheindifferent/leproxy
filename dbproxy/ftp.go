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

type FTPProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
}

func NewFTPProxy(backend string, tlsConfig *tls.Config) *FTPProxy {
	return &FTPProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *FTPProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *FTPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to FTP backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	if p.EnableTLS {
		wrappedClientConn, wrappedBackendConn, err := p.handleFTPS(clientConn, backendConn)
		if err != nil {
			log.Printf("FTPS handling failed: %v", err)
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

func (p *FTPProxy) handleFTPS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
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
			if err == io.EOF {
				break
			}
			return clientConn, backendConn, fmt.Errorf("failed to read client command: %w", err)
		}

		if _, err := backendConn.Write([]byte(line)); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward command: %w", err)
		}

		response, err := p.readFTPResponse(backendReader)
		if err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to read backend response: %w", err)
		}

		if _, err := clientConn.Write([]byte(response)); err != nil {
			return clientConn, backendConn, fmt.Errorf("failed to forward response: %w", err)
		}

		upperLine := strings.ToUpper(strings.TrimSpace(line))
		if strings.HasPrefix(upperLine, "AUTH TLS") || strings.HasPrefix(upperLine, "AUTH SSL") {
			if strings.HasPrefix(response, "234") {
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

		if strings.HasPrefix(upperLine, "QUIT") {
			break
		}
	}

	return clientConn, backendConn, nil
}

func (p *FTPProxy) readFTPResponse(reader *bufio.Reader) (string, error) {
	var response strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		response.WriteString(line)
		
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return response.String(), nil
}

func (p *FTPProxy) handleImplicitFTPS(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error) {
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