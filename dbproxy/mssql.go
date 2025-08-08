package dbproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type MSSQLProxy struct {
	Backend    string
	TLSConfig  *tls.Config
	EnableTLS  bool
}

func NewMSSQLProxy(backend string, tlsConfig *tls.Config) *MSSQLProxy {
	return &MSSQLProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *MSSQLProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *MSSQLProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to MSSQL backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	if p.EnableTLS {
		if err := p.handleTLSNegotiation(clientConn, backendConn); err != nil {
			log.Printf("TLS negotiation failed: %v", err)
			return
		}
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

func (p *MSSQLProxy) handleTLSNegotiation(clientConn, backendConn net.Conn) error {
	preloginBuf := make([]byte, 4096)
	n, err := clientConn.Read(preloginBuf)
	if err != nil {
		return fmt.Errorf("failed to read prelogin packet: %w", err)
	}

	if n > 8 && preloginBuf[0] == 0x12 {
		if _, err := backendConn.Write(preloginBuf[:n]); err != nil {
			return fmt.Errorf("failed to forward prelogin packet: %w", err)
		}

		responseBuf := make([]byte, 4096)
		n, err := backendConn.Read(responseBuf)
		if err != nil {
			return fmt.Errorf("failed to read prelogin response: %w", err)
		}

		if n > 8 && responseBuf[0] == 0x12 {
			if n > 35 && responseBuf[35] == 0x01 {
				tlsClient := tls.Server(clientConn, p.TLSConfig)
				if err := tlsClient.Handshake(); err != nil {
					return fmt.Errorf("TLS handshake with client failed: %w", err)
				}
				
				clientConn = tlsClient
			}
		}

		if _, err := clientConn.Write(responseBuf[:n]); err != nil {
			return fmt.Errorf("failed to forward prelogin response: %w", err)
		}
	} else {
		if _, err := backendConn.Write(preloginBuf[:n]); err != nil {
			return fmt.Errorf("failed to forward initial packet: %w", err)
		}
	}

	return nil
}