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

type RedisProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
}

func NewRedisProxy(backend string, tlsConfig *tls.Config) *RedisProxy {
	return &RedisProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
	}
}

func (p *RedisProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *RedisProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to Redis backend %s: %v", p.Backend, err)
		return
	}
	defer backendConn.Close()

	// Handle TLS if enabled
	if p.EnableTLS {
		// Check if client sends STARTTLS command
		clientReader := bufio.NewReader(clientConn)
		
		// Peek at the first command
		firstLine, err := clientReader.Peek(64)
		if err == nil && p.isStartTLSCommand(firstLine) {
			// Read the full STARTTLS command
			_, err := clientReader.ReadString('\n')
			if err != nil {
				log.Printf("Failed to read STARTTLS command: %v", err)
				return
			}

			// Send +OK response
			if _, err := clientConn.Write([]byte("+OK\r\n")); err != nil {
				log.Printf("Failed to send STARTTLS response: %v", err)
				return
			}

			// Upgrade to TLS
			tlsConn := tls.Server(clientConn, p.TLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake failed: %v", err)
				return
			}
			clientConn = tlsConn
			
			// Create new reader for TLS connection
			clientReader = bufio.NewReader(clientConn)
		} else {
			// No STARTTLS, but we can still offer TLS wrapper if client connects with TLS directly
			if p.EnableTLS {
				// Try to detect TLS handshake (starts with 0x16 for TLS)
				if len(firstLine) > 0 && firstLine[0] == 0x16 {
					tlsConn := tls.Server(clientConn, p.TLSConfig)
					if err := tlsConn.Handshake(); err != nil {
						// Not a TLS connection, continue with plain text
						log.Printf("Client connected without TLS, continuing with plain connection")
					} else {
						clientConn = tlsConn
						clientReader = bufio.NewReader(clientConn)
					}
				}
			}
		}

		// For connections that used a reader, we need to handle buffered data
		if clientReader != nil {
			errCh := make(chan error, 2)
			go func() {
				err := p.proxyWithReader(clientReader, clientConn, backendConn)
				errCh <- err
			}()
			go func() {
				_, err := io.Copy(clientConn, backendConn)
				if err != nil && err != io.EOF {
					log.Printf("Error copying from backend to client: %v", err)
				}
				errCh <- err
			}()
			
			// Wait for either direction to finish
			<-errCh
			return
		}
	}

	// Standard bidirectional copy for non-TLS or after TLS negotiation
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(backendConn, clientConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, backendConn)
		errCh <- err
	}()

	// Wait for either direction to finish
	<-errCh
}

func (p *RedisProxy) isStartTLSCommand(data []byte) bool {
	// Redis STARTTLS command in RESP protocol
	// Could be: *1\r\n$8\r\nSTARTTLS\r\n
	// Or simple: STARTTLS\r\n
	str := string(data)
	return strings.Contains(strings.ToUpper(str), "STARTTLS")
}

func (p *RedisProxy) proxyWithReader(reader *bufio.Reader, client, backend net.Conn) error {
	// First, flush any buffered data
	if reader.Buffered() > 0 {
		buffered, err := reader.Peek(reader.Buffered())
		if err == nil {
			if _, err := backend.Write(buffered); err != nil {
				return err
			}
			reader.Discard(len(buffered))
		}
	}
	
	// Then continue with regular copy
	_, err := io.Copy(backend, reader)
	if err != nil && err != io.EOF {
		log.Printf("Error copying from client to backend: %v", err)
	}
	return err
}