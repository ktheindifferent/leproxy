package dbproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	DefaultConnectTimeout = 10 * time.Second
	TLSHandshakeByte     = 0x16
)

type ProxyHandler interface {
	HandleProtocolNegotiation(clientConn, backendConn net.Conn) (net.Conn, net.Conn, error)
	GetProtocolName() string
}

type BaseProxy struct {
	Backend   string
	TLSConfig *tls.Config
	EnableTLS bool
	Handler   ProxyHandler
}

func NewBaseProxy(backend string, tlsConfig *tls.Config, handler ProxyHandler) *BaseProxy {
	return &BaseProxy{
		Backend:   backend,
		TLSConfig: tlsConfig,
		EnableTLS: tlsConfig != nil,
		Handler:   handler,
	}
}

func (p *BaseProxy) Serve(listener net.Listener) error {
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}
		go p.handleConnection(clientConn)
	}
}

func (p *BaseProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	backendConn, err := p.connectToBackend()
	if err != nil {
		log.Printf("Failed to connect to %s backend %s: %v", 
			p.Handler.GetProtocolName(), p.Backend, err)
		return
	}
	defer backendConn.Close()

	clientConn, backendConn, err = p.Handler.HandleProtocolNegotiation(clientConn, backendConn)
	if err != nil {
		log.Printf("Protocol negotiation failed for %s: %v", 
			p.Handler.GetProtocolName(), err)
		return
	}

	p.proxyConnections(clientConn, backendConn)
}

func (p *BaseProxy) connectToBackend() (net.Conn, error) {
	return net.DialTimeout("tcp", p.Backend, DefaultConnectTimeout)
}

func (p *BaseProxy) proxyConnections(clientConn, backendConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyData := func(dst, src net.Conn, direction string) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil && err != io.EOF {
			log.Printf("%s proxy %s error: %v", 
				p.Handler.GetProtocolName(), direction, err)
		}
	}

	go copyData(backendConn, clientConn, "client->backend")
	go copyData(clientConn, backendConn, "backend->client")

	wg.Wait()
}

func (p *BaseProxy) UpgradeToTLS(conn net.Conn) (*tls.Conn, error) {
	if p.TLSConfig == nil {
		return nil, fmt.Errorf("TLS not configured")
	}
	
	tlsConn := tls.Server(conn, p.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	
	return tlsConn, nil
}

func ReadBytes(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func IsTLSHandshake(data []byte) bool {
	return len(data) > 0 && data[0] == TLSHandshakeByte
}

type PrefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

func NewPrefixConn(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{
		Conn:   conn,
		prefix: prefix,
		offset: 0,
	}
}

func (c *PrefixConn) Read(b []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(b, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}