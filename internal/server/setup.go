package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/artyom/leproxy/internal/errors"
	"github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/safe"
	"golang.org/x/crypto/acme/autocert"
)

// Config holds the server configuration parameters
type Config struct {
	Addr        string
	HTTP        string
	Cache       string
	HSTS        bool
	Email       string
	Provider    string
	ACMEURL     string
	EABKID      string
	EABHMAC     string
	ReadTimeout time.Duration
	WriteTimeout time.Duration
	IdleTimeout time.Duration
}

// Builder provides a fluent interface for server construction
type Builder struct {
	config      *Config
	manager     *autocert.Manager
	handler     http.Handler
	tlsConfig   *tls.Config
}

// NewBuilder creates a new server builder
func NewBuilder(config *Config) *Builder {
	return &Builder{
		config: config,
	}
}

// WithCertManager sets the certificate manager
func (b *Builder) WithCertManager(manager *autocert.Manager) *Builder {
	b.manager = manager
	return b
}

// WithHandler sets the HTTP handler
func (b *Builder) WithHandler(handler http.Handler) *Builder {
	b.handler = handler
	return b
}

// WithTLSConfig sets the TLS configuration
func (b *Builder) WithTLSConfig(config *tls.Config) *Builder {
	b.tlsConfig = config
	return b
}

// Build creates the configured HTTP server
func (b *Builder) Build() (*http.Server, error) {
	if b.handler == nil {
		return nil, fmt.Errorf("handler is required")
	}

	srv := &http.Server{
		Addr:         b.config.Addr,
		Handler:      b.handler,
		ReadTimeout:  b.config.ReadTimeout,
		WriteTimeout: b.config.WriteTimeout,
		IdleTimeout:  b.config.IdleTimeout,
	}

	if b.tlsConfig != nil {
		srv.TLSConfig = b.tlsConfig
	} else if b.manager != nil {
		srv.TLSConfig = b.manager.TLSConfig()
	}

	return srv, nil
}

// StartHTTPS starts the HTTPS server
func StartHTTPS(srv *http.Server, idleTimeout time.Duration) error {
	logger.Info("Starting HTTPS server", "address", srv.Addr)
	
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return errors.Wrap(err, errors.ErrConnection, "failed to listen on address")
	}

	if idleTimeout > 0 {
		tcpLn, err := safe.AssertTCPListener(ln)
		if err != nil {
			return errors.Wrap(err, errors.ErrConnection, "failed to setup keep-alive")
		}
		ln = &tcpKeepAliveListener{
			TCPListener: tcpLn,
			timeout:     idleTimeout,
		}
	}

	return srv.ServeTLS(ln, "", "")
}

// StartHTTPRedirect starts the HTTP redirect server
func StartHTTPRedirect(addr string, handler http.Handler) error {
	if addr == "" {
		return nil
	}

	logger.Info("Starting HTTP redirect server", "address", addr)
	
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP redirect server failed", "error", err)
		}
	}()

	return nil
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted connections
type tcpKeepAliveListener struct {
	*net.TCPListener
	timeout time.Duration
}

func (ln *tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(ln.timeout)
	return tc, nil
}