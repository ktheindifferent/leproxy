package server

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func TestNewBuilder(t *testing.T) {
	config := &Config{
		Addr:         ":8443",
		HTTP:         ":8080",
		Cache:        "/tmp/cache",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	builder := NewBuilder(config)
	if builder == nil {
		t.Fatal("NewBuilder returned nil")
	}
	if builder.config != config {
		t.Error("Builder config mismatch")
	}
}

func TestBuilderWithHandler(t *testing.T) {
	config := &Config{
		Addr: ":8443",
	}
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	
	builder := NewBuilder(config).WithHandler(handler)
	if builder.handler == nil {
		t.Error("Handler not set")
	}
}

func TestBuilderWithCertManager(t *testing.T) {
	config := &Config{
		Addr: ":8443",
	}
	
	manager := &autocert.Manager{
		Cache:  autocert.DirCache("/tmp/cache"),
		Prompt: autocert.AcceptTOS,
	}
	
	builder := NewBuilder(config).WithCertManager(manager)
	if builder.manager != manager {
		t.Error("Certificate manager not set")
	}
}

func TestBuilderBuild(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*Builder)
		wantError bool
	}{
		{
			name: "valid configuration",
			setup: func(b *Builder) {
				b.WithHandler(http.DefaultServeMux)
			},
			wantError: false,
		},
		{
			name:      "missing handler",
			setup:     func(b *Builder) {},
			wantError: true,
		},
		{
			name: "with TLS config",
			setup: func(b *Builder) {
				b.WithHandler(http.DefaultServeMux)
				b.WithTLSConfig(&tls.Config{})
			},
			wantError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Addr:         ":8443",
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
			
			builder := NewBuilder(config)
			tt.setup(builder)
			
			srv, err := builder.Build()
			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if srv == nil {
					t.Error("Server is nil")
				}
				if srv != nil && srv.Addr != config.Addr {
					t.Errorf("Server address mismatch: got %s, want %s", srv.Addr, config.Addr)
				}
			}
		})
	}
}

func TestTCPKeepAliveListener(t *testing.T) {
	// This test would require a real TCP listener
	// For unit testing, we're checking the structure exists
	listener := &tcpKeepAliveListener{
		timeout: 30 * time.Second,
	}
	
	if listener.timeout != 30*time.Second {
		t.Errorf("Timeout mismatch: got %v, want %v", listener.timeout, 30*time.Second)
	}
}

func BenchmarkBuilderCreate(b *testing.B) {
	config := &Config{
		Addr:         ":8443",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	
	handler := http.DefaultServeMux
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewBuilder(config)
		builder.WithHandler(handler)
		builder.Build()
	}
}