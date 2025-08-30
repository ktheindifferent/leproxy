package tests

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
	
	"github.com/artyom/leproxy/internal/acme"
	"github.com/artyom/leproxy/internal/certbackup"
	"github.com/artyom/leproxy/internal/graceful"
	"github.com/artyom/leproxy/internal/health"
	"github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/metrics"
	"github.com/artyom/leproxy/internal/pool"
	"github.com/artyom/leproxy/internal/proxy"
	"github.com/artyom/leproxy/internal/ratelimit"
	"github.com/artyom/leproxy/internal/reload"
	"github.com/artyom/leproxy/internal/security"
	"github.com/artyom/leproxy/internal/websocket"
)

// TestGracefulShutdown tests the complete graceful shutdown sequence
func TestGracefulShutdown(t *testing.T) {
	// Initialize logger for testing
	logger.SetLevel("debug")
	
	// Create test HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	srv := &http.Server{
		Addr:    ":0", // Random port
		Handler: mux,
	}
	
	// Create graceful server configuration
	cfg := graceful.Config{
		HTTPServer:      srv,
		ShutdownTimeout: 5 * time.Second,
		ReloadFunc: func() error {
			t.Log("Configuration reload triggered")
			return nil
		},
	}
	
	gracefulServer := graceful.New(cfg)
	coordinator := graceful.NewShutdownCoordinator(gracefulServer, 10*time.Second)
	
	// Start metrics server
	metricsServer := metrics.NewServer(":0")
	go func() {
		if err := metricsServer.Start(); err != nil && err != http.ErrServerClosed {
			t.Logf("Metrics server error: %v", err)
		}
	}()
	
	// Register all shutdown hooks
	registerTestShutdownHooks(t, coordinator, metricsServer)
	
	// Give servers time to start
	time.Sleep(100 * time.Millisecond)
	
	// Trigger shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	shutdownStart := time.Now()
	err := coordinator.Shutdown(ctx)
	shutdownDuration := time.Since(shutdownStart)
	
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
	
	t.Logf("Graceful shutdown completed in %v", shutdownDuration)
	
	// Verify all resources are cleaned up
	verifyResourcesCleanedUp(t)
}

// TestShutdownWithActiveConnections tests shutdown behavior with active connections
func TestShutdownWithActiveConnections(t *testing.T) {
	// Create connection pool
	poolCfg := pool.Config{
		Factory: func(ctx context.Context) (net.Conn, error) {
			// Mock connection factory
			return &mockConn{}, nil
		},
		MinConns:    2,
		MaxConns:    10,
		MaxLifetime: 30 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	}
	
	testPool, err := pool.New(poolCfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	
	// Register pool
	pool.Register("test-pool", testPool)
	
	// Get some connections to simulate active usage
	ctx := context.Background()
	conns := make([]net.Conn, 3)
	for i := range conns {
		conn, err := testPool.Get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection: %v", err)
		}
		conns[i] = conn
	}
	
	// Create shutdown coordinator
	coordinator := graceful.NewShutdownCoordinator(nil, 5*time.Second)
	
	// Add pool shutdown hook
	coordinator.AddShutdownFunc("test-pools", func(ctx context.Context) error {
		return pool.ShutdownAll(ctx)
	}, 3*time.Second)
	
	// Start shutdown in background
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- coordinator.Shutdown(ctx)
	}()
	
	// Return connections after a delay
	go func() {
		time.Sleep(1 * time.Second)
		for _, conn := range conns {
			conn.Close()
		}
	}()
	
	// Wait for shutdown
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Errorf("Shutdown with active connections failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Error("Shutdown timeout with active connections")
	}
	
	// Verify pool is closed
	stats := pool.GlobalRegistry().GetStats()
	if len(stats) != 0 {
		t.Error("Pool registry should be empty after shutdown")
	}
}

// TestConfigurationReload tests hot configuration reload
func TestConfigurationReload(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-config.yml")
	
	initialConfig := `
mappings:
  example.com: localhost:8080
  test.com: localhost:8081
`
	if err := os.WriteFile(configFile, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}
	
	// Create config reloader
	reloader := reload.NewConfigReloader(configFile, 1*time.Second)
	reload.SetGlobalReloader(reloader)
	
	// Start reloader
	reloader.Start()
	defer reloader.Stop()
	
	// Register reload handler
	reloadCalled := make(chan bool, 1)
	reloader.RegisterReloadHandler(func(old, new map[string]string) error {
		t.Logf("Config reloaded: %d -> %d mappings", len(old), len(new))
		reloadCalled <- true
		return nil
	})
	
	// Give initial load time
	time.Sleep(100 * time.Millisecond)
	
	// Update configuration
	updatedConfig := `
mappings:
  example.com: localhost:8080
  test.com: localhost:8082
  new.com: localhost:8083
`
	if err := os.WriteFile(configFile, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}
	
	// Wait for reload
	select {
	case <-reloadCalled:
		t.Log("Configuration reloaded successfully")
	case <-time.After(3 * time.Second):
		t.Error("Configuration reload timeout")
	}
	
	// Verify new mappings
	mappings := reloader.GetMappings()
	if len(mappings) != 3 {
		t.Errorf("Expected 3 mappings, got %d", len(mappings))
	}
	
	if backend, ok := reloader.GetMapping("new.com"); !ok || backend != "localhost:8083" {
		t.Errorf("New mapping not found or incorrect: %v", backend)
	}
}

// TestInvalidConfigurationReload tests reload with invalid configuration
func TestInvalidConfigurationReload(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-config.yml")
	
	validConfig := `
mappings:
  example.com: localhost:8080
`
	if err := os.WriteFile(configFile, []byte(validConfig), 0644); err != nil {
		t.Fatalf("Failed to write valid config: %v", err)
	}
	
	// Create config reloader
	reloader := reload.NewConfigReloader(configFile, 1*time.Second)
	
	// Start reloader
	reloader.Start()
	defer reloader.Stop()
	
	// Get initial mappings
	time.Sleep(100 * time.Millisecond)
	initialMappings := reloader.GetMappings()
	
	// Write invalid configuration
	invalidConfig := `
mappings:
  [invalid yaml content
`
	if err := os.WriteFile(configFile, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to write invalid config: %v", err)
	}
	
	// Wait for reload attempt
	time.Sleep(2 * time.Second)
	
	// Verify mappings haven't changed
	currentMappings := reloader.GetMappings()
	if len(currentMappings) != len(initialMappings) {
		t.Error("Mappings should not change with invalid configuration")
	}
	
	// Write another valid configuration
	newValidConfig := `
mappings:
  example.com: localhost:8090
  another.com: localhost:8091
`
	if err := os.WriteFile(configFile, []byte(newValidConfig), 0644); err != nil {
		t.Fatalf("Failed to write new valid config: %v", err)
	}
	
	// Wait for reload
	time.Sleep(2 * time.Second)
	
	// Verify new mappings are loaded
	finalMappings := reloader.GetMappings()
	if len(finalMappings) != 2 {
		t.Errorf("Expected 2 mappings after recovery, got %d", len(finalMappings))
	}
}

// TestMetricsServerShutdown tests metrics server graceful shutdown
func TestMetricsServerShutdown(t *testing.T) {
	// Create metrics server
	metricsServer := metrics.NewServer(":0")
	
	// Start server
	serverStarted := make(chan bool)
	go func() {
		serverStarted <- true
		if err := metricsServer.Start(); err != nil && err != http.ErrServerClosed {
			t.Logf("Metrics server error: %v", err)
		}
	}()
	
	<-serverStarted
	time.Sleep(100 * time.Millisecond)
	
	// Stop server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := metricsServer.Stop(ctx); err != nil {
		t.Errorf("Failed to stop metrics server: %v", err)
	}
	
	// Try to stop again (should be idempotent)
	if err := metricsServer.Stop(ctx); err != nil {
		t.Errorf("Second stop should not error: %v", err)
	}
}

// Helper functions

func registerTestShutdownHooks(t *testing.T, coordinator *graceful.ShutdownCoordinator, metricsServer *metrics.Server) {
	// Connection pools
	coordinator.AddShutdownFunc("connection-pools", func(ctx context.Context) error {
		t.Log("Shutting down connection pools")
		return pool.ShutdownAll(ctx)
	}, 5*time.Second)
	
	// Metrics server
	if metricsServer != nil {
		coordinator.AddShutdownFunc("metrics-server", func(ctx context.Context) error {
			t.Log("Shutting down metrics server")
			return metricsServer.Stop(ctx)
		}, 5*time.Second)
	}
	
	// Certificate cache
	coordinator.AddShutdownFunc("certificate-cache", func(ctx context.Context) error {
		t.Log("Cleaning up certificate cache")
		if certMgr := acme.GetGlobalManager(); certMgr != nil {
			return certMgr.CleanupExpired()
		}
		return nil
	}, 5*time.Second)
	
	// Health server
	coordinator.AddShutdownFunc("health-server", func(ctx context.Context) error {
		t.Log("Shutting down health server")
		if healthServer := health.GetGlobalServer(); healthServer != nil {
			return healthServer.Shutdown(ctx)
		}
		return nil
	}, 5*time.Second)
	
	// WebSocket proxy
	coordinator.AddShutdownFunc("websocket-proxy", func(ctx context.Context) error {
		t.Log("Closing WebSocket proxy")
		if wsProxy := websocket.GetGlobalProxy(); wsProxy != nil {
			return (*wsProxy).Close()
		}
		return nil
	}, 5*time.Second)
	
	// Rate limiter
	coordinator.AddShutdownFunc("rate-limiter", func(ctx context.Context) error {
		t.Log("Stopping rate limiter")
		if limiter := ratelimit.GetGlobalLimiter(); limiter != nil {
			limiter.Stop()
		}
		return nil
	}, 3*time.Second)
	
	// Security scanner
	coordinator.AddShutdownFunc("security-scanner", func(ctx context.Context) error {
		t.Log("Stopping security scanner")
		if scanner := security.GetGlobalScanner(); scanner != nil {
			scanner.Stop()
		}
		return nil
	}, 3*time.Second)
}

func verifyResourcesCleanedUp(t *testing.T) {
	// Check pool registry
	poolStats := pool.GlobalRegistry().GetStats()
	if len(poolStats) > 0 {
		t.Errorf("Pool registry not empty: %d pools remaining", len(poolStats))
	}
	
	// Check global instances are cleaned
	if proxy.GetGlobalManager() != nil {
		proxies := proxy.GetGlobalManager().GetStatus()
		if len(proxies) > 0 {
			t.Errorf("Proxy manager has %d active proxies", len(proxies))
		}
	}
}

// mockConn is a mock implementation of net.Conn for testing
type mockConn struct {
	closed bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, fmt.Errorf("connection closed")
	}
	return 0, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, fmt.Errorf("connection closed")
	}
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}