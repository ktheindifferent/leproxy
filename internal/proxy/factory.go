package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/artyom/leproxy/dbproxy"
	// "github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/safegoroutine"
)

// Type represents the database proxy type
type Type string

// Database proxy type constants
const (
	TypeMySQL        Type = "mysql"
	TypePostgres     Type = "postgres"
	TypeMongoDB      Type = "mongodb"
	TypeRedis        Type = "redis"
	TypeCassandra    Type = "cassandra"
	TypeElastic      Type = "elasticsearch"
	TypeMemcached    Type = "memcached"
	TypeKafka        Type = "kafka"
	TypeRabbitMQ     Type = "rabbitmq"
	TypeMSSQL        Type = "mssql"
	TypeFTP          Type = "ftp"
	TypeSMTP         Type = "smtp"
	TypeLDAP         Type = "ldap"
)

// Config holds proxy configuration
type Config struct {
	ListenAddr     string
	Backend        string
	Type           Type
	TLSConfig      *TLSConfig
	MaxConnections int           // Maximum concurrent connections (0 = unlimited)
	DrainTimeout   time.Duration // Timeout for graceful shutdown (default 30s)
}

// TLSConfig holds TLS configuration for proxies
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
	Insecure bool
}

// Factory creates database proxy instances
type Factory struct {
	registry map[Type]ProxyCreator
	mu       sync.RWMutex
}

// ProxyCreator is a function that creates a proxy instance
type ProxyCreator func(config *Config) (Proxy, error)

// Proxy interface for all database proxies
type Proxy interface {
	Start() error
	Stop() error
	GracefulStop(timeout time.Duration) error
	GetType() Type
	GetListenAddr() string
	GetStats() map[string]interface{}
	IsHealthy() bool
}

// NewFactory creates a new proxy factory
func NewFactory() *Factory {
	f := &Factory{
		registry: make(map[Type]ProxyCreator),
	}
	f.registerDefaultProxies()
	return f
}

// Register registers a new proxy creator
func (f *Factory) Register(proxyType Type, creator ProxyCreator) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registry[proxyType] = creator
}

// Create creates a new proxy instance
func (f *Factory) Create(config *Config) (Proxy, error) {
	f.mu.RLock()
	creator, exists := f.registry[config.Type]
	f.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown proxy type: %s", config.Type)
	}

	return creator(config)
}

// GetSupportedTypes returns all supported proxy types
func (f *Factory) GetSupportedTypes() []Type {
	f.mu.RLock()
	defer f.mu.RUnlock()

	types := make([]Type, 0, len(f.registry))
	for t := range f.registry {
		types = append(types, t)
	}
	return types
}

func (f *Factory) registerDefaultProxies() {
	// MySQL proxy
	f.Register(TypeMySQL, func(config *Config) (Proxy, error) {
		return &mysqlProxy{
			baseProxy: baseProxy{config: config},
			proxy:     dbproxy.NewMySQLProxy(config.Backend, nil),
		}, nil
	})

	// PostgreSQL proxy
	f.Register(TypePostgres, func(config *Config) (Proxy, error) {
		return &postgresProxy{
			baseProxy: baseProxy{config: config},
			proxy:     dbproxy.NewPostgresProxy(config.Backend, nil),
		}, nil
	})

	// MongoDB proxy
	f.Register(TypeMongoDB, func(config *Config) (Proxy, error) {
		return &mongoProxy{
			baseProxy: baseProxy{config: config},
			proxy:     dbproxy.NewMongoDBProxy(config.Backend, nil),
		}, nil
	})

	// Redis proxy
	f.Register(TypeRedis, func(config *Config) (Proxy, error) {
		return &redisProxy{
			baseProxy: baseProxy{config: config},
			proxy:     dbproxy.NewRedisProxy(config.Backend, nil),
		}, nil
	})

	// Additional proxy registrations...
}

// ProxyManager manages multiple proxy instances
type ProxyManager struct {
	factory *Factory
	proxies map[string]Proxy
	mu      sync.RWMutex
}

// Global proxy manager instance
var globalManager *ProxyManager

// NewManager creates a new proxy manager
func NewManager(factory *Factory) *ProxyManager {
	return &ProxyManager{
		factory: factory,
		proxies: make(map[string]Proxy),
	}
}

// GetGlobalManager returns the global proxy manager instance
func GetGlobalManager() *ProxyManager {
	return globalManager
}

// SetGlobalManager sets the global proxy manager instance
func SetGlobalManager(manager *ProxyManager) {
	globalManager = manager
}

// StartProxy starts a new proxy instance
func (m *ProxyManager) StartProxy(config *Config) error {
	proxy, err := m.factory.Create(config)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	if err := proxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	m.mu.Lock()
	m.proxies[config.ListenAddr] = proxy
	m.mu.Unlock()

	// logger.Info("Proxy started", map[string]interface{}{
	// 	"type": config.Type,
	// 	"listen": config.ListenAddr,
	// 	"backend": config.Backend,
	// })

	return nil
}

// StopProxy stops a proxy instance gracefully
func (m *ProxyManager) StopProxy(addr string) error {
	return m.StopProxyWithTimeout(addr, 30*time.Second)
}

// StopProxyWithTimeout stops a proxy instance with custom timeout
func (m *ProxyManager) StopProxyWithTimeout(addr string, timeout time.Duration) error {
	m.mu.Lock()
	proxy, exists := m.proxies[addr]
	if exists {
		delete(m.proxies, addr)
	}
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("proxy not found: %s", addr)
	}

	// logger.Info("Stopping proxy gracefully", map[string]interface{}{
	// 	"addr": addr,
	// 	"timeout": timeout,
	// })
	return proxy.GracefulStop(timeout)
}

// StopAll stops all proxy instances gracefully
func (m *ProxyManager) StopAll() {
	m.StopAllWithTimeout(30 * time.Second)
}

// StopAllWithTimeout stops all proxy instances with custom timeout
func (m *ProxyManager) StopAllWithTimeout(timeout time.Duration) {
	m.mu.Lock()
	proxies := make([]Proxy, 0, len(m.proxies))
	for _, p := range m.proxies {
		proxies = append(proxies, p)
	}
	m.proxies = make(map[string]Proxy)
	m.mu.Unlock()

	// logger.Info("Stopping all proxies gracefully", map[string]interface{}{
	// 	"count": len(proxies),
	// 	"timeout": timeout,
	// })
	
	// Stop all proxies concurrently
	var wg sync.WaitGroup
	for _, proxy := range proxies {
		proxy := proxy
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.GracefulStop(timeout); err != nil {
				// logger.Error("Failed to stop proxy gracefully", map[string]interface{}{
				// 	"type": proxy.GetType(),
				// 	"addr": proxy.GetListenAddr(),
				// 	"error": err,
				// })
			}
		}()
	}
	
	// Wait for all to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// logger.Info("All proxies stopped successfully")
	case <-time.After(timeout + 5*time.Second):
		// logger.Error("Timeout waiting for all proxies to stop")
	}
}

// GetStatus returns the status of all proxies
func (m *ProxyManager) GetStatus() map[string]ProxyStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]ProxyStatus)
	for addr, proxy := range m.proxies {
		stats := proxy.GetStats()
		
		// Extract connection count from stats
		var activeConns int
		if v, ok := stats["active_connections"].(int32); ok {
			activeConns = int(v)
		}
		
		// Extract bytes from stats
		var bytesIn, bytesOut int64
		if v, ok := stats["total_bytes_in"].(uint64); ok {
			bytesIn = int64(v)
		}
		if v, ok := stats["total_bytes_out"].(uint64); ok {
			bytesOut = int64(v)
		}
		
		status[addr] = ProxyStatus{
			Type:        proxy.GetType(),
			ListenAddr:  proxy.GetListenAddr(),
			Running:     proxy.IsHealthy(),
			Connections: activeConns,
			BytesIn:     bytesIn,
			BytesOut:    bytesOut,
		}
	}
	return status
}

// ProxyStatus represents the status of a proxy
type ProxyStatus struct {
	Type        Type
	ListenAddr  string
	Running     bool
	Connections int
	BytesIn     int64
	BytesOut    int64
}

// GetHealthStatus returns health status for all proxies
func (m *ProxyManager) GetHealthStatus() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	health := make(map[string]bool)
	for addr, proxy := range m.proxies {
		health[addr] = proxy.IsHealthy()
	}
	return health
}

// GetDetailedStats returns detailed statistics for a specific proxy
func (m *ProxyManager) GetDetailedStats(addr string) (map[string]interface{}, error) {
	m.mu.RLock()
	proxy, exists := m.proxies[addr]
	m.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("proxy not found: %s", addr)
	}
	
	return proxy.GetStats(), nil
}

// Base proxy implementations

type baseProxy struct {
	config      *Config
	listener    net.Listener
	connTracker *ConnectionTracker
	shutdownCtx context.Context
	shutdownFn  context.CancelFunc
	closed      atomic.Bool
	wg          sync.WaitGroup
}

func (p *baseProxy) initBase() {
	maxConns := p.config.MaxConnections
	if maxConns <= 0 {
		maxConns = 1000 // Default max connections
	}
	drainTimeout := p.config.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = 30 * time.Second
	}
	
	p.connTracker = NewConnectionTracker(maxConns, drainTimeout)
	p.shutdownCtx, p.shutdownFn = context.WithCancel(context.Background())
}

func (p *baseProxy) GetType() Type {
	return p.config.Type
}

func (p *baseProxy) GetListenAddr() string {
	return p.config.ListenAddr
}

func (p *baseProxy) GetStats() map[string]interface{} {
	if p.connTracker != nil {
		return p.connTracker.GetStats()
	}
	return map[string]interface{}{"status": "no tracker"}
}

func (p *baseProxy) IsHealthy() bool {
	if p.closed.Load() {
		return false
	}
	if p.connTracker != nil {
		return p.connTracker.IsHealthy()
	}
	return true
}

func (p *baseProxy) Stop() error {
	return p.GracefulStop(5 * time.Second)
}

func (p *baseProxy) GracefulStop(timeout time.Duration) error {
	if p.closed.Load() {
		return nil
	}
	
	p.closed.Store(true)
	// logger.Info("Stopping proxy", map[string]interface{}{
	// 	"type": p.config.Type,
	// 	"addr": p.config.ListenAddr,
	// })
	
	// Close listener first to stop accepting new connections
	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			// logger.Warn("Error closing listener", map[string]interface{}{
			// 	"error": err,
			// })
		}
	}
	
	// Signal shutdown to all goroutines
	if p.shutdownFn != nil {
		p.shutdownFn()
	}
	
	// Close all connections with timeout
	if p.connTracker != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := p.connTracker.CloseAll(ctx); err != nil {
			// logger.Warn("Error during connection draining", map[string]interface{}{
			// 	"error": err,
			// })
			return err
		}
	}
	
	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		// logger.Warn("Graceful stop timeout exceeded", map[string]interface{}{
		// 	"type": p.config.Type,
		// })
		return fmt.Errorf("graceful stop timeout")
	}
}

// Specific proxy implementations

type mysqlProxy struct {
	baseProxy
	proxy *dbproxy.MySQLProxy
}

func (p *mysqlProxy) Start() error {
	p.initBase()
	
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	// Set proxy type for the underlying proxy
	p.proxy.BaseProxy.SetProxyType(string(TypeMySQL))
	p.proxy.BaseProxy.SetConnectionTracker(p.connTracker)
	
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptLoop(ln)
	}()
	
	return nil
}

func (p *mysqlProxy) acceptLoop(ln net.Listener) {
	for {
		// Check for shutdown
		select {
		case <-p.shutdownCtx.Done():
			return
		default:
		}
		
		// Apply backpressure if needed
		if p.connTracker.ShouldPauseAccept() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		conn, err := ln.Accept()
		if err != nil {
			if p.closed.Load() {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// logger.Debug("Temporary accept error", map[string]interface{}{
				// 	"error": err,
				// })
				time.Sleep(10 * time.Millisecond)
				continue
			}
			// logger.Error("Accept error", map[string]interface{}{
			// 	"error": err,
			// })
			return
		}
		
		// Track connection
		connInfo, err := p.connTracker.Track(conn, TypeMySQL)
		if err != nil {
			// logger.Warn("Connection rejected", map[string]interface{}{
			// 	"error": err,
			// 	"remote": conn.RemoteAddr(),
			// })
			conn.Close()
			continue
		}
		
		p.wg.Add(1)
		safegoroutine.Go(fmt.Sprintf("mysql-handler-%s", conn.RemoteAddr()), func() {
			defer p.wg.Done()
			defer p.connTracker.Untrack(conn)
			defer conn.Close()
			// Handle connection through the proxy's internal method
			// p.proxy doesn't have Handle, needs to be implemented differently
			// Update activity for the connection
			p.connTracker.UpdateActivity(conn, connInfo.BytesIn.Load(), connInfo.BytesOut.Load())
		})
	}
}

type postgresProxy struct {
	baseProxy
	proxy *dbproxy.PostgresProxy
}

func (p *postgresProxy) Start() error {
	p.initBase()
	
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	// Set proxy type for the underlying proxy
	p.proxy.BaseProxy.SetProxyType(string(TypePostgres))
	p.proxy.BaseProxy.SetConnectionTracker(p.connTracker)
	
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptLoop(ln)
	}()
	
	return nil
}

func (p *postgresProxy) acceptLoop(ln net.Listener) {
	for {
		// Check for shutdown
		select {
		case <-p.shutdownCtx.Done():
			return
		default:
		}
		
		// Apply backpressure if needed
		if p.connTracker.ShouldPauseAccept() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		conn, err := ln.Accept()
		if err != nil {
			if p.closed.Load() {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// logger.Debug("Temporary accept error", map[string]interface{}{
				// 	"error": err,
				// })
				time.Sleep(10 * time.Millisecond)
				continue
			}
			// logger.Error("Accept error", map[string]interface{}{
			// 	"error": err,
			// })
			return
		}
		
		// Track connection
		connInfo, err := p.connTracker.Track(conn, TypePostgres)
		if err != nil {
			// logger.Warn("Connection rejected", map[string]interface{}{
			// 	"error": err,
			// 	"remote": conn.RemoteAddr(),
			// })
			conn.Close()
			continue
		}
		
		p.wg.Add(1)
		safegoroutine.Go(fmt.Sprintf("postgres-handler-%s", conn.RemoteAddr()), func() {
			defer p.wg.Done()
			defer p.connTracker.Untrack(conn)
			defer conn.Close()
			// Handle connection through the proxy's internal method
			// p.proxy doesn't have Handle, needs to be implemented differently
			// Update activity for the connection
			p.connTracker.UpdateActivity(conn, connInfo.BytesIn.Load(), connInfo.BytesOut.Load())
		})
	}
}

type mongoProxy struct {
	baseProxy
	proxy *dbproxy.MongoDBProxy
}

func (p *mongoProxy) Start() error {
	p.initBase()
	
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	// Set proxy type for the underlying proxy
	p.proxy.BaseProxy.SetProxyType(string(TypeMongoDB))
	p.proxy.BaseProxy.SetConnectionTracker(p.connTracker)
	
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptLoop(ln)
	}()
	
	return nil
}

func (p *mongoProxy) acceptLoop(ln net.Listener) {
	for {
		// Check for shutdown
		select {
		case <-p.shutdownCtx.Done():
			return
		default:
		}
		
		// Apply backpressure if needed
		if p.connTracker.ShouldPauseAccept() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		conn, err := ln.Accept()
		if err != nil {
			if p.closed.Load() {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// logger.Debug("Temporary accept error", map[string]interface{}{
				// 	"error": err,
				// })
				time.Sleep(10 * time.Millisecond)
				continue
			}
			// logger.Error("Accept error", map[string]interface{}{
			// 	"error": err,
			// })
			return
		}
		
		// Track connection
		connInfo, err := p.connTracker.Track(conn, TypeMongoDB)
		if err != nil {
			// logger.Warn("Connection rejected", map[string]interface{}{
			// 	"error": err,
			// 	"remote": conn.RemoteAddr(),
			// })
			conn.Close()
			continue
		}
		
		p.wg.Add(1)
		safegoroutine.Go(fmt.Sprintf("mongo-handler-%s", conn.RemoteAddr()), func() {
			defer p.wg.Done()
			defer p.connTracker.Untrack(conn)
			defer conn.Close()
			// Handle connection through the proxy's internal method
			// p.proxy doesn't have Handle, needs to be implemented differently
			// Update activity for the connection
			p.connTracker.UpdateActivity(conn, connInfo.BytesIn.Load(), connInfo.BytesOut.Load())
		})
	}
}

type redisProxy struct {
	baseProxy
	proxy *dbproxy.RedisProxy
}

func (p *redisProxy) Start() error {
	p.initBase()
	
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	// Set proxy type for the underlying proxy
	p.proxy.BaseProxy.SetProxyType(string(TypeRedis))
	p.proxy.BaseProxy.SetConnectionTracker(p.connTracker)
	
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptLoop(ln)
	}()
	
	return nil
}

func (p *redisProxy) acceptLoop(ln net.Listener) {
	for {
		// Check for shutdown
		select {
		case <-p.shutdownCtx.Done():
			return
		default:
		}
		
		// Apply backpressure if needed
		if p.connTracker.ShouldPauseAccept() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		conn, err := ln.Accept()
		if err != nil {
			if p.closed.Load() {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// logger.Debug("Temporary accept error", map[string]interface{}{
				// 	"error": err,
				// })
				time.Sleep(10 * time.Millisecond)
				continue
			}
			// logger.Error("Accept error", map[string]interface{}{
			// 	"error": err,
			// })
			return
		}
		
		// Track connection
		connInfo, err := p.connTracker.Track(conn, TypeRedis)
		if err != nil {
			// logger.Warn("Connection rejected", map[string]interface{}{
			// 	"error": err,
			// 	"remote": conn.RemoteAddr(),
			// })
			conn.Close()
			continue
		}
		
		p.wg.Add(1)
		safegoroutine.Go(fmt.Sprintf("redis-handler-%s", conn.RemoteAddr()), func() {
			defer p.wg.Done()
			defer p.connTracker.Untrack(conn)
			defer conn.Close()
			// Handle connection through the proxy's internal method
			// p.proxy doesn't have Handle, needs to be implemented differently
			// Update activity for the connection
			p.connTracker.UpdateActivity(conn, connInfo.BytesIn.Load(), connInfo.BytesOut.Load())
		})
	}
}

// ParseProxyType parses a string into a proxy type
func ParseProxyType(s string) (Type, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	
	typeMap := map[string]Type{
		"mysql":         TypeMySQL,
		"postgres":      TypePostgres,
		"postgresql":    TypePostgres,
		"mongodb":       TypeMongoDB,
		"mongo":         TypeMongoDB,
		"redis":         TypeRedis,
		"cassandra":     TypeCassandra,
		"elasticsearch": TypeElastic,
		"elastic":       TypeElastic,
		"memcached":     TypeMemcached,
		"kafka":         TypeKafka,
		"rabbitmq":      TypeRabbitMQ,
		"mssql":         TypeMSSQL,
		"sqlserver":     TypeMSSQL,
		"ftp":           TypeFTP,
		"smtp":          TypeSMTP,
		"ldap":          TypeLDAP,
	}
	
	if proxyType, ok := typeMap[normalized]; ok {
		return proxyType, nil
	}
	
	return "", fmt.Errorf("unknown proxy type: %s", s)
}