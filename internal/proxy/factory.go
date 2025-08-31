package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/artyom/leproxy/dbproxy"
	"github.com/artyom/leproxy/internal/logger"
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
	ListenAddr string
	Backend    string
	Type       Type
	TLSConfig  *TLSConfig
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
	Start(ctx context.Context) error
	Stop() error
	GetType() Type
	GetListenAddr() string
	GetActiveConnections() int32
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
			config: config,
			proxy:  dbproxy.NewMySQLProxy(config.Backend),
		}, nil
	})

	// PostgreSQL proxy
	f.Register(TypePostgres, func(config *Config) (Proxy, error) {
		return &postgresProxy{
			config: config,
			proxy:  dbproxy.NewPostgresProxy(config.Backend),
		}, nil
	})

	// MongoDB proxy
	f.Register(TypeMongoDB, func(config *Config) (Proxy, error) {
		return &mongoProxy{
			config: config,
			proxy:  dbproxy.NewMongoDBProxy(config.Backend),
		}, nil
	})

	// Redis proxy
	f.Register(TypeRedis, func(config *Config) (Proxy, error) {
		return &redisProxy{
			config: config,
			proxy:  dbproxy.NewRedisProxy(config.Backend),
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
	return m.StartProxyWithContext(context.Background(), config)
}

// StartProxyWithContext starts a new proxy instance with context
func (m *ProxyManager) StartProxyWithContext(ctx context.Context, config *Config) error {
	proxy, err := m.factory.Create(config)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	if err := proxy.Start(ctx); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	m.mu.Lock()
	m.proxies[config.ListenAddr] = proxy
	m.mu.Unlock()

	logger.Info("Proxy started", 
		"type", config.Type,
		"listen", config.ListenAddr,
		"backend", config.Backend)

	return nil
}

// StopProxy stops a proxy instance
func (m *ProxyManager) StopProxy(addr string) error {
	m.mu.Lock()
	proxy, exists := m.proxies[addr]
	if exists {
		delete(m.proxies, addr)
	}
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("proxy not found: %s", addr)
	}

	return proxy.Stop()
}

// StopAll stops all proxy instances
func (m *ProxyManager) StopAll() {
	m.mu.Lock()
	proxies := make([]Proxy, 0, len(m.proxies))
	for _, p := range m.proxies {
		proxies = append(proxies, p)
	}
	m.proxies = make(map[string]Proxy)
	m.mu.Unlock()

	for _, proxy := range proxies {
		if err := proxy.Stop(); err != nil {
			logger.Error("Failed to stop proxy", "error", err)
		}
	}
}

// GetStatus returns the status of all proxies
func (m *ProxyManager) GetStatus() map[string]ProxyStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]ProxyStatus)
	for addr, proxy := range m.proxies {
		status[addr] = ProxyStatus{
			Type:       proxy.GetType(),
			ListenAddr: proxy.GetListenAddr(),
			Running:    true,
			Connections: int(proxy.GetActiveConnections()),
		}
	}
	return status
}

// ProxyStatus represents the status of a proxy
type ProxyStatus struct {
	Type       Type
	ListenAddr string
	Running    bool
	Connections int
	BytesIn    int64
	BytesOut   int64
}

// Base proxy implementations

type baseProxy struct {
	config            *Config
	listener          net.Listener
	stopped           chan struct{}
	ctx               context.Context
	cancel            context.CancelFunc
	activeConnections atomic.Int32
	connectionWg      sync.WaitGroup
}

func (p *baseProxy) GetType() Type {
	return p.config.Type
}

func (p *baseProxy) GetListenAddr() string {
	return p.config.ListenAddr
}

func (p *baseProxy) GetActiveConnections() int32 {
	return p.activeConnections.Load()
}

func (p *baseProxy) Stop() error {
	// Signal shutdown
	if p.cancel != nil {
		p.cancel()
	}
	
	// Close the listener to stop accepting new connections
	var err error
	if p.listener != nil {
		err = p.listener.Close()
	}
	
	// Wait for all active connections to complete
	p.connectionWg.Wait()
	
	return err
}

// acceptLoop handles incoming connections with proper lifecycle management
func (p *baseProxy) acceptLoop(handler func(net.Conn)) {
	for {
		select {
		case <-p.ctx.Done():
			logger.Info("Accept loop shutting down",
				"type", p.config.Type,
				"listen", p.config.ListenAddr)
			return
		default:
			conn, err := p.listener.Accept()
			if err != nil {
				// Check if this is a normal shutdown
				if errors.Is(err, net.ErrClosed) {
					logger.Debug("Listener closed",
						"type", p.config.Type,
						"listen", p.config.ListenAddr)
				} else {
					logger.Error("Accept error",
						"type", p.config.Type,
						"listen", p.config.ListenAddr,
						"error", err)
				}
				return
			}
			
			// Track connection
			p.activeConnections.Add(1)
			p.connectionWg.Add(1)
			
			// Handle connection in a safe goroutine
			safegoroutine.GoWithContext(p.ctx, 
				fmt.Sprintf("%s-handler-%s", p.config.Type, conn.RemoteAddr()),
				func() {
					defer func() {
						p.activeConnections.Add(-1)
						p.connectionWg.Done()
					}()
					handler(conn)
				})
		}
	}
}

// Specific proxy implementations

type mysqlProxy struct {
	baseProxy
	proxy *dbproxy.MySQLProxy
}

func (p *mysqlProxy) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.stopped = make(chan struct{})
	
	// Start accept loop in a safe goroutine
	safegoroutine.GoWithContext(p.ctx,
		fmt.Sprintf("mysql-accept-%s", p.config.ListenAddr),
		func() {
			defer close(p.stopped)
			p.acceptLoop(p.proxy.Handle)
		})
	
	return nil
}

type postgresProxy struct {
	baseProxy
	proxy *dbproxy.PostgresProxy
}

func (p *postgresProxy) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.stopped = make(chan struct{})
	
	// Start accept loop in a safe goroutine
	safegoroutine.GoWithContext(p.ctx,
		fmt.Sprintf("postgres-accept-%s", p.config.ListenAddr),
		func() {
			defer close(p.stopped)
			p.acceptLoop(p.proxy.Handle)
		})
	
	return nil
}

type mongoProxy struct {
	baseProxy
	proxy *dbproxy.MongoDBProxy
}

func (p *mongoProxy) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.stopped = make(chan struct{})
	
	// Start accept loop in a safe goroutine
	safegoroutine.GoWithContext(p.ctx,
		fmt.Sprintf("mongodb-accept-%s", p.config.ListenAddr),
		func() {
			defer close(p.stopped)
			p.acceptLoop(p.proxy.Handle)
		})
	
	return nil
}

type redisProxy struct {
	baseProxy
	proxy *dbproxy.RedisProxy
}

func (p *redisProxy) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.stopped = make(chan struct{})
	
	// Start accept loop in a safe goroutine
	safegoroutine.GoWithContext(p.ctx,
		fmt.Sprintf("redis-accept-%s", p.config.ListenAddr),
		func() {
			defer close(p.stopped)
			p.acceptLoop(p.proxy.Handle)
		})
	
	return nil
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