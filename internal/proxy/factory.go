package proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/artyom/leproxy/dbproxy"
	"github.com/artyom/leproxy/internal/logger"
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
	Start() error
	Stop() error
	GetType() Type
	GetListenAddr() string
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
	config   *Config
	listener net.Listener
	stopped  chan struct{}
}

func (p *baseProxy) GetType() Type {
	return p.config.Type
}

func (p *baseProxy) GetListenAddr() string {
	return p.config.ListenAddr
}

func (p *baseProxy) Stop() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// Specific proxy implementations

type mysqlProxy struct {
	baseProxy
	proxy *dbproxy.MySQLProxy
}

func (p *mysqlProxy) Start() error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.proxy.Handle(conn)
		}
	}()
	
	return nil
}

type postgresProxy struct {
	baseProxy
	proxy *dbproxy.PostgresProxy
}

func (p *postgresProxy) Start() error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.proxy.Handle(conn)
		}
	}()
	
	return nil
}

type mongoProxy struct {
	baseProxy
	proxy *dbproxy.MongoDBProxy
}

func (p *mongoProxy) Start() error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.proxy.Handle(conn)
		}
	}()
	
	return nil
}

type redisProxy struct {
	baseProxy
	proxy *dbproxy.RedisProxy
}

func (p *redisProxy) Start() error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.proxy.Handle(conn)
		}
	}()
	
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