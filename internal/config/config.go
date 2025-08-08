package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main application configuration
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server" json:"server"`
	
	// Proxy mappings
	Mappings map[string]BackendConfig `yaml:"mappings" json:"mappings"`
	
	// Database proxy configuration
	DatabaseProxies []DatabaseProxyConfig `yaml:"database_proxies" json:"database_proxies"`
	
	// Security configuration
	Security SecurityConfig `yaml:"security" json:"security"`
	
	// Logging configuration
	Logging LoggingConfig `yaml:"logging" json:"logging"`
	
	// Metrics configuration
	Metrics MetricsConfig `yaml:"metrics" json:"metrics"`
	
	// Advanced configuration
	Advanced AdvancedConfig `yaml:"advanced" json:"advanced"`
}

type ServerConfig struct {
	HTTPAddr  string `yaml:"http_addr" json:"http_addr" default:":80"`
	HTTPSAddr string `yaml:"https_addr" json:"https_addr" default:":443"`
	
	// ACME configuration
	ACME ACMEConfig `yaml:"acme" json:"acme"`
	
	// Timeouts
	ReadTimeout  Duration `yaml:"read_timeout" json:"read_timeout" default:"1m"`
	WriteTimeout Duration `yaml:"write_timeout" json:"write_timeout" default:"5m"`
	IdleTimeout  Duration `yaml:"idle_timeout" json:"idle_timeout" default:"2m"`
}

type ACMEConfig struct {
	Provider  string `yaml:"provider" json:"provider" default:"letsencrypt" enum:"letsencrypt,zerossl,letsencrypt-staging"`
	Email     string `yaml:"email" json:"email" required:"true"`
	CacheDir  string `yaml:"cache_dir" json:"cache_dir" default:"/var/cache/letsencrypt"`
	
	// ZeroSSL specific
	EABKID  string `yaml:"eab_kid" json:"eab_kid"`
	EABHMAC string `yaml:"eab_hmac" json:"eab_hmac"`
	
	// Custom ACME server
	DirectoryURL string `yaml:"directory_url" json:"directory_url"`
}

type BackendConfig struct {
	URL             string            `yaml:"url" json:"url" required:"true"`
	HealthCheck     string            `yaml:"health_check" json:"health_check"`
	Headers         map[string]string `yaml:"headers" json:"headers"`
	WebSocketPath   string            `yaml:"websocket_path" json:"websocket_path"`
	MaxConnections  int               `yaml:"max_connections" json:"max_connections" default:"100"`
	ConnectTimeout  Duration          `yaml:"connect_timeout" json:"connect_timeout" default:"10s"`
	RequestTimeout  Duration          `yaml:"request_timeout" json:"request_timeout" default:"30s"`
	RetryAttempts   int               `yaml:"retry_attempts" json:"retry_attempts" default:"3"`
	RetryDelay      Duration          `yaml:"retry_delay" json:"retry_delay" default:"1s"`
}

type DatabaseProxyConfig struct {
	Name     string `yaml:"name" json:"name" required:"true"`
	Type     string `yaml:"type" json:"type" required:"true" enum:"postgres,mysql,mongodb,redis,cassandra,mssql,memcached"`
	Listen   string `yaml:"listen" json:"listen" required:"true"`
	Backend  string `yaml:"backend" json:"backend" required:"true"`
	TLS      bool   `yaml:"tls" json:"tls"`
	CertFile string `yaml:"cert_file" json:"cert_file"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
	
	// Connection pooling
	Pool PoolConfig `yaml:"pool" json:"pool"`
}

type PoolConfig struct {
	Enabled     bool     `yaml:"enabled" json:"enabled" default:"true"`
	MinConns    int      `yaml:"min_conns" json:"min_conns" default:"2"`
	MaxConns    int      `yaml:"max_conns" json:"max_conns" default:"10"`
	MaxLifetime Duration `yaml:"max_lifetime" json:"max_lifetime" default:"30m"`
	IdleTimeout Duration `yaml:"idle_timeout" json:"idle_timeout" default:"5m"`
}

type SecurityConfig struct {
	HSTS HSTSConfig `yaml:"hsts" json:"hsts"`
	
	RateLimit RateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
	
	DDoSProtection DDoSConfig `yaml:"ddos_protection" json:"ddos_protection"`
	
	// IP filtering
	WhitelistIPs   []string `yaml:"whitelist_ips" json:"whitelist_ips"`
	WhitelistCIDRs []string `yaml:"whitelist_cidrs" json:"whitelist_cidrs"`
	BlacklistIPs   []string `yaml:"blacklist_ips" json:"blacklist_ips"`
	BlacklistCIDRs []string `yaml:"blacklist_cidrs" json:"blacklist_cidrs"`
}

type HSTSConfig struct {
	Enabled           bool `yaml:"enabled" json:"enabled" default:"false"`
	MaxAge            int  `yaml:"max_age" json:"max_age" default:"31536000"`
	IncludeSubdomains bool `yaml:"include_subdomains" json:"include_subdomains" default:"true"`
	Preload           bool `yaml:"preload" json:"preload" default:"false"`
}

type RateLimitConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled" default:"true"`
	RequestsPerSecond int      `yaml:"requests_per_second" json:"requests_per_second" default:"10"`
	Burst             int      `yaml:"burst" json:"burst" default:"100"`
	TTL               Duration `yaml:"ttl" json:"ttl" default:"3m"`
	BlacklistTTL      Duration `yaml:"blacklist_ttl" json:"blacklist_ttl" default:"1h"`
}

type DDoSConfig struct {
	Enabled               bool     `yaml:"enabled" json:"enabled" default:"true"`
	MaxConnectionsPerIP   int      `yaml:"max_connections_per_ip" json:"max_connections_per_ip" default:"100"`
	DetectionWindow       Duration `yaml:"detection_window" json:"detection_window" default:"10s"`
	DetectionThreshold    int      `yaml:"detection_threshold" json:"detection_threshold" default:"50"`
	AutoBlacklistEnabled  bool     `yaml:"auto_blacklist_enabled" json:"auto_blacklist_enabled" default:"true"`
	AutoBlacklistDuration Duration `yaml:"auto_blacklist_duration" json:"auto_blacklist_duration" default:"1h"`
}

type LoggingConfig struct {
	Level      string `yaml:"level" json:"level" default:"info" enum:"debug,info,warn,error"`
	Format     string `yaml:"format" json:"format" default:"text" enum:"text,json"`
	Output     string `yaml:"output" json:"output" default:"stdout" enum:"stdout,stderr,file"`
	FilePath   string `yaml:"file_path" json:"file_path"`
	MaxSize    int    `yaml:"max_size" json:"max_size" default:"100"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups" default:"3"`
	MaxAge     int    `yaml:"max_age" json:"max_age" default:"7"`
	Compress   bool   `yaml:"compress" json:"compress" default:"true"`
}

type MetricsConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled" default:"true"`
	Endpoint string `yaml:"endpoint" json:"endpoint" default:"/metrics"`
	Port     int    `yaml:"port" json:"port" default:"9090"`
}

type AdvancedConfig struct {
	GracefulShutdownTimeout Duration `yaml:"graceful_shutdown_timeout" json:"graceful_shutdown_timeout" default:"30s"`
	EnableProfiling         bool     `yaml:"enable_profiling" json:"enable_profiling" default:"false"`
	ProfilingPort           int      `yaml:"profiling_port" json:"profiling_port" default:"6060"`
	MaxHeaderBytes          int      `yaml:"max_header_bytes" json:"max_header_bytes" default:"1048576"`
	DisableHTTP2            bool     `yaml:"disable_http2" json:"disable_http2" default:"false"`
}

// Duration is a custom type for time.Duration that supports YAML/JSON marshaling
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	
	*d = Duration(dur)
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	
	*d = Duration(dur)
	return nil
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()
	
	return ParseConfig(file, path)
}

// ParseConfig parses configuration from a reader
func ParseConfig(r io.Reader, filename string) (*Config, error) {
	var config Config
	
	// Read all content
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	
	// Determine format by extension
	var unmarshalErr error
	if strings.HasSuffix(filename, ".json") {
		unmarshalErr = json.Unmarshal(content, &config)
	} else {
		unmarshalErr = yaml.Unmarshal(content, &config)
	}
	
	if unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse config: %w", unmarshalErr)
	}
	
	// Set defaults
	if err := setDefaults(&config); err != nil {
		return nil, fmt.Errorf("failed to set defaults: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	
	return &config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	var errors []string
	
	// Validate server configuration
	if c.Server.ACME.Email == "" && c.Server.ACME.Provider != "" {
		errors = append(errors, "ACME email is required when provider is set")
	}
	
	if c.Server.ACME.Provider == "zerossl" {
		if c.Server.ACME.EABKID == "" || c.Server.ACME.EABHMAC == "" {
			errors = append(errors, "EAB credentials are required for ZeroSSL")
		}
	}
	
	// Validate mappings
	for host, backend := range c.Mappings {
		if !isValidHost(host) {
			errors = append(errors, fmt.Sprintf("invalid host: %s", host))
		}
		
		if _, err := url.Parse(backend.URL); err != nil {
			errors = append(errors, fmt.Sprintf("invalid backend URL for %s: %v", host, err))
		}
		
		if backend.MaxConnections < 1 {
			errors = append(errors, fmt.Sprintf("max_connections must be at least 1 for %s", host))
		}
	}
	
	// Validate database proxies
	for _, db := range c.DatabaseProxies {
		if !isValidDBType(db.Type) {
			errors = append(errors, fmt.Sprintf("invalid database type: %s", db.Type))
		}
		
		if _, _, err := net.SplitHostPort(db.Listen); err != nil {
			errors = append(errors, fmt.Sprintf("invalid listen address for %s: %v", db.Name, err))
		}
		
		if _, _, err := net.SplitHostPort(db.Backend); err != nil {
			errors = append(errors, fmt.Sprintf("invalid backend address for %s: %v", db.Name, err))
		}
		
		if db.Pool.MinConns > db.Pool.MaxConns {
			errors = append(errors, fmt.Sprintf("min_conns cannot be greater than max_conns for %s", db.Name))
		}
	}
	
	// Validate security configuration
	for _, ip := range c.Security.WhitelistIPs {
		if net.ParseIP(ip) == nil {
			errors = append(errors, fmt.Sprintf("invalid whitelist IP: %s", ip))
		}
	}
	
	for _, cidr := range c.Security.WhitelistCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errors = append(errors, fmt.Sprintf("invalid whitelist CIDR: %s", cidr))
		}
	}
	
	// Validate logging configuration
	if c.Logging.Output == "file" && c.Logging.FilePath == "" {
		errors = append(errors, "file_path is required when output is 'file'")
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("validation errors:\n  - %s", strings.Join(errors, "\n  - "))
	}
	
	return nil
}

func setDefaults(c *Config) error {
	// Set server defaults
	if c.Server.HTTPAddr == "" {
		c.Server.HTTPAddr = ":80"
	}
	if c.Server.HTTPSAddr == "" {
		c.Server.HTTPSAddr = ":443"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = Duration(1 * time.Minute)
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = Duration(5 * time.Minute)
	}
	
	// Set ACME defaults
	if c.Server.ACME.Provider == "" {
		c.Server.ACME.Provider = "letsencrypt"
	}
	if c.Server.ACME.CacheDir == "" {
		c.Server.ACME.CacheDir = "/var/cache/letsencrypt"
	}
	
	// Set security defaults
	if c.Security.RateLimit.RequestsPerSecond == 0 {
		c.Security.RateLimit.RequestsPerSecond = 10
	}
	if c.Security.RateLimit.Burst == 0 {
		c.Security.RateLimit.Burst = 100
	}
	
	// Set logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	
	return nil
}

func isValidHost(host string) bool {
	// Simple validation for hostname
	hostRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	return hostRegex.MatchString(host) || host == "*" // Allow wildcard
}

func isValidDBType(dbType string) bool {
	validTypes := []string{"postgres", "mysql", "mongodb", "redis", "cassandra", "mssql", "memcached"}
	for _, valid := range validTypes {
		if dbType == valid {
			return true
		}
	}
	return false
}

// GenerateSchema generates a JSON schema for the configuration
func GenerateSchema() map[string]interface{} {
	return map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"title":   "LeProxy Configuration Schema",
		"type":    "object",
		"properties": map[string]interface{}{
			"server": map[string]interface{}{
				"type":        "object",
				"description": "Server configuration",
				"properties": map[string]interface{}{
					"http_addr":     map[string]interface{}{"type": "string", "default": ":80"},
					"https_addr":    map[string]interface{}{"type": "string", "default": ":443"},
					"read_timeout":  map[string]interface{}{"type": "string", "pattern": "^[0-9]+(ms|s|m|h)$"},
					"write_timeout": map[string]interface{}{"type": "string", "pattern": "^[0-9]+(ms|s|m|h)$"},
				},
			},
			"mappings": map[string]interface{}{
				"type":        "object",
				"description": "Host to backend mappings",
				"additionalProperties": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"url":            map[string]interface{}{"type": "string", "format": "uri"},
						"health_check":   map[string]interface{}{"type": "string"},
						"max_connections": map[string]interface{}{"type": "integer", "minimum": 1},
					},
					"required": []string{"url"},
				},
			},
		},
	}
}