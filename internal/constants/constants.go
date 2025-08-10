package constants

import "time"

// Timeout constants
const (
	DefaultReadTimeout     = 1 * time.Minute
	DefaultWriteTimeout    = 5 * time.Minute
	DefaultIdleTimeout     = 120 * time.Second
	DefaultShutdownTimeout = 30 * time.Second
	DefaultDialTimeout     = 10 * time.Second
	DefaultKeepAlive       = 30 * time.Second
)

// HTTP constants
const (
	DefaultHTTPPort  = ":http"
	DefaultHTTPSPort = ":https"
	DefaultAdminPort = ":8081"
	DefaultHealthPort = ":8080"
	DefaultMetricsPort = ":9090"
)

// Rate limiting constants
const (
	DefaultRateLimit      = 100  // requests per second
	DefaultBurstLimit     = 200  // burst size
	DefaultBlockDuration  = 1 * time.Hour
	DefaultCleanupPeriod  = 5 * time.Minute
	MaxConnectionsPerIP   = 100
)

// Buffer sizes
const (
	DefaultBufferSize     = 32 * 1024  // 32KB
	SmallBufferSize      = 4 * 1024   // 4KB
	LargeBufferSize      = 64 * 1024  // 64KB
	MaxRequestBodySize   = 10 * 1024 * 1024  // 10MB
	MaxWebSocketMessageSize = 512 * 1024  // 512KB
)

// Certificate constants
const (
	DefaultCertCacheDir    = "/var/cache/letsencrypt"
	DefaultDBCertCacheDir  = "/var/cache/dbcerts"
	CertRenewalCheckPeriod = 24 * time.Hour
	CertRenewalThreshold   = 30 * 24 * time.Hour  // 30 days
)

// Retry constants
const (
	MaxRetries          = 3
	RetryBackoffBase    = 1 * time.Second
	RetryBackoffMax     = 30 * time.Second
	ConnectionRetryDelay = 5 * time.Second
)

// Database proxy constants
const (
	// Protocol magic numbers
	MySQLProtocolVersion    = 10
	PostgresProtocolVersion = 196608  // 3.0
	MongoDBWireVersion      = 6
	RedisProtocolVersion    = 3
	
	// Default ports
	MySQLDefaultPort     = 3306
	PostgresDefaultPort  = 5432
	MongoDBDefaultPort   = 27017
	RedisDefaultPort     = 6379
	CassandraDefaultPort = 9042
	ElasticDefaultPort   = 9200
	MemcachedDefaultPort = 11211
	KafkaDefaultPort     = 9092
	RabbitMQDefaultPort  = 5672
	MSSQLDefaultPort     = 1433
	FTPDefaultPort       = 21
	SMTPDefaultPort      = 25
	LDAPDefaultPort      = 389
)

// Security constants  
const (
	MinPasswordLength     = 12
	MaxLoginAttempts      = 5
	LoginAttemptWindow    = 15 * time.Minute
	SessionTimeout        = 24 * time.Hour
	TokenExpiryTime       = 1 * time.Hour
	MaxSessionsPerUser    = 5
)

// Logging constants
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
	LogLevelFatal = "fatal"
	
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// Monitoring constants
const (
	MetricsCollectionInterval = 10 * time.Second
	HealthCheckInterval       = 30 * time.Second
	HealthCheckTimeout        = 5 * time.Second
	MetricsRetentionPeriod    = 7 * 24 * time.Hour  // 7 days
)

// File system constants
const (
	DefaultFileMode    = 0644
	DefaultDirMode     = 0755
	SecureFileMode     = 0600
	SecureDirMode      = 0700
	MaxFileSize        = 100 * 1024 * 1024  // 100MB
	TempFilePrefix     = "leproxy-"
)

// WebSocket constants
const (
	WebSocketHandshakeTimeout = 10 * time.Second
	WebSocketPingPeriod       = 30 * time.Second
	WebSocketPongTimeout      = 60 * time.Second
	WebSocketWriteTimeout     = 10 * time.Second
)

// Plugin constants
const (
	PluginLoadTimeout     = 10 * time.Second
	PluginExecuteTimeout  = 30 * time.Second
	MaxPluginNameLength   = 64
	MaxPluginDescLength   = 256
)

// Cache constants
const (
	DefaultCacheTTL       = 5 * time.Minute
	MaxCacheEntries       = 10000
	CacheCleanupInterval  = 10 * time.Minute
	CacheEvictionRatio    = 0.1  // Evict 10% when full
)

// Network constants
const (
	TCPKeepAliveInterval  = 30 * time.Second
	MaxHeaderSize         = 8192  // 8KB
	MaxTrailerSize        = 4096  // 4KB
	DNSCacheTTL          = 5 * time.Minute
)

// Error messages
const (
	ErrMsgInvalidConfig     = "invalid configuration"
	ErrMsgConnectionFailed  = "connection failed"
	ErrMsgAuthFailed       = "authentication failed"
	ErrMsgRateLimitExceeded = "rate limit exceeded"
	ErrMsgServerOverload   = "server overloaded"
	ErrMsgInvalidRequest   = "invalid request"
	ErrMsgTimeout          = "operation timed out"
	ErrMsgInternalError    = "internal server error"
)

// HTTP Headers
const (
	HeaderContentType     = "Content-Type"
	HeaderAuthorization   = "Authorization"
	HeaderXForwardedFor   = "X-Forwarded-For"
	HeaderXRealIP         = "X-Real-IP"
	HeaderXRequestID      = "X-Request-ID"
	HeaderXRateLimitLimit = "X-RateLimit-Limit"
	HeaderXRateLimitRemaining = "X-RateLimit-Remaining"
	HeaderXRateLimitReset = "X-RateLimit-Reset"
	HeaderStrictTransportSecurity = "Strict-Transport-Security"
)

// MIME Types
const (
	MIMEApplicationJSON = "application/json"
	MIMEApplicationXML  = "application/xml"
	MIMETextHTML       = "text/html"
	MIMETextPlain      = "text/plain"
	MIMEOctetStream    = "application/octet-stream"
)