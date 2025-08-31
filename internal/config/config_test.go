package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_YAML(t *testing.T) {
	// Create a temporary YAML config file
	yamlContent := `
server:
  http_addr: ":8080"
  https_addr: ":8443"
  read_timeout: "30s"
  write_timeout: "1m"
  acme:
    provider: "letsencrypt"
    email: "test@example.com"
    cache_dir: "/tmp/certs"
    test_mode: true
    renew_before_days: 30

mappings:
  example.com:
    url: "http://localhost:3000"
    health_check: "/health"
    max_connections: 50
    connect_timeout: "5s"
  api.example.com:
    url: "http://localhost:4000"
    max_connections: 100

database_proxies:
  - name: "postgres-main"
    type: "postgres"
    listen: "localhost:5433"
    backend: "localhost:5432"
    tls: true
    pool:
      enabled: true
      min_conns: 5
      max_conns: 20

security:
  rate_limit:
    enabled: true
    requests_per_second: 20
    burst: 50
  ddos_protection:
    enabled: true
    max_connections_per_ip: 10

logging:
  level: "debug"
  format: "json"
  output: "stdout"

metrics:
  enabled: true
  port: 9090
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Test loading the config
	cfg, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}

	// Verify server configuration
	if cfg.Server.HTTPAddr != ":8080" {
		t.Errorf("Expected HTTPAddr :8080, got %s", cfg.Server.HTTPAddr)
	}
	if cfg.Server.HTTPSAddr != ":8443" {
		t.Errorf("Expected HTTPSAddr :8443, got %s", cfg.Server.HTTPSAddr)
	}
	if time.Duration(cfg.Server.ReadTimeout) != 30*time.Second {
		t.Errorf("Expected ReadTimeout 30s, got %v", cfg.Server.ReadTimeout)
	}
	if time.Duration(cfg.Server.WriteTimeout) != 1*time.Minute {
		t.Errorf("Expected WriteTimeout 1m, got %v", cfg.Server.WriteTimeout)
	}

	// Verify ACME configuration
	if cfg.Server.ACME.Provider != "letsencrypt" {
		t.Errorf("Expected ACME provider letsencrypt, got %s", cfg.Server.ACME.Provider)
	}
	if cfg.Server.ACME.Email != "test@example.com" {
		t.Errorf("Expected ACME email test@example.com, got %s", cfg.Server.ACME.Email)
	}
	if !cfg.Server.ACME.TestMode {
		t.Error("Expected ACME test mode to be true")
	}

	// Verify mappings
	if len(cfg.Mappings) != 2 {
		t.Errorf("Expected 2 mappings, got %d", len(cfg.Mappings))
	}
	if backend, ok := cfg.Mappings["example.com"]; ok {
		if backend.URL != "http://localhost:3000" {
			t.Errorf("Expected backend URL http://localhost:3000, got %s", backend.URL)
		}
		if backend.MaxConnections != 50 {
			t.Errorf("Expected max connections 50, got %d", backend.MaxConnections)
		}
	} else {
		t.Error("Missing mapping for example.com")
	}

	// Verify database proxies
	if len(cfg.DatabaseProxies) != 1 {
		t.Errorf("Expected 1 database proxy, got %d", len(cfg.DatabaseProxies))
	}
	if len(cfg.DatabaseProxies) > 0 {
		dbProxy := cfg.DatabaseProxies[0]
		if dbProxy.Name != "postgres-main" {
			t.Errorf("Expected database proxy name postgres-main, got %s", dbProxy.Name)
		}
		if dbProxy.Type != "postgres" {
			t.Errorf("Expected database type postgres, got %s", dbProxy.Type)
		}
		if !dbProxy.TLS {
			t.Error("Expected database TLS to be true")
		}
		if dbProxy.Pool.MinConns != 5 {
			t.Errorf("Expected pool min_conns 5, got %d", dbProxy.Pool.MinConns)
		}
	}

	// Verify security configuration
	if !cfg.Security.RateLimit.Enabled {
		t.Error("Expected rate limit to be enabled")
	}
	if cfg.Security.RateLimit.RequestsPerSecond != 20 {
		t.Errorf("Expected rate limit 20 rps, got %d", cfg.Security.RateLimit.RequestsPerSecond)
	}
	if !cfg.Security.DDoSProtection.Enabled {
		t.Error("Expected DDoS protection to be enabled")
	}

	// Verify logging configuration
	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected log level debug, got %s", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Expected log format json, got %s", cfg.Logging.Format)
	}

	// Verify metrics configuration
	if !cfg.Metrics.Enabled {
		t.Error("Expected metrics to be enabled")
	}
	if cfg.Metrics.Port != 9090 {
		t.Errorf("Expected metrics port 9090, got %d", cfg.Metrics.Port)
	}
}

func TestLoadConfig_JSON(t *testing.T) {
	// Create a temporary JSON config file
	jsonContent := `{
  "server": {
    "http_addr": ":8080",
    "https_addr": ":8443",
    "read_timeout": "30s",
    "write_timeout": "1m",
    "acme": {
      "provider": "zerossl",
      "email": "test@example.com",
      "cache_dir": "/tmp/certs",
      "eab_kid": "test-kid",
      "eab_hmac": "test-hmac"
    }
  },
  "mappings": {
    "example.com": {
      "url": "http://localhost:3000",
      "max_connections": 50
    }
  },
  "logging": {
    "level": "info",
    "format": "text"
  }
}`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Test loading the config
	cfg, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load JSON config: %v", err)
	}

	// Verify configuration
	if cfg.Server.HTTPAddr != ":8080" {
		t.Errorf("Expected HTTPAddr :8080, got %s", cfg.Server.HTTPAddr)
	}
	if cfg.Server.ACME.Provider != "zerossl" {
		t.Errorf("Expected ACME provider zerossl, got %s", cfg.Server.ACME.Provider)
	}
	if cfg.Server.ACME.EABKID != "test-kid" {
		t.Errorf("Expected EAB KID test-kid, got %s", cfg.Server.ACME.EABKID)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Expected log level info, got %s", cfg.Logging.Level)
	}
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	// Test with non-existent file
	_, err := LoadConfig("/non/existent/file.yaml")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Test with invalid YAML
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	invalidContent := `
server:
  http_addr: [this is not valid
`
	if err := os.WriteFile(invalidFile, []byte(invalidContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err = LoadConfig(invalidFile)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestLoadConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		errMsg  string
	}{
		{
			name: "missing_acme_email",
			content: `
server:
  acme:
    provider: "letsencrypt"
`,
			errMsg: "ACME email is required",
		},
		{
			name: "missing_eab_credentials",
			content: `
server:
  acme:
    provider: "zerossl"
    email: "test@example.com"
`,
			errMsg: "EAB credentials",
		},
		{
			name: "invalid_host",
			content: `
server:
  acme:
    email: "test@example.com"
mappings:
  "invalid..host":
    url: "http://localhost:3000"
`,
			errMsg: "invalid host",
		},
		{
			name: "invalid_backend_url",
			content: `
server:
  acme:
    email: "test@example.com"
mappings:
  example.com:
    url: "not-a-valid-url"
`,
			errMsg: "invalid backend URL",
		},
		{
			name: "invalid_database_type",
			content: `
server:
  acme:
    email: "test@example.com"
database_proxies:
  - name: "test"
    type: "invalid-db"
    listen: "localhost:5433"
    backend: "localhost:5432"
`,
			errMsg: "invalid database type",
		},
		{
			name: "invalid_pool_config",
			content: `
server:
  acme:
    email: "test@example.com"
database_proxies:
  - name: "test"
    type: "postgres"
    listen: "localhost:5433"
    backend: "localhost:5432"
    pool:
      min_conns: 10
      max_conns: 5
`,
			errMsg: "min_conns cannot be greater than max_conns",
		},
		{
			name: "invalid_whitelist_ip",
			content: `
server:
  acme:
    email: "test@example.com"
security:
  whitelist_ips:
    - "not-an-ip"
`,
			errMsg: "invalid whitelist IP",
		},
		{
			name: "missing_log_file_path",
			content: `
server:
  acme:
    email: "test@example.com"
logging:
  output: "file"
`,
			errMsg: "file_path is required when output is 'file'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to write test config file: %v", err)
			}

			_, err := LoadConfig(configFile)
			if err == nil {
				t.Error("Expected validation error")
			} else if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
			}
		})
	}
}

func TestLoadFile_WithCLIArgs(t *testing.T) {
	// Create a config file
	yamlContent := `
server:
  http_addr: ":8080"
  https_addr: ":8443"
  acme:
    provider: "letsencrypt"
    email: "file@example.com"
logging:
  level: "info"
  format: "text"
security:
  rate_limit:
    requests_per_second: 10
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Create CLI args that should override file config
	cliArgs := &CLIArgs{
		HTTPAddr:    ":9090",  // Override
		LogLevel:    "debug",  // Override
		RateLimit:   20,       // Override
		ACMEEmail:   "",       // Don't override (empty)
	}

	// Load config with CLI args
	cfg, err := LoadFile(configFile, cliArgs)
	if err != nil {
		t.Fatalf("Failed to load config with CLI args: %v", err)
	}

	// Verify CLI args took precedence
	if cfg.Server.HTTPAddr != ":9090" {
		t.Errorf("Expected HTTPAddr :9090 (from CLI), got %s", cfg.Server.HTTPAddr)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected log level debug (from CLI), got %s", cfg.Logging.Level)
	}
	if cfg.Security.RateLimit.RequestsPerSecond != 20 {
		t.Errorf("Expected rate limit 20 (from CLI), got %d", cfg.Security.RateLimit.RequestsPerSecond)
	}

	// Verify file config was used where CLI didn't override
	if cfg.Server.ACME.Email != "file@example.com" {
		t.Errorf("Expected email file@example.com (from file), got %s", cfg.Server.ACME.Email)
	}
	if cfg.Server.HTTPSAddr != ":8443" {
		t.Errorf("Expected HTTPSAddr :8443 (from file), got %s", cfg.Server.HTTPSAddr)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("Expected log format text (from file), got %s", cfg.Logging.Format)
	}
}

func TestDuration_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"seconds", 30 * time.Second, "30s"},
		{"minutes", 5 * time.Minute, "5m0s"},
		{"hours", 2 * time.Hour, "2h0m0s"},
		{"complex", 1*time.Hour + 30*time.Minute + 45*time.Second, "1h30m45s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Duration(tt.duration)

			// Test JSON marshaling
			jsonBytes, err := d.MarshalJSON()
			if err != nil {
				t.Fatalf("Failed to marshal to JSON: %v", err)
			}

			// Test JSON unmarshaling
			var d2 Duration
			if err := d2.UnmarshalJSON(jsonBytes); err != nil {
				t.Fatalf("Failed to unmarshal from JSON: %v", err)
			}

			if time.Duration(d2) != tt.duration {
				t.Errorf("JSON roundtrip failed: expected %v, got %v", tt.duration, time.Duration(d2))
			}

			// Test YAML marshaling
			yamlValue, err := d.MarshalYAML()
			if err != nil {
				t.Fatalf("Failed to marshal to YAML: %v", err)
			}

			if yamlValue != tt.expected {
				t.Errorf("YAML marshal: expected %s, got %v", tt.expected, yamlValue)
			}
		})
	}
}

func TestSetDefaults(t *testing.T) {
	cfg := &Config{}

	if err := setDefaults(cfg); err != nil {
		t.Fatalf("Failed to set defaults: %v", err)
	}

	// Verify defaults were set
	if cfg.Server.HTTPAddr != ":80" {
		t.Errorf("Expected default HTTPAddr :80, got %s", cfg.Server.HTTPAddr)
	}
	if cfg.Server.HTTPSAddr != ":443" {
		t.Errorf("Expected default HTTPSAddr :443, got %s", cfg.Server.HTTPSAddr)
	}
	if cfg.Server.ACME.Provider != "letsencrypt" {
		t.Errorf("Expected default ACME provider letsencrypt, got %s", cfg.Server.ACME.Provider)
	}
	if cfg.Security.RateLimit.RequestsPerSecond != 10 {
		t.Errorf("Expected default rate limit 10, got %d", cfg.Security.RateLimit.RequestsPerSecond)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("Expected default log level info, got %s", cfg.Logging.Level)
	}
}

func TestIsValidHost(t *testing.T) {
	tests := []struct {
		host  string
		valid bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"example-test.com", true},
		{"localhost", true},
		{"*", true},
		{"invalid..com", false},
		{"-invalid.com", false},
		{"invalid-.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if isValidHost(tt.host) != tt.valid {
				t.Errorf("isValidHost(%s) = %v, want %v", tt.host, !tt.valid, tt.valid)
			}
		})
	}
}

func TestIsValidDBType(t *testing.T) {
	tests := []struct {
		dbType string
		valid  bool
	}{
		{"postgres", true},
		{"mysql", true},
		{"mongodb", true},
		{"redis", true},
		{"cassandra", true},
		{"mssql", true},
		{"memcached", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.dbType, func(t *testing.T) {
			if isValidDBType(tt.dbType) != tt.valid {
				t.Errorf("isValidDBType(%s) = %v, want %v", tt.dbType, !tt.valid, tt.valid)
			}
		})
	}
}

func TestValidate_Tracing(t *testing.T) {
	tests := []struct {
		name      string
		tracing   TracingConfig
		shouldErr bool
		errMsg    string
	}{
		{
			name: "valid_jaeger",
			tracing: TracingConfig{
				Enabled:        true,
				ServiceName:    "test-service",
				ExporterType:   "jaeger",
				JaegerEndpoint: "http://localhost:14268",
				SampleRate:     0.5,
			},
			shouldErr: false,
		},
		{
			name: "valid_otlp",
			tracing: TracingConfig{
				Enabled:      true,
				ServiceName:  "test-service",
				ExporterType: "otlp",
				OTLPEndpoint: "localhost:4317",
				SampleRate:   1.0,
			},
			shouldErr: false,
		},
		{
			name: "invalid_sample_rate",
			tracing: TracingConfig{
				Enabled:      true,
				ServiceName:  "test-service",
				ExporterType: "stdout",
				SampleRate:   1.5,
			},
			shouldErr: true,
			errMsg:    "sample_rate must be between 0 and 1",
		},
		{
			name: "missing_service_name",
			tracing: TracingConfig{
				Enabled:      true,
				ExporterType: "stdout",
				SampleRate:   0.5,
			},
			shouldErr: true,
			errMsg:    "service_name is required",
		},
		{
			name: "invalid_circuit_breaker",
			tracing: TracingConfig{
				Enabled:                 true,
				ServiceName:             "test-service",
				EnableCircuitBreaker:    true,
				CircuitBreakerThreshold: 0,
			},
			shouldErr: true,
			errMsg:    "circuit_breaker_threshold must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Advanced: AdvancedConfig{
					Tracing: tt.tracing,
				},
			}
			
			// Set minimal required config to pass other validations
			cfg.Server.ACME.Email = "test@example.com"
			
			err := cfg.Validate()
			if tt.shouldErr {
				if err == nil {
					t.Error("Expected validation error")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected validation error: %v", err)
				}
			}
		})
	}
}

func TestGenerateSchema(t *testing.T) {
	schema := GenerateSchema()
	
	// Verify schema structure
	if schema["$schema"] != "http://json-schema.org/draft-07/schema#" {
		t.Error("Missing or incorrect $schema field")
	}
	
	if schema["title"] != "LeProxy Configuration Schema" {
		t.Error("Missing or incorrect title")
	}
	
	if schema["type"] != "object" {
		t.Error("Schema type should be object")
	}
	
	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("Properties field is missing or not a map")
	}
	
	// Check for expected top-level properties
	expectedProps := []string{"server", "mappings"}
	for _, prop := range expectedProps {
		if _, exists := properties[prop]; !exists {
			t.Errorf("Missing expected property: %s", prop)
		}
	}
}