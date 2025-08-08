# LeProxy API Documentation

## Table of Contents
- [Overview](#overview)
- [HTTP API Endpoints](#http-api-endpoints)
- [Configuration API](#configuration-api)
- [Metrics API](#metrics-api)
- [Health Check API](#health-check-api)
- [Admin API](#admin-api)
- [WebSocket API](#websocket-api)
- [Database Proxy Protocols](#database-proxy-protocols)
- [Error Responses](#error-responses)
- [Examples](#examples)

## Overview

LeProxy provides several APIs for configuration, monitoring, and management:

- **HTTP REST API** - For health checks, metrics, and admin operations
- **Configuration API** - YAML/JSON-based configuration management
- **WebSocket API** - Real-time bidirectional communication
- **Database Proxy API** - Protocol-specific database proxying

Base URL: `https://<your-domain>`

## HTTP API Endpoints

### Health Check Endpoints

#### GET /health
Returns comprehensive health status of the proxy server.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "checks": [
    {
      "name": "backend_connectivity",
      "status": "healthy",
      "latency_ms": 5,
      "timestamp": "2024-01-01T12:00:00Z"
    },
    {
      "name": "certificate_validity",
      "status": "healthy",
      "message": "Valid until 2024-12-31",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ],
  "metadata": {
    "active_connections": 42,
    "requests_per_second": 100
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

**Status Codes:**
- `200 OK` - Service is healthy or degraded
- `503 Service Unavailable` - Service is unhealthy

#### GET /ready
Checks if the service is ready to accept traffic.

**Response:**
```json
{
  "ready": true,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

**Status Codes:**
- `200 OK` - Service is ready
- `503 Service Unavailable` - Service is not ready

#### GET /live
Simple liveness check.

**Response:**
```json
{
  "alive": true,
  "timestamp": "2024-01-01T12:00:00Z",
  "uptime": 3600
}
```

**Status Codes:**
- `200 OK` - Service is alive

### Metrics Endpoints

#### GET /metrics
Returns Prometheus-formatted metrics.

**Response:**
```
# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200",path="/"} 1234

# HELP http_request_duration_seconds HTTP request latencies in seconds
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",status="200",path="/",le="0.005"} 100
http_request_duration_seconds_bucket{method="GET",status="200",path="/",le="0.01"} 200
http_request_duration_seconds_sum{method="GET",status="200",path="/"} 12.34
http_request_duration_seconds_count{method="GET",status="200",path="/"} 1234

# HELP proxy_active_connections Number of active proxy connections by type
# TYPE proxy_active_connections gauge
proxy_active_connections{type="postgres"} 10
proxy_active_connections{type="mysql"} 5

# HELP certificate_expiry_seconds Certificate expiry time in seconds since epoch
# TYPE certificate_expiry_seconds gauge
certificate_expiry_seconds{domain="example.com"} 1735689600
```

### Admin API Endpoints

#### GET /admin/stats
Returns server statistics.

**Headers:**
- `Authorization: Bearer <token>` (required)

**Response:**
```json
{
  "server": {
    "uptime_seconds": 3600,
    "version": "1.0.0",
    "go_version": "1.21",
    "goroutines": 50,
    "memory_mb": 128
  },
  "proxy": {
    "total_requests": 10000,
    "active_connections": 42,
    "total_bytes_transferred": 1073741824
  },
  "backends": {
    "example.com": {
      "status": "healthy",
      "requests": 5000,
      "errors": 2,
      "latency_ms": 10
    }
  },
  "rate_limiting": {
    "active_visitors": 100,
    "blacklisted_ips": 5,
    "requests_blocked": 50
  }
}
```

#### POST /admin/reload
Reload configuration without downtime.

**Headers:**
- `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "config_path": "/etc/leproxy/config.yml"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration reloaded",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### POST /admin/blacklist
Add IP to blacklist.

**Headers:**
- `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "ip": "192.168.1.100",
  "duration_seconds": 3600,
  "reason": "Suspicious activity detected"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "IP blacklisted",
  "expires_at": "2024-01-01T13:00:00Z"
}
```

#### DELETE /admin/blacklist/:ip
Remove IP from blacklist.

**Headers:**
- `Authorization: Bearer <token>` (required)

**Response:**
```json
{
  "status": "success",
  "message": "IP removed from blacklist"
}
```

## Configuration API

### Configuration Schema

The configuration file supports YAML and JSON formats:

```yaml
server:
  http_addr: ":80"
  https_addr: ":443"
  read_timeout: "1m"
  write_timeout: "5m"
  idle_timeout: "2m"

  acme:
    provider: "letsencrypt"  # letsencrypt, zerossl, letsencrypt-staging
    email: "admin@example.com"
    cache_dir: "/var/cache/letsencrypt"
    # For ZeroSSL:
    eab_kid: "your-eab-kid"
    eab_hmac: "your-eab-hmac"

mappings:
  example.com:
    url: "http://localhost:8080"
    health_check: "/health"
    headers:
      X-Custom-Header: "value"
    websocket_path: "/ws"
    max_connections: 100
    connect_timeout: "10s"
    request_timeout: "30s"
    retry_attempts: 3
    retry_delay: "1s"

database_proxies:
  - name: "postgres-main"
    type: "postgres"
    listen: "0.0.0.0:5432"
    backend: "db.internal:5432"
    tls: true
    cert_file: "/certs/postgres.crt"
    key_file: "/certs/postgres.key"
    pool:
      enabled: true
      min_conns: 2
      max_conns: 10
      max_lifetime: "30m"
      idle_timeout: "5m"

security:
  hsts:
    enabled: true
    max_age: 31536000
    include_subdomains: true
    preload: false

  rate_limit:
    enabled: true
    requests_per_second: 10
    burst: 100
    ttl: "3m"
    blacklist_ttl: "1h"

  ddos_protection:
    enabled: true
    max_connections_per_ip: 100
    detection_window: "10s"
    detection_threshold: 50
    auto_blacklist_enabled: true
    auto_blacklist_duration: "1h"

  whitelist_ips:
    - "10.0.0.0/8"
    - "192.168.0.0/16"

logging:
  level: "info"  # debug, info, warn, error
  format: "json"  # text, json
  output: "stdout"  # stdout, stderr, file
  file_path: "/var/log/leproxy.log"
  max_size: 100  # MB
  max_backups: 3
  max_age: 7  # days
  compress: true

metrics:
  enabled: true
  endpoint: "/metrics"
  port: 9090

advanced:
  graceful_shutdown_timeout: "30s"
  enable_profiling: false
  profiling_port: 6060
  max_header_bytes: 1048576
  disable_http2: false
```

### Validation Rules

- **Required Fields:**
  - `server.acme.email` (when ACME provider is set)
  - `mappings.<host>.url`
  - `database_proxies[].name`
  - `database_proxies[].type`
  - `database_proxies[].listen`
  - `database_proxies[].backend`

- **Enum Values:**
  - `server.acme.provider`: `letsencrypt`, `zerossl`, `letsencrypt-staging`
  - `database_proxies[].type`: `postgres`, `mysql`, `mongodb`, `redis`, `cassandra`, `mssql`, `memcached`
  - `logging.level`: `debug`, `info`, `warn`, `error`
  - `logging.format`: `text`, `json`
  - `logging.output`: `stdout`, `stderr`, `file`

## WebSocket API

### WebSocket Proxy Configuration

WebSocket connections are automatically detected and proxied based on the `Upgrade` header.

**Connection Flow:**
1. Client sends HTTP request with `Upgrade: websocket`
2. Proxy establishes connection to backend WebSocket server
3. Bidirectional streaming begins

**Headers Added by Proxy:**
- `X-Forwarded-For`: Client IP address
- `X-Forwarded-Proto`: Original protocol (http/https)

### WebSocket Path Mapping

```yaml
mappings:
  example.com:
    url: "http://backend:8080"
    websocket_path: "/ws"  # WebSocket endpoint
```

## Database Proxy Protocols

### PostgreSQL Proxy

**Port:** Configurable (default 5432)
**Protocol:** PostgreSQL wire protocol with SSL negotiation

**Features:**
- SSL/TLS negotiation support
- Connection pooling
- Query logging (when debug enabled)
- Automatic reconnection

### MySQL Proxy

**Port:** Configurable (default 3306)
**Protocol:** MySQL wire protocol

**Features:**
- SSL/TLS support
- Connection pooling
- Authentication pass-through
- Prepared statement support

### MongoDB Proxy

**Port:** Configurable (default 27017)
**Protocol:** MongoDB wire protocol

**Features:**
- TLS encryption
- Connection pooling
- Wire protocol version negotiation

### Redis Proxy

**Port:** Configurable (default 6379)
**Protocol:** RESP (Redis Serialization Protocol)

**Features:**
- STARTTLS support
- Pipelining
- Pub/Sub support
- Connection pooling

### Cassandra Proxy

**Port:** Configurable (default 9042)
**Protocol:** CQL native protocol

**Features:**
- TLS encryption
- Protocol version negotiation
- Prepared statement caching

## Error Responses

### Standard Error Format

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "details": {
      "limit": 10,
      "window": "1s",
      "retry_after": "2024-01-01T12:00:01Z"
    }
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|------------|-------------|
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded |
| `BLACKLISTED` | 403 | IP address is blacklisted |
| `BACKEND_UNAVAILABLE` | 502 | Backend server is unavailable |
| `BACKEND_TIMEOUT` | 504 | Backend server timeout |
| `INVALID_REQUEST` | 400 | Invalid request format |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Access forbidden |
| `NOT_FOUND` | 404 | Resource not found |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

## Examples

### cURL Examples

#### Health Check
```bash
curl https://proxy.example.com/health
```

#### Metrics
```bash
curl https://proxy.example.com/metrics
```

#### Admin Stats (with authentication)
```bash
curl -H "Authorization: Bearer your-token" https://proxy.example.com/admin/stats
```

#### Reload Configuration
```bash
curl -X POST -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"config_path": "/etc/leproxy/config.yml"}' \
  https://proxy.example.com/admin/reload
```

#### Blacklist IP
```bash
curl -X POST -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "duration_seconds": 3600}' \
  https://proxy.example.com/admin/blacklist
```

### WebSocket Connection Example

```javascript
// JavaScript WebSocket client
const ws = new WebSocket('wss://proxy.example.com/ws');

ws.onopen = function() {
    console.log('Connected to WebSocket');
    ws.send('Hello Server');
};

ws.onmessage = function(event) {
    console.log('Received:', event.data);
};

ws.onerror = function(error) {
    console.error('WebSocket error:', error);
};

ws.onclose = function() {
    console.log('WebSocket connection closed');
};
```

### Database Connection Examples

#### PostgreSQL through proxy
```bash
psql -h proxy.example.com -p 5432 -U username -d database
```

#### MySQL through proxy
```bash
mysql -h proxy.example.com -P 3306 -u username -p database
```

#### Redis through proxy
```bash
redis-cli -h proxy.example.com -p 6379
```

### Go Client Example

```go
package main

import (
    "fmt"
    "io"
    "net/http"
)

func main() {
    // Health check
    resp, err := http.Get("https://proxy.example.com/health")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Health Status: %s\n", body)
}
```

### Python Client Example

```python
import requests
import websocket

# Health check
response = requests.get('https://proxy.example.com/health')
print(f"Health Status: {response.json()}")

# WebSocket connection
def on_message(ws, message):
    print(f"Received: {message}")

def on_error(ws, error):
    print(f"Error: {error}")

def on_close(ws, close_status_code, close_msg):
    print("Connection closed")

def on_open(ws):
    ws.send("Hello Server")

ws = websocket.WebSocketApp("wss://proxy.example.com/ws",
                            on_open=on_open,
                            on_message=on_message,
                            on_error=on_error,
                            on_close=on_close)
ws.run_forever()
```

## Rate Limiting

### Rate Limit Headers

Responses include rate limit information:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 5
X-RateLimit-Reset: 1704110400
```

### Rate Limit Response

When rate limit is exceeded:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "details": {
      "limit": 10,
      "window": "1s",
      "retry_after": "2024-01-01T12:00:01Z"
    }
  }
}
```

## Authentication

### Bearer Token Authentication

Admin endpoints require Bearer token authentication:

```
Authorization: Bearer <your-secure-token>
```

### API Key Authentication (Future)

Planned support for API key authentication:

```
X-API-Key: <your-api-key>
```

## Monitoring Integration

### Prometheus Integration

Configure Prometheus to scrape metrics:

```yaml
scrape_configs:
  - job_name: 'leproxy'
    static_configs:
      - targets: ['proxy.example.com:9090']
    metrics_path: '/metrics'
```

### Grafana Dashboard

Import the LeProxy dashboard for visualization:
- Request rate and latency
- Active connections by type
- Certificate expiry warnings
- Error rates and types
- Rate limiting statistics

## Troubleshooting

### Common Issues

1. **Backend Unavailable (502)**
   - Check backend server is running
   - Verify network connectivity
   - Check firewall rules

2. **Rate Limit Exceeded (429)**
   - Reduce request frequency
   - Request rate limit increase
   - Check for IP whitelisting

3. **Certificate Issues**
   - Verify domain ownership
   - Check ACME provider status
   - Ensure port 80 is accessible for challenges

4. **WebSocket Connection Failed**
   - Verify WebSocket path configuration
   - Check for proxy timeout settings
   - Ensure backend supports WebSocket

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
logging:
  level: "debug"
  format: "json"
```

## Support

For issues and feature requests, visit: https://github.com/artyom/leproxy/issues

---
*API Version: 1.0.0*
*Last Updated: 2024-01-01*