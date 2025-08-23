# WebSocket Proxy Implementation

## Overview

This WebSocket proxy implementation provides secure, efficient proxying of WebSocket connections with comprehensive goroutine leak prevention and resource management.

## Key Features

### 1. Goroutine Leak Prevention
- **Context-based cancellation**: All copy goroutines use context for proper cancellation
- **Proper cleanup**: Goroutines are properly terminated when connections close
- **Monitoring goroutines**: Dedicated monitor goroutine handles timeouts and cleanup

### 2. Timeout Management
- **Idle timeout**: Connections automatically close after period of inactivity (default: 60s)
- **Read/Write deadlines**: Prevents hanging on slow or stalled connections
- **Configurable timeouts**: All timeouts can be configured per deployment needs

### 3. Connection Limits
- **Per-IP connection limits**: Prevents single IP from consuming too many resources
- **Maximum message size**: Prevents memory exhaustion from large messages (default: 10MB)
- **Connection tracking**: Real-time tracking of active connections per client IP

### 4. Keepalive Mechanism
- **WebSocket ping/pong**: Automatic ping frames sent at configurable intervals
- **Pong timeout**: Connections closed if pong not received within timeout
- **Connection health monitoring**: Detects and closes dead connections

### 5. Rate Limiting Integration
- **Request rate limiting**: Integrates with ratelimit package for DDoS protection
- **Connection rate limiting**: Separate limits for connection attempts
- **IP-based tracking**: Rate limits applied per client IP address

### 6. Metrics & Monitoring
- **Prometheus metrics**: Comprehensive metrics for monitoring
- **Active connections gauge**: Real-time active connection count
- **Bytes transferred counter**: Track data volume by direction
- **Error tracking**: Categorized error metrics for debugging

## Configuration

```go
config := websocket.Config{
    Target:         "ws://backend:8080",
    IdleTimeout:    60 * time.Second,     // Connection idle timeout
    MaxMessageSize: 10 * 1024 * 1024,     // 10MB max message
    PingInterval:   30 * time.Second,     // Ping interval
    PongTimeout:    10 * time.Second,     // Pong wait timeout
    MaxConnPerIP:   100,                  // Max connections per IP
    BufferSize:     32 * 1024,            // Copy buffer size
    RateLimiter:    limiter,              // Optional rate limiter
}

proxy, err := websocket.New(config)
```

## Metrics

The following Prometheus metrics are available:

- `websocket_active_connections`: Current number of active WebSocket connections
- `websocket_connections_total`: Total number of WebSocket connections handled
- `websocket_bytes_transferred_total{direction}`: Bytes transferred by direction
- `websocket_errors_total{type}`: Errors by type (copy_error, ping_error, etc.)
- `websocket_timeouts_total{type}`: Timeouts by type (idle, pong, etc.)
- `websocket_rate_limited_total`: Connections rejected due to rate limiting
- `websocket_connection_limited_total`: Connections rejected due to per-IP limits

## Testing

The implementation includes comprehensive tests for:

1. **Goroutine cleanup**: Verifies no goroutines leak after connections close
2. **Idle timeout**: Tests automatic connection closure on inactivity
3. **Message size limits**: Verifies large messages are rejected
4. **Connection limits**: Tests per-IP connection limiting
5. **Rate limiting**: Verifies rate limiting integration
6. **Concurrent connections**: Load tests with many simultaneous connections
7. **Memory leaks**: Extended tests checking for memory leaks under load
8. **Context cancellation**: Tests proper cleanup on context cancellation

Run tests:
```bash
# All tests
go test ./internal/websocket/...

# With race detection
go test -race ./internal/websocket/...

# Memory leak test
go test -run TestMemoryLeak -timeout 2m ./internal/websocket/...

# Benchmark
go test -bench=. -benchmem ./internal/websocket/...
```

## Implementation Details

### Goroutine Management

The proxy creates the following goroutines per connection:
1. Client-to-backend copy goroutine
2. Backend-to-client copy goroutine
3. Monitor goroutine for timeouts and keepalive

All goroutines are properly terminated when:
- Connection closes (either side)
- Idle timeout expires
- Context is cancelled
- Ping/pong keepalive fails
- Message size limit exceeded

### Resource Cleanup

Resources are cleaned up in the following order:
1. Context cancellation signals all goroutines
2. Copy goroutines detect closed connections and exit
3. Monitor goroutine ensures connections are closed
4. Defer statements clean up remaining resources
5. Connection tracker updates per-IP counts
6. Metrics are updated

### Security Considerations

1. **DDoS Protection**: Rate limiting and connection limits prevent resource exhaustion
2. **Memory Protection**: Message size limits prevent memory exhaustion attacks
3. **IP Tracking**: Uses X-Forwarded-For and X-Real-IP headers when available
4. **Timeout Protection**: All operations have timeouts to prevent hanging
5. **Error Handling**: Errors logged but not exposed to clients

## Performance

Benchmark results (Intel Xeon @ 2.00GHz):
- **Throughput**: ~2,500 connections/second
- **Latency**: ~420μs per connection
- **Memory**: ~180KB per connection
- **Allocations**: ~195 allocations per connection

## Known Limitations

1. WebSocket protocol validation is minimal (relies on backend validation)
2. Binary WebSocket frames not specifically optimized
3. No WebSocket compression support (permessage-deflate)
4. No WebSocket subprotocol negotiation

## Future Improvements

1. Add WebSocket frame validation
2. Implement permessage-deflate compression
3. Add subprotocol negotiation support
4. Optimize binary frame handling
5. Add circuit breaker pattern for backend failures