# Tracing Configuration Enhancements

## Overview
Enhanced the tracing configuration in LeProxy with validation, timeouts, and fallback mechanisms to improve reliability and prevent startup delays or hangs with unreachable endpoints.

## Key Features Implemented

### 1. Configuration Validation (`internal/tracing/config.go`)
- **Endpoint Validation**: URL parsing and DNS resolution checks before initialization
- **Configuration Defaults**: Automatic setting of sensible defaults for all timeout and retry settings
- **Schema Validation**: Comprehensive validation of all tracing configuration parameters

### 2. Configurable Timeouts
- **Connection Timeout**: Default 5s for establishing connections to exporters
- **Export Timeout**: Default 10s for exporting spans
- **Health Check Timeout**: Default 3s for endpoint health checks

### 3. Fallback Mechanism
- **Primary to Stdout**: Automatic fallback to stdout exporter when primary fails
- **Health Checks**: Pre-initialization health checks to detect unreachable endpoints
- **Graceful Degradation**: Service continues operating even with tracing issues

### 4. Retry Logic with Exponential Backoff
- **Smart Retries**: Configurable retry attempts (default 3) with exponential backoff
- **Jitter**: Added jitter to prevent thundering herd problems
- **Context-Aware**: Respects context cancellation during retries

### 5. Circuit Breaker Pattern
- **Failure Detection**: Opens circuit after configurable threshold (default 5 failures)
- **Auto-Recovery**: Transitions to half-open state after timeout (default 30s)
- **State Management**: Closed → Open → Half-Open → Closed lifecycle

### 6. Metrics Collection
- **Export Metrics**: Success/failure counts and latencies per exporter type
- **Fallback Tracking**: Count of fallback activations
- **Performance Monitoring**: Average export latencies tracking

## Configuration Structure

### Extended Configuration (`internal/config/config.go`)
```yaml
advanced:
  tracing:
    enabled: true
    service_name: leproxy
    environment: production
    exporter_type: jaeger  # jaeger, otlp, or stdout
    sample_rate: 0.1
    
    # Endpoint configuration
    jaeger_endpoint: "http://jaeger:14268/api/traces"
    otlp_endpoint: "otel-collector:4317"
    
    # Timeouts
    connection_timeout: 5s
    export_timeout: 10s
    
    # Retry configuration
    max_retries: 3
    retry_delay: 1s
    enable_exponential_backoff: true
    
    # Health checks
    health_check_interval: 30s
    health_check_timeout: 3s
    
    # Fallback
    enable_fallback: true
    fallback_to_stdout: true
    
    # Circuit breaker
    enable_circuit_breaker: true
    circuit_breaker_threshold: 5
    circuit_breaker_timeout: 30s
```

## File Structure

### Core Implementation Files
- `internal/tracing/tracing.go` - Main tracing provider with timeout support
- `internal/tracing/config.go` - Configuration validation and health checking
- `internal/config/config.go` - Integration with main configuration

### Test Files
- `internal/tracing/tracing_test.go` - Core functionality tests
- `internal/tracing/config_test.go` - Validation and circuit breaker tests

### Example Configuration
- `examples/tracing-config.yaml` - Complete configuration examples

## Key Components

### ConfigValidator
- Validates configuration before use
- Performs DNS resolution checks
- Manages health check cache
- Provides circuit breakers per endpoint

### ExtendedConfig
- Extends base tracing config with timeout and retry settings
- Supports all major exporters (Jaeger, OTLP, Stdout)
- Configurable fallback behavior

### MetricsCollector
- Tracks export successes and failures
- Records latency measurements
- Monitors fallback activations

### Circuit Breaker
- Prevents cascading failures
- Automatic recovery attempts
- Thread-safe state management

## Testing

Comprehensive test coverage including:
- Configuration validation tests
- Endpoint health check tests
- Circuit breaker state transition tests
- Retry logic with backoff tests
- Metrics collection tests
- Fallback activation tests

All tests pass successfully with proper handling of:
- Invalid configurations
- Unreachable endpoints
- Context cancellation
- Timeout scenarios

## Benefits

1. **Improved Reliability**: Service starts even with unreachable tracing endpoints
2. **Faster Startup**: No hanging on unavailable endpoints
3. **Better Observability**: Metrics for tracing system health
4. **Graceful Degradation**: Automatic fallback to stdout when needed
5. **Production Ready**: Circuit breakers prevent cascade failures
6. **Developer Friendly**: Clear error messages and sensible defaults

## Migration Notes

Existing configurations will continue to work with default values applied for new settings. To leverage the new features:

1. Update configuration to include timeout and fallback settings
2. Enable circuit breaker for production environments
3. Configure appropriate retry delays based on network conditions
4. Set sample rates based on traffic volume

## Security Considerations

- No sensitive data logged in fallback mode
- DNS resolution performed with timeout to prevent DoS
- Circuit breakers prevent resource exhaustion
- Health check results cached to limit network calls