# Goroutine Leak Fix in Proxy Factory

## Problem Statement
The proxy factory implementations in `internal/proxy/factory.go` had goroutines that ran Accept() loops without proper lifecycle management. When Accept() returned an error, the goroutines would simply return without cleanup or notification, leading to potential goroutine leaks.

## Solution Implemented

### 1. Added Context Support
- Modified the `Proxy` interface to accept a context in the `Start()` method
- Added `StartProxyWithContext()` method to `ProxyManager`
- Each proxy now maintains its own context and cancellation function

### 2. Implemented Proper Shutdown Coordination
- Added `baseProxy` fields for lifecycle management:
  - `ctx`: Context for cancellation
  - `cancel`: Cancel function for signaling shutdown
  - `activeConnections`: Atomic counter for tracking connections
  - `connectionWg`: WaitGroup for graceful shutdown
  - `stopped`: Channel to signal completion

### 3. Created Centralized Accept Loop
- Implemented `acceptLoop()` method in `baseProxy` that:
  - Respects context cancellation
  - Logs errors appropriately (distinguishing between normal shutdown and actual errors)
  - Tracks active connections
  - Uses safegoroutine for panic recovery

### 4. Enhanced Connection Tracking
- Each accepted connection increments `activeConnections` counter
- Connection handlers decrement counter on completion
- `GetActiveConnections()` method added to Proxy interface
- Graceful shutdown waits for all connections to complete

### 5. Improved Error Handling
- Accept errors are now properly logged with context
- Distinguishes between `net.ErrClosed` (normal shutdown) and actual errors
- Uses structured logging with type, address, and error details

## Code Changes

### Modified Files:
1. **internal/proxy/factory.go**:
   - Added context, errors, and sync/atomic imports
   - Updated Proxy interface with context support and connection tracking
   - Enhanced baseProxy with lifecycle management fields
   - Implemented centralized acceptLoop method
   - Updated all proxy implementations (mysql, postgres, mongodb, redis)
   - Used safegoroutine for panic recovery

### New Test File:
2. **internal/proxy/factory_goroutine_test.go**:
   - `TestProxyGoroutineCleanup`: Verifies goroutines are cleaned up properly
   - `TestProxyAcceptErrorHandling`: Tests error handling in accept loops
   - `TestProxyGracefulShutdown`: Verifies graceful shutdown with active connections
   - `TestConcurrentProxyOperations`: Tests concurrent start/stop operations
   - `TestProxyManagerStopAll`: Tests stopping all proxies at once
   - `TestContextCancellation`: Tests context cancellation handling

## Key Improvements

### Before:
```go
go func() {
    for {
        conn, err := ln.Accept()
        if err != nil {
            return  // Silent failure, goroutine leak!
        }
        go p.proxy.Handle(conn)
    }
}()
```

### After:
```go
safegoroutine.GoWithContext(p.ctx,
    fmt.Sprintf("mysql-accept-%s", p.config.ListenAddr),
    func() {
        defer close(p.stopped)
        p.acceptLoop(p.proxy.Handle)
    })
```

## Benefits

1. **No Goroutine Leaks**: Proper cleanup ensures goroutines are terminated
2. **Graceful Shutdown**: Active connections are allowed to complete
3. **Better Observability**: Error logging and connection tracking
4. **Panic Recovery**: Using safegoroutine prevents crashes
5. **Context Support**: Respects cancellation for clean shutdown
6. **Testability**: Comprehensive test suite to prevent regressions

## Testing

The implementation includes comprehensive tests that verify:
- Goroutines are properly cleaned up on shutdown
- No leaks occur during normal operation
- Accept errors are handled correctly
- Graceful shutdown works with active connections
- Concurrent operations don't cause leaks
- Context cancellation is respected

## Migration Guide

For code using the old API:
```go
// Old way
proxy.Start()

// New way
proxy.Start(context.Background())
// Or with context
ctx, cancel := context.WithCancel(context.Background())
proxy.Start(ctx)
```

## Monitoring

The enhanced implementation provides:
- Active connection count via `GetActiveConnections()`
- Structured logging for all accept errors
- Connection lifecycle tracking
- Graceful shutdown coordination

## Future Improvements

Potential enhancements could include:
1. Metrics collection for connection statistics
2. Health check endpoints
3. Connection pooling limits
4. Rate limiting support
5. Circuit breaker integration