package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	// "github.com/artyom/leproxy/internal/logger"
	// "github.com/artyom/leproxy/internal/metrics"
)

// ConnectionTracker manages active connections for a proxy
type ConnectionTracker struct {
	mu              sync.RWMutex
	connections     map[net.Conn]*ConnectionInfo
	maxConnections  int
	wg              sync.WaitGroup
	closed          atomic.Bool
	stats           *ConnectionStats
	healthCallback  func() bool
	drainTimeout    time.Duration
	acceptPauseChan chan struct{}
}

// ConnectionInfo stores information about a connection
type ConnectionInfo struct {
	Conn        net.Conn
	StartTime   time.Time
	BytesIn     atomic.Uint64
	BytesOut    atomic.Uint64
	LastActive  atomic.Pointer[time.Time]
	RemoteAddr  string
	ProxyType   Type
}

// ConnectionStats tracks connection statistics
type ConnectionStats struct {
	TotalConnections   atomic.Uint64
	ActiveConnections  atomic.Int32
	RejectedConnections atomic.Uint64
	TotalBytesIn       atomic.Uint64
	TotalBytesOut      atomic.Uint64
	MaxConcurrent      atomic.Int32
	LastConnectionTime atomic.Pointer[time.Time]
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker(maxConnections int, drainTimeout time.Duration) *ConnectionTracker {
	if maxConnections <= 0 {
		maxConnections = 10000 // Default max connections
	}
	if drainTimeout <= 0 {
		drainTimeout = 30 * time.Second // Default drain timeout
	}

	return &ConnectionTracker{
		connections:     make(map[net.Conn]*ConnectionInfo),
		maxConnections:  maxConnections,
		stats:           &ConnectionStats{},
		drainTimeout:    drainTimeout,
		acceptPauseChan: make(chan struct{}),
	}
}

// SetHealthCallback sets a callback to check if the tracker is healthy
func (ct *ConnectionTracker) SetHealthCallback(callback func() bool) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.healthCallback = callback
}

// Track attempts to track a new connection
func (ct *ConnectionTracker) Track(conn net.Conn, proxyType Type) (*ConnectionInfo, error) {
	if ct.closed.Load() {
		return nil, fmt.Errorf("connection tracker is closed")
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Check connection limit
	activeCount := len(ct.connections)
	if activeCount >= ct.maxConnections {
		ct.stats.RejectedConnections.Add(1)
		// metrics.RecordConnectionRejected(string(proxyType), "max_connections")
		return nil, fmt.Errorf("maximum connections reached: %d", ct.maxConnections)
	}

	// Create connection info
	now := time.Now()
	info := &ConnectionInfo{
		Conn:       conn,
		StartTime:  now,
		RemoteAddr: conn.RemoteAddr().String(),
		ProxyType:  proxyType,
	}
	info.LastActive.Store(&now)

	// Track the connection
	ct.connections[conn] = info
	ct.wg.Add(1)

	// Update statistics
	ct.stats.TotalConnections.Add(1)
	currentActive := ct.stats.ActiveConnections.Add(1)
	ct.stats.LastConnectionTime.Store(&now)

	// Update max concurrent if needed
	for {
		max := ct.stats.MaxConcurrent.Load()
		if currentActive <= max || ct.stats.MaxConcurrent.CompareAndSwap(max, currentActive) {
			break
		}
	}

	// Check if we should pause accepting new connections (backpressure)
	if float64(activeCount) >= float64(ct.maxConnections)*0.9 {
		select {
		case ct.acceptPauseChan <- struct{}{}:
			// logger.Warn("Connection limit approaching, applying backpressure",
			// 	"active", activeCount,
			// 	"max", ct.maxConnections)
		default:
		}
	}

	// logger.Debug("Connection tracked",
	// 	"remote_addr", info.RemoteAddr,
	// 	"proxy_type", proxyType,
	// 	"active_connections", currentActive)

	// metrics.RecordConnection(string(proxyType), "accepted")
	return info, nil
}

// Untrack removes a connection from tracking
func (ct *ConnectionTracker) Untrack(conn net.Conn) {
	ct.mu.Lock()
	info, exists := ct.connections[conn]
	if exists {
		delete(ct.connections, conn)
	}
	ct.mu.Unlock()

	if exists {
		ct.wg.Done()
		// activeCount := ct.stats.ActiveConnections.Add(-1)
		ct.stats.ActiveConnections.Add(-1)

		// Update byte statistics
		ct.stats.TotalBytesIn.Add(info.BytesIn.Load())
		ct.stats.TotalBytesOut.Add(info.BytesOut.Load())

		// duration := time.Since(info.StartTime)
		// logger.Debug("Connection untracked",
		// 	"remote_addr", info.RemoteAddr,
		// 	"proxy_type", info.ProxyType,
		// 	"duration", duration,
		// 	"bytes_in", info.BytesIn.Load(),
		// 	"bytes_out", info.BytesOut.Load(),
		// 	"active_connections", activeCount)

		// metrics.RecordConnection(string(info.ProxyType), "closed")
		// metrics.RecordConnectionDuration(string(info.ProxyType), duration)
	}
}

// UpdateActivity updates the last activity time for a connection
func (ct *ConnectionTracker) UpdateActivity(conn net.Conn, bytesIn, bytesOut uint64) {
	ct.mu.RLock()
	info, exists := ct.connections[conn]
	ct.mu.RUnlock()

	if exists {
		now := time.Now()
		info.LastActive.Store(&now)
		if bytesIn > 0 {
			info.BytesIn.Add(bytesIn)
		}
		if bytesOut > 0 {
			info.BytesOut.Add(bytesOut)
		}
	}
}

// GetActiveCount returns the number of active connections
func (ct *ConnectionTracker) GetActiveCount() int32 {
	return ct.stats.ActiveConnections.Load()
}

// GetStats returns current connection statistics
func (ct *ConnectionTracker) GetStats() map[string]interface{} {
	ct.mu.RLock()
	connectionDetails := make([]map[string]interface{}, 0, len(ct.connections))
	for _, info := range ct.connections {
		lastActive := info.LastActive.Load()
		var idleTime time.Duration
		if lastActive != nil {
			idleTime = time.Since(*lastActive)
		}
		connectionDetails = append(connectionDetails, map[string]interface{}{
			"remote_addr": info.RemoteAddr,
			"duration":    time.Since(info.StartTime),
			"bytes_in":    info.BytesIn.Load(),
			"bytes_out":   info.BytesOut.Load(),
			"idle_time":   idleTime,
			"proxy_type":  info.ProxyType,
		})
	}
	ct.mu.RUnlock()

	lastConnTime := ct.stats.LastConnectionTime.Load()
	var timeSinceLastConn time.Duration
	if lastConnTime != nil {
		timeSinceLastConn = time.Since(*lastConnTime)
	}

	return map[string]interface{}{
		"total_connections":    ct.stats.TotalConnections.Load(),
		"active_connections":   ct.stats.ActiveConnections.Load(),
		"rejected_connections": ct.stats.RejectedConnections.Load(),
		"max_concurrent":       ct.stats.MaxConcurrent.Load(),
		"max_allowed":          ct.maxConnections,
		"total_bytes_in":       ct.stats.TotalBytesIn.Load(),
		"total_bytes_out":      ct.stats.TotalBytesOut.Load(),
		"time_since_last_conn": timeSinceLastConn,
		"connections":          connectionDetails,
	}
}

// IsHealthy checks if the connection tracker is healthy
func (ct *ConnectionTracker) IsHealthy() bool {
	if ct.closed.Load() {
		return false
	}

	// Check if we're at capacity
	activeCount := ct.GetActiveCount()
	if float64(activeCount) >= float64(ct.maxConnections)*0.95 {
		return false
	}

	// Call custom health callback if set
	ct.mu.RLock()
	callback := ct.healthCallback
	ct.mu.RUnlock()

	if callback != nil {
		return callback()
	}

	return true
}

// ShouldPauseAccept returns true if new connections should be paused (backpressure)
func (ct *ConnectionTracker) ShouldPauseAccept() bool {
	activeCount := ct.GetActiveCount()
	return float64(activeCount) >= float64(ct.maxConnections)*0.9
}

// GetAcceptPauseChan returns a channel that signals when to pause accepting
func (ct *ConnectionTracker) GetAcceptPauseChan() <-chan struct{} {
	return ct.acceptPauseChan
}

// CloseAll closes all tracked connections with graceful shutdown
func (ct *ConnectionTracker) CloseAll(ctx context.Context) error {
	ct.closed.Store(true)

	// Create timeout context if not provided
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), ct.drainTimeout)
		defer cancel()
	}

	ct.mu.Lock()
	connections := make([]net.Conn, 0, len(ct.connections))
	for conn := range ct.connections {
		connections = append(connections, conn)
	}
	ct.mu.Unlock()

	// logger.Info("Starting graceful connection shutdown",
	// 	"connections", len(connections),
	// 	"timeout", ct.drainTimeout)

	// Close all connections
	var closeWg sync.WaitGroup
	for _, conn := range connections {
		conn := conn
		closeWg.Add(1)
		go func() {
			defer closeWg.Done()
			// Set deadline to force close if client doesn't disconnect
			if deadline, ok := ctx.Deadline(); ok {
				conn.SetDeadline(deadline)
			}
			if err := conn.Close(); err != nil {
				// logger.Debug("Error closing connection",
				// 	"error", err,
				// 	"remote_addr", conn.RemoteAddr())
			}
		}()
	}

	// Wait for all connections to close or timeout
	done := make(chan struct{})
	go func() {
		ct.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// logger.Info("All connections closed gracefully")
		return nil
	case <-ctx.Done():
		activeCount := ct.GetActiveCount()
		if activeCount > 0 {
			// logger.Warn("Connection drain timeout, forcing close",
			// 	"remaining_connections", activeCount)
			// Force close any remaining connections
			ct.mu.Lock()
			for conn := range ct.connections {
				conn.Close()
			}
			ct.mu.Unlock()
		}
		return fmt.Errorf("connection drain timeout with %d active connections", activeCount)
	}
}

// CleanupIdleConnections closes connections that have been idle for too long
func (ct *ConnectionTracker) CleanupIdleConnections(maxIdleTime time.Duration) int {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.closed.Load() {
		return 0
	}

	closedCount := 0
	now := time.Now()

	for conn, info := range ct.connections {
		lastActive := info.LastActive.Load()
		if lastActive != nil && now.Sub(*lastActive) > maxIdleTime {
			// logger.Debug("Closing idle connection",
			// 	"remote_addr", info.RemoteAddr,
			// 	"idle_time", now.Sub(*lastActive))
			conn.Close()
			closedCount++
		}
	}

	if closedCount > 0 {
		// logger.Info("Cleaned up idle connections", "count", closedCount)
	}

	return closedCount
}

// StartIdleConnectionCleanup starts a goroutine to periodically clean up idle connections
func (ct *ConnectionTracker) StartIdleConnectionCleanup(ctx context.Context, maxIdleTime, checkInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ct.CleanupIdleConnections(maxIdleTime)
			}
		}
	}()
}