package pool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	ErrPoolClosed    = errors.New("pool is closed")
	ErrPoolExhausted = errors.New("connection pool exhausted")
	ErrConnClosed    = errors.New("connection is closed")
)

type Factory func(ctx context.Context) (net.Conn, error)

type PooledConn struct {
	net.Conn
	pool      *Pool
	createdAt time.Time
	lastUsed  time.Time
	closed    bool
	mu        sync.Mutex
}

func (pc *PooledConn) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	
	if pc.closed {
		return nil
	}
	
	if pc.pool.closed {
		pc.closed = true
		return pc.Conn.Close()
	}
	
	// Return connection to pool if it's still healthy
	if time.Since(pc.createdAt) < pc.pool.maxLifetime {
		pc.lastUsed = time.Now()
		select {
		case pc.pool.conns <- pc:
			return nil
		default:
			// Pool is full, close the connection
		}
	}
	
	pc.closed = true
	return pc.Conn.Close()
}

func (pc *PooledConn) MarkUnhealthy() {
	pc.mu.Lock()
	pc.closed = true
	pc.mu.Unlock()
	pc.Conn.Close()
}

type Pool struct {
	factory     Factory
	conns       chan *PooledConn
	minConns    int
	maxConns    int
	maxLifetime time.Duration
	idleTimeout time.Duration
	closed      bool
	mu          sync.RWMutex
	
	// Statistics
	stats struct {
		created    uint64
		active     int32
		idle       int32
		closed     uint64
		timeouts   uint64
		errors     uint64
		mu         sync.RWMutex
	}
}

type Config struct {
	Factory     Factory
	MinConns    int
	MaxConns    int
	MaxLifetime time.Duration
	IdleTimeout time.Duration
}

func New(cfg Config) (*Pool, error) {
	if cfg.Factory == nil {
		return nil, errors.New("factory function is required")
	}
	
	if cfg.MinConns < 0 {
		cfg.MinConns = 0
	}
	
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 10
	}
	
	if cfg.MinConns > cfg.MaxConns {
		cfg.MinConns = cfg.MaxConns
	}
	
	if cfg.MaxLifetime <= 0 {
		cfg.MaxLifetime = 30 * time.Minute
	}
	
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	
	p := &Pool{
		factory:     cfg.Factory,
		conns:       make(chan *PooledConn, cfg.MaxConns),
		minConns:    cfg.MinConns,
		maxConns:    cfg.MaxConns,
		maxLifetime: cfg.MaxLifetime,
		idleTimeout: cfg.IdleTimeout,
	}
	
	// Pre-create minimum connections
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	for i := 0; i < p.minConns; i++ {
		conn, err := p.createConn(ctx)
		if err != nil {
			// Clean up any created connections
			p.Close()
			return nil, fmt.Errorf("failed to create initial connections: %w", err)
		}
		p.conns <- conn
	}
	
	// Start cleanup goroutine
	go p.cleanupLoop()
	
	return p, nil
}

func (p *Pool) Get(ctx context.Context) (net.Conn, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	p.mu.RUnlock()
	
	// Try to get an existing connection
	select {
	case conn := <-p.conns:
		if p.isHealthy(conn) {
			p.stats.mu.Lock()
			p.stats.idle--
			p.stats.active++
			p.stats.mu.Unlock()
			return conn, nil
		}
		// Connection is unhealthy, close it
		conn.MarkUnhealthy()
		p.stats.mu.Lock()
		p.stats.closed++
		p.stats.mu.Unlock()
		
	case <-ctx.Done():
		p.stats.mu.Lock()
		p.stats.timeouts++
		p.stats.mu.Unlock()
		return nil, ctx.Err()
		
	default:
		// No connections available
	}
	
	// Check if we can create a new connection
	p.stats.mu.Lock()
	if int(p.stats.active+p.stats.idle) >= p.maxConns {
		p.stats.mu.Unlock()
		
		// Wait for a connection to become available
		select {
		case conn := <-p.conns:
			if p.isHealthy(conn) {
				p.stats.mu.Lock()
				p.stats.idle--
				p.stats.active++
				p.stats.mu.Unlock()
				return conn, nil
			}
			conn.MarkUnhealthy()
			p.stats.mu.Lock()
			p.stats.closed++
			p.stats.mu.Unlock()
			
		case <-ctx.Done():
			p.stats.mu.Lock()
			p.stats.timeouts++
			p.stats.mu.Unlock()
			return nil, ctx.Err()
		}
	}
	p.stats.mu.Unlock()
	
	// Create a new connection
	conn, err := p.createConn(ctx)
	if err != nil {
		p.stats.mu.Lock()
		p.stats.errors++
		p.stats.mu.Unlock()
		return nil, err
	}
	
	p.stats.mu.Lock()
	p.stats.active++
	p.stats.mu.Unlock()
	
	return conn, nil
}

func (p *Pool) createConn(ctx context.Context) (*PooledConn, error) {
	conn, err := p.factory(ctx)
	if err != nil {
		return nil, err
	}
	
	p.stats.mu.Lock()
	p.stats.created++
	p.stats.mu.Unlock()
	
	return &PooledConn{
		Conn:      conn,
		pool:      p,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}, nil
}

func (p *Pool) isHealthy(conn *PooledConn) bool {
	if conn.closed {
		return false
	}
	
	// Check connection age
	if time.Since(conn.createdAt) > p.maxLifetime {
		return false
	}
	
	// Check idle time
	if time.Since(conn.lastUsed) > p.idleTimeout {
		return false
	}
	
	// Try to check if connection is still alive
	conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})
	
	one := make([]byte, 1)
	if _, err := conn.Read(one); err != nil {
		// If it's a timeout, the connection is probably still good
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true
		}
		return false
	}
	
	return true
}

func (p *Pool) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			p.cleanup()
		}
		
		p.mu.RLock()
		if p.closed {
			p.mu.RUnlock()
			return
		}
		p.mu.RUnlock()
	}
}

func (p *Pool) cleanup() {
	conns := make([]*PooledConn, 0)
	
	// Collect all connections
	for {
		select {
		case conn := <-p.conns:
			conns = append(conns, conn)
		default:
			goto check
		}
	}
	
check:
	// Check each connection and return healthy ones
	for _, conn := range conns {
		if p.isHealthy(conn) {
			select {
			case p.conns <- conn:
			default:
				conn.MarkUnhealthy()
				p.stats.mu.Lock()
				p.stats.closed++
				p.stats.mu.Unlock()
			}
		} else {
			conn.MarkUnhealthy()
			p.stats.mu.Lock()
			p.stats.closed++
			p.stats.idle--
			p.stats.mu.Unlock()
		}
	}
	
	// Ensure minimum connections
	p.stats.mu.RLock()
	currentConns := int(p.stats.idle)
	p.stats.mu.RUnlock()
	
	if currentConns < p.minConns {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		for i := currentConns; i < p.minConns; i++ {
			conn, err := p.createConn(ctx)
			if err != nil {
				break
			}
			
			select {
			case p.conns <- conn:
				p.stats.mu.Lock()
				p.stats.idle++
				p.stats.mu.Unlock()
			default:
				conn.MarkUnhealthy()
			}
		}
	}
}

func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	
	// Close all connections
	close(p.conns)
	for conn := range p.conns {
		conn.MarkUnhealthy()
	}
	
	return nil
}

func (p *Pool) Stats() PoolStats {
	p.stats.mu.RLock()
	defer p.stats.mu.RUnlock()
	
	return PoolStats{
		Created:  p.stats.created,
		Active:   p.stats.active,
		Idle:     p.stats.idle,
		Closed:   p.stats.closed,
		Timeouts: p.stats.timeouts,
		Errors:   p.stats.errors,
	}
}

type PoolStats struct {
	Created  uint64
	Active   int32
	Idle     int32
	Closed   uint64
	Timeouts uint64
	Errors   uint64
}

// PoolManager manages pools for different backends
type PoolManager struct {
	pools map[string]*Pool
	mu    sync.RWMutex
}

func NewPoolManager() *PoolManager {
	return &PoolManager{
		pools: make(map[string]*Pool),
	}
}

func (pm *PoolManager) GetPool(key string, cfg Config) (*Pool, error) {
	pm.mu.RLock()
	pool, exists := pm.pools[key]
	pm.mu.RUnlock()
	
	if exists {
		return pool, nil
	}
	
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Double-check after acquiring write lock
	pool, exists = pm.pools[key]
	if exists {
		return pool, nil
	}
	
	// Create new pool
	pool, err := New(cfg)
	if err != nil {
		return nil, err
	}
	
	pm.pools[key] = pool
	return pool, nil
}

func (pm *PoolManager) CloseAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	for _, pool := range pm.pools {
		pool.Close()
	}
	
	pm.pools = make(map[string]*Pool)
}