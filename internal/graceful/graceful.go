package graceful

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Server struct {
	httpServer      *http.Server
	listeners       map[string]net.Listener
	activeConns     map[net.Conn]struct{}
	shutdownTimeout time.Duration
	reloadFunc      func() error
	
	mu           sync.RWMutex
	shutdown     chan struct{}
	shutdownOnce sync.Once
	isShutdown   int32
	
	// Statistics
	stats struct {
		activeRequests   int64
		totalRequests    int64
		gracefulReloads  int64
		gracefulShutdowns int64
	}
}

type Config struct {
	HTTPServer      *http.Server
	ShutdownTimeout time.Duration
	ReloadFunc      func() error
}

func New(cfg Config) *Server {
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	
	s := &Server{
		httpServer:      cfg.HTTPServer,
		listeners:       make(map[string]net.Listener),
		activeConns:     make(map[net.Conn]struct{}),
		shutdownTimeout: cfg.ShutdownTimeout,
		reloadFunc:      cfg.ReloadFunc,
		shutdown:        make(chan struct{}),
	}
	
	// Wrap the HTTP server's ConnState to track connections
	originalConnState := cfg.HTTPServer.ConnState
	cfg.HTTPServer.ConnState = func(conn net.Conn, state http.ConnState) {
		s.trackConnection(conn, state)
		if originalConnState != nil {
			originalConnState(conn, state)
		}
	}
	
	return s
}

func (s *Server) ListenAndServe(addr string) error {
	if atomic.LoadInt32(&s.isShutdown) == 1 {
		return fmt.Errorf("server is shutdown")
	}
	
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	
	return s.Serve(ln)
}

func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.listeners[ln.Addr().String()] = ln
	s.mu.Unlock()
	
	defer func() {
		s.mu.Lock()
		delete(s.listeners, ln.Addr().String())
		s.mu.Unlock()
	}()
	
	// Create a tracked listener
	tl := &trackedListener{
		Listener: ln,
		server:   s,
	}
	
	return s.httpServer.Serve(tl)
}

func (s *Server) trackConnection(conn net.Conn, state http.ConnState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	switch state {
	case http.StateNew:
		s.activeConns[conn] = struct{}{}
		atomic.AddInt64(&s.stats.activeRequests, 1)
		atomic.AddInt64(&s.stats.totalRequests, 1)
		
	case http.StateHijacked, http.StateClosed:
		delete(s.activeConns, conn)
		atomic.AddInt64(&s.stats.activeRequests, -1)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&s.isShutdown, 1)
	atomic.AddInt64(&s.stats.gracefulShutdowns, 1)
	
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		close(s.shutdown)
		
		// Close all listeners
		s.mu.Lock()
		for _, ln := range s.listeners {
			ln.Close()
		}
		s.mu.Unlock()
		
		// Shutdown HTTP server
		shutdownErr = s.httpServer.Shutdown(ctx)
		
		// Wait for active connections with timeout
		done := make(chan struct{})
		go func() {
			s.waitForConnections()
			close(done)
		}()
		
		select {
		case <-done:
			// All connections closed
		case <-ctx.Done():
			// Timeout - force close remaining connections
			s.forceCloseConnections()
		}
	})
	
	return shutdownErr
}

func (s *Server) waitForConnections() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		s.mu.RLock()
		count := len(s.activeConns)
		s.mu.RUnlock()
		
		if count == 0 {
			return
		}
		
		<-ticker.C
	}
}

func (s *Server) forceCloseConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	for conn := range s.activeConns {
		conn.Close()
	}
	s.activeConns = make(map[net.Conn]struct{})
}

func (s *Server) Reload() error {
	if s.reloadFunc == nil {
		return fmt.Errorf("reload function not configured")
	}
	
	atomic.AddInt64(&s.stats.gracefulReloads, 1)
	
	// Execute reload function
	if err := s.reloadFunc(); err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}
	
	return nil
}

func (s *Server) HandleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	
	for sig := range sigChan {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			// Graceful shutdown
			ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
			defer cancel()
			
			if err := s.Shutdown(ctx); err != nil {
				os.Exit(1)
			}
			os.Exit(0)
			
		case syscall.SIGHUP:
			// Reload configuration
			if err := s.Reload(); err != nil {
				// Log error but don't exit
			}
			
		case syscall.SIGUSR1:
			// Reopen log files (useful for log rotation)
			// This would be implemented based on your logging setup
			
		case syscall.SIGUSR2:
			// Custom signal for debugging/stats
			s.printStats()
		}
	}
}

func (s *Server) printStats() {
	fmt.Printf("Server Statistics:\n")
	fmt.Printf("  Active Requests: %d\n", atomic.LoadInt64(&s.stats.activeRequests))
	fmt.Printf("  Total Requests: %d\n", atomic.LoadInt64(&s.stats.totalRequests))
	fmt.Printf("  Graceful Reloads: %d\n", atomic.LoadInt64(&s.stats.gracefulReloads))
	fmt.Printf("  Graceful Shutdowns: %d\n", atomic.LoadInt64(&s.stats.gracefulShutdowns))
	
	s.mu.RLock()
	fmt.Printf("  Active Connections: %d\n", len(s.activeConns))
	s.mu.RUnlock()
}

func (s *Server) Stats() Stats {
	s.mu.RLock()
	activeConns := len(s.activeConns)
	s.mu.RUnlock()
	
	return Stats{
		ActiveRequests:    atomic.LoadInt64(&s.stats.activeRequests),
		TotalRequests:     atomic.LoadInt64(&s.stats.totalRequests),
		ActiveConnections: activeConns,
		GracefulReloads:   atomic.LoadInt64(&s.stats.gracefulReloads),
		GracefulShutdowns: atomic.LoadInt64(&s.stats.gracefulShutdowns),
	}
}

type Stats struct {
	ActiveRequests    int64
	TotalRequests     int64
	ActiveConnections int
	GracefulReloads   int64
	GracefulShutdowns int64
}

// trackedListener wraps a net.Listener to track accepted connections
type trackedListener struct {
	net.Listener
	server *Server
}

func (tl *trackedListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	
	// Check if server is shutting down
	select {
	case <-tl.server.shutdown:
		conn.Close()
		return nil, http.ErrServerClosed
	default:
	}
	
	return &trackedConn{
		Conn:   conn,
		server: tl.server,
	}, nil
}

// trackedConn wraps a net.Conn to track its lifecycle
type trackedConn struct {
	net.Conn
	server *Server
	once   sync.Once
}

func (tc *trackedConn) Close() error {
	var err error
	tc.once.Do(func() {
		tc.server.mu.Lock()
		delete(tc.server.activeConns, tc)
		tc.server.mu.Unlock()
		
		err = tc.Conn.Close()
	})
	return err
}

// Manager handles multiple graceful servers
type Manager struct {
	servers map[string]*Server
	mu      sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		servers: make(map[string]*Server),
	}
}

func (m *Manager) Add(name string, server *Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.servers[name] = server
}

func (m *Manager) Remove(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.servers, name)
}

func (m *Manager) ShutdownAll(ctx context.Context) error {
	m.mu.RLock()
	servers := make([]*Server, 0, len(m.servers))
	for _, srv := range m.servers {
		servers = append(servers, srv)
	}
	m.mu.RUnlock()
	
	var wg sync.WaitGroup
	errChan := make(chan error, len(servers))
	
	for _, srv := range servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			if err := s.Shutdown(ctx); err != nil {
				errChan <- err
			}
		}(srv)
	}
	
	wg.Wait()
	close(errChan)
	
	// Return first error if any
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	
	return nil
}

func (m *Manager) ReloadAll() error {
	m.mu.RLock()
	servers := make([]*Server, 0, len(m.servers))
	for _, srv := range m.servers {
		servers = append(servers, srv)
	}
	m.mu.RUnlock()
	
	for _, srv := range servers {
		if err := srv.Reload(); err != nil {
			return err
		}
	}
	
	return nil
}

func (m *Manager) HandleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	
	for sig := range sigChan {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			
			if err := m.ShutdownAll(ctx); err != nil {
				os.Exit(1)
			}
			os.Exit(0)
			
		case syscall.SIGHUP:
			m.ReloadAll()
		}
	}
}