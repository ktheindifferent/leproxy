package graceful

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/metrics"
)

type Server struct {
	httpServer      *http.Server
	listeners       map[string]net.Listener
	activeConns     map[net.Conn]struct{}
	shutdownTimeout time.Duration
	reloadFunc      func() error
	
	// Shutdown hooks for external components
	shutdownHooks   []ShutdownHook
	cleanupFuncs    []func() error
	
	// Enhanced shutdown tracking
	shutdownMetrics *ShutdownMetrics
	errorCollector  *MultiError
	
	mu           sync.RWMutex
	shutdown     chan struct{}
	shutdownOnce sync.Once
	isShutdown   int32
	
	// Progress reporting
	progressChan chan ShutdownProgress
	
	// Statistics
	stats struct {
		activeRequests   int64
		totalRequests    int64
		gracefulReloads  int64
		gracefulShutdowns int64
	}
}

// ShutdownHook represents a component that needs graceful shutdown
type ShutdownHook struct {
	Name     string
	Phase    ShutdownPhase
	Priority int // Lower values shut down first within a phase
	Shutdown func(context.Context) error
}

// ShutdownProgress represents progress during shutdown
type ShutdownProgress struct {
	Phase     ShutdownPhase
	Component string
	Message   string
	Progress  float64 // 0.0 to 1.0
	Timestamp time.Time
}

type Config struct {
	HTTPServer      *http.Server
	ShutdownTimeout time.Duration
	ReloadFunc      func() error
	EnableProgress  bool // Enable progress reporting
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
		shutdownHooks:   make([]ShutdownHook, 0),
		cleanupFuncs:    make([]func() error, 0),
		shutdownMetrics: NewShutdownMetrics(),
		errorCollector:  NewMultiError(),
	}
	
	if cfg.EnableProgress {
		s.progressChan = make(chan ShutdownProgress, 100)
		go s.progressReporter()
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

// RegisterShutdownHook adds a shutdown hook for external components
func (s *Server) RegisterShutdownHook(hook ShutdownHook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdownHooks = append(s.shutdownHooks, hook)
}

// RegisterCleanup adds a cleanup function to be called during shutdown
func (s *Server) RegisterCleanup(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupFuncs = append(s.cleanupFuncs, fn)
}

func (s *Server) Shutdown(ctx context.Context) error {
	atomic.StoreInt32(&s.isShutdown, 1)
	atomic.AddInt64(&s.stats.gracefulShutdowns, 1)
	
	var finalErr error
	s.shutdownOnce.Do(func() {
		s.shutdownMetrics.StartTime = time.Now()
		logger.Info("Starting graceful shutdown", map[string]interface{}{
			"timeout": s.shutdownTimeout,
		})
		
		close(s.shutdown)
		
		// Create a context with timeout for the entire shutdown
		shutdownCtx, cancel := context.WithTimeout(ctx, s.shutdownTimeout)
		defer cancel()
		
		// Execute shutdown in phases
		s.executeShutdownPhases(shutdownCtx)
		
		// Finalize metrics
		s.shutdownMetrics.Finalize(s.errorCollector.Count())
		
		// Report metrics
		if metrics.IsEnabled() {
			s.recordShutdownMetrics()
		}
		
		// Log shutdown summary
		logger.Info("Shutdown completed", map[string]interface{}{
			"duration": s.shutdownMetrics.Duration,
			"errors":   s.errorCollector.Count(),
			"metrics":  s.shutdownMetrics.String(),
		})
		
		finalErr = s.errorCollector.ErrorOrNil()
	})
	
	return finalErr
}

func (s *Server) executeShutdownPhases(ctx context.Context) {
	// Phase 1: Close listeners
	s.shutdownPhase(ctx, PhaseListeners, func(phaseCtx context.Context) {
		s.shutdownMetrics.StartPhase(PhaseListeners)
		defer s.shutdownMetrics.EndPhase(PhaseListeners, 0)
		
		s.reportProgress(PhaseListeners, "listeners", "Closing all listeners", 0.0)
		
		s.mu.Lock()
		listenerCount := len(s.listeners)
		closed := 0
		for addr, ln := range s.listeners {
			s.shutdownMetrics.AddComponent(PhaseListeners, addr)
			if err := ln.Close(); err != nil {
				s.errorCollector.AddWithContext(PhaseListeners, addr, err, 0)
			}
			closed++
			s.reportProgress(PhaseListeners, "listeners", 
				fmt.Sprintf("Closed %d/%d listeners", closed, listenerCount), 
				float64(closed)/float64(listenerCount))
		}
		s.mu.Unlock()
		
		s.reportProgress(PhaseListeners, "listeners", "All listeners closed", 1.0)
	})
	
	// Phase 2: Shutdown HTTP server
	s.shutdownPhase(ctx, PhaseConnections, func(phaseCtx context.Context) {
		s.shutdownMetrics.StartPhase(PhaseConnections)
		defer s.shutdownMetrics.EndPhase(PhaseConnections, 0)
		
		s.reportProgress(PhaseConnections, "http-server", "Shutting down HTTP server", 0.0)
		s.shutdownMetrics.AddComponent(PhaseConnections, "http-server")
		
		start := time.Now()
		if err := s.httpServer.Shutdown(phaseCtx); err != nil {
			s.errorCollector.AddWithContext(PhaseConnections, "http-server", err, time.Since(start))
		}
		
		s.reportProgress(PhaseConnections, "http-server", "HTTP server shutdown complete", 0.5)
		
		// Wait for active connections or timeout
		done := make(chan struct{})
		go func() {
			s.waitForConnectionsWithProgress()
			close(done)
		}()
		
		select {
		case <-done:
			s.reportProgress(PhaseConnections, "connections", "All connections closed gracefully", 1.0)
		case <-phaseCtx.Done():
			logger.Warn("Connection shutdown timeout - forcing close", nil)
			s.forceCloseConnections()
			s.errorCollector.Add(ErrShutdownTimeout)
			s.reportProgress(PhaseConnections, "connections", "Forced connection closure", 1.0)
		}
	})
	
	// Phase 3: Shutdown external components (pools, services, etc.)
	s.shutdownExternalComponents(ctx)
	
	// Phase 4: Run cleanup functions
	s.shutdownPhase(ctx, PhaseCleanup, func(phaseCtx context.Context) {
		s.shutdownMetrics.StartPhase(PhaseCleanup)
		defer s.shutdownMetrics.EndPhase(PhaseCleanup, 0)
		
		s.reportProgress(PhaseCleanup, "cleanup", "Running cleanup functions", 0.0)
		
		total := len(s.cleanupFuncs)
		for i, fn := range s.cleanupFuncs {
			s.shutdownMetrics.AddComponent(PhaseCleanup, fmt.Sprintf("cleanup-%d", i))
			if err := fn(); err != nil {
				s.errorCollector.AddWithContext(PhaseCleanup, fmt.Sprintf("cleanup-%d", i), err, 0)
			}
			s.reportProgress(PhaseCleanup, "cleanup", 
				fmt.Sprintf("Completed %d/%d cleanup tasks", i+1, total),
				float64(i+1)/float64(total))
		}
		
		s.reportProgress(PhaseCleanup, "cleanup", "All cleanup tasks completed", 1.0)
	})
	
	// Close progress channel if it exists
	if s.progressChan != nil {
		close(s.progressChan)
	}
}

func (s *Server) shutdownPhase(ctx context.Context, phase ShutdownPhase, fn func(context.Context)) {
	// Create a sub-context with a portion of the remaining time
	deadline, ok := ctx.Deadline()
	if !ok {
		fn(ctx)
		return
	}
	
	remaining := time.Until(deadline)
	phaseTimeout := remaining / 3 // Give each phase 1/3 of remaining time
	if phaseTimeout < time.Second {
		phaseTimeout = time.Second
	}
	
	phaseCtx, cancel := context.WithTimeout(ctx, phaseTimeout)
	defer cancel()
	
	fn(phaseCtx)
}

func (s *Server) shutdownExternalComponents(ctx context.Context) {
	// Group hooks by phase
	phaseHooks := make(map[ShutdownPhase][]ShutdownHook)
	for _, hook := range s.shutdownHooks {
		phaseHooks[hook.Phase] = append(phaseHooks[hook.Phase], hook)
	}
	
	// Execute hooks in phase order
	for _, phase := range []ShutdownPhase{PhasePools, PhaseServices, PhaseTracers} {
		hooks := phaseHooks[phase]
		if len(hooks) == 0 {
			continue
		}
		
		s.shutdownPhase(ctx, phase, func(phaseCtx context.Context) {
			s.shutdownMetrics.StartPhase(phase)
			defer s.shutdownMetrics.EndPhase(phase, 0)
			
			s.reportProgress(phase, string(phase), fmt.Sprintf("Shutting down %d components", len(hooks)), 0.0)
			
			// Sort hooks by priority
			sortShutdownHooks(hooks)
			
			// Execute hooks with error collection
			for i, hook := range hooks {
				s.shutdownMetrics.AddComponent(phase, hook.Name)
				start := time.Now()
				
				if err := hook.Shutdown(phaseCtx); err != nil {
					s.errorCollector.AddWithContext(phase, hook.Name, err, time.Since(start))
				}
				
				s.reportProgress(phase, string(phase),
					fmt.Sprintf("Completed %d/%d components", i+1, len(hooks)),
					float64(i+1)/float64(len(hooks)))
			}
			
			s.reportProgress(phase, string(phase), "Phase completed", 1.0)
		})
	}
}

// sortShutdownHooks sorts hooks by priority (lower priority shuts down first)
func sortShutdownHooks(hooks []ShutdownHook) {
	for i := 0; i < len(hooks)-1; i++ {
		for j := i + 1; j < len(hooks); j++ {
			if hooks[j].Priority < hooks[i].Priority {
				hooks[i], hooks[j] = hooks[j], hooks[i]
			}
		}
	}
}

func (s *Server) waitForConnectionsWithProgress() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	initialCount := 0
	s.mu.RLock()
	initialCount = len(s.activeConns)
	s.mu.RUnlock()
	
	if initialCount == 0 {
		return
	}
	
	for {
		s.mu.RLock()
		count := len(s.activeConns)
		s.mu.RUnlock()
		
		if count == 0 {
			return
		}
		
		closed := initialCount - count
		progress := float64(closed) / float64(initialCount)
		s.reportProgress(PhaseConnections, "active-connections",
			fmt.Sprintf("Waiting for %d connections to close", count), progress)
		
		<-ticker.C
	}
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
	signal.Notify(sigChan, 
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, 
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGQUIT)
	
	for sig := range sigChan {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			// Graceful shutdown
			logger.Info("Received shutdown signal", map[string]interface{}{"signal": sig.String()})
			ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout) // This is OK - it's in the shutdown signal handler
			defer cancel()
			
			if err := s.Shutdown(ctx); err != nil {
				logger.Error("Shutdown failed", map[string]interface{}{"error": err})
				os.Exit(1)
			}
			os.Exit(0)
			
		case syscall.SIGHUP:
			// Reload configuration
			logger.Info("Received reload signal", nil)
			if err := s.Reload(); err != nil {
				logger.Error("Reload failed", map[string]interface{}{"error": err})
			}
			
		case syscall.SIGUSR1:
			// Dump statistics to log
			s.dumpStats()
			
		case syscall.SIGUSR2:
			// Dump goroutine stacks for debugging
			s.dumpGoroutines()
			
		case syscall.SIGQUIT:
			// Force shutdown with stack dump
			s.forceShutdownWithDump()
		}
	}
}

func (s *Server) dumpStats() {
	stats := s.Stats()
	logger.Info("Server statistics dump", map[string]interface{}{
		"active_requests":    stats.ActiveRequests,
		"total_requests":     stats.TotalRequests,
		"active_connections": stats.ActiveConnections,
		"graceful_reloads":   stats.GracefulReloads,
		"graceful_shutdowns": stats.GracefulShutdowns,
		"goroutines":         runtime.NumGoroutine(),
		"memory_alloc":       getMemStats().Alloc,
		"memory_sys":         getMemStats().Sys,
	})
}

func (s *Server) dumpGoroutines() {
	buf := make([]byte, 1<<20) // 1MB buffer
	stackSize := runtime.Stack(buf, true)
	logger.Info("Goroutine stack dump", map[string]interface{}{
		"stack_size": stackSize,
		"stack":      string(buf[:stackSize]),
	})
}

func (s *Server) forceShutdownWithDump() {
	logger.Warn("Force shutdown initiated - dumping state", nil)
	
	// Dump goroutines
	s.dumpGoroutines()
	
	// Dump heap profile if possible
	if f, err := os.Create("/tmp/leproxy-heap.prof"); err == nil {
		pprof.WriteHeapProfile(f)
		f.Close()
		logger.Info("Heap profile written", map[string]interface{}{"file": "/tmp/leproxy-heap.prof"})
	}
	
	// Force close everything
	s.forceCloseConnections()
	
	// Exit immediately
	os.Exit(130) // 128 + SIGQUIT(3)
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

func getMemStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
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
	servers := make([]string, 0, len(m.servers))
	serverList := make([]*Server, 0, len(m.servers))
	for name, srv := range m.servers {
		servers = append(servers, name)
		serverList = append(serverList, srv)
	}
	m.mu.RUnlock()
	
	logger.Info("Manager shutting down all servers", map[string]interface{}{
		"count": len(servers),
		"servers": servers,
	})
	
	errorCollector := NewMultiError()
	var wg sync.WaitGroup
	
	for i, srv := range serverList {
		wg.Add(1)
		serverName := servers[i]
		go func(name string, s *Server) {
			defer wg.Done()
			start := time.Now()
			if err := s.Shutdown(ctx); err != nil {
				errorCollector.AddWithContext(PhaseServices, name, err, time.Since(start))
			}
		}(serverName, srv)
	}
	
	wg.Wait()
	
	if errorCollector.HasErrors() {
		logger.Error("Manager shutdown completed with errors", map[string]interface{}{
			"error_count": errorCollector.Count(),
			"errors": errorCollector.Error(),
		})
	} else {
		logger.Info("Manager shutdown completed successfully", nil)
	}
	
	return errorCollector.ErrorOrNil()
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

// reportProgress sends progress updates if channel is available
func (s *Server) reportProgress(phase ShutdownPhase, component, message string, progress float64) {
	if s.progressChan == nil {
		return
	}
	
	select {
	case s.progressChan <- ShutdownProgress{
		Phase:     phase,
		Component: component,
		Message:   message,
		Progress:  progress,
		Timestamp: time.Now(),
	}:
	default:
		// Don't block if channel is full
	}
}

// progressReporter handles progress reporting
func (s *Server) progressReporter() {
	for progress := range s.progressChan {
		logger.Info("Shutdown progress", map[string]interface{}{
			"phase":     progress.Phase,
			"component": progress.Component,
			"message":   progress.Message,
			"progress":  fmt.Sprintf("%.0f%%", progress.Progress*100),
		})
	}
}

// recordShutdownMetrics records shutdown metrics for monitoring
func (s *Server) recordShutdownMetrics() {
	registry := metrics.DefaultRegistry()
	
	// Record total shutdown duration
	if m := registry.Get("graceful_shutdown_duration_seconds"); m != nil {
		m.Set(s.shutdownMetrics.Duration.Seconds())
	}
	
	// Record errors count
	if m := registry.Get("graceful_shutdown_errors_total"); m != nil {
		for i := 0; i < s.shutdownMetrics.ErrorCount; i++ {
			m.Inc()
		}
	}
	
	// Record phase durations
	for phase, pm := range s.shutdownMetrics.PhaseMetrics {
		metricName := fmt.Sprintf("graceful_shutdown_phase_duration_seconds{phase=\"%s\"}", phase)
		if m := registry.Get(metricName); m != nil {
			m.Set(pm.Duration.Seconds())
		}
	}
}

// GetShutdownProgress returns current shutdown progress channel for monitoring
func (s *Server) GetShutdownProgress() <-chan ShutdownProgress {
	return s.progressChan
}

// IsShuttingDown returns true if server is in shutdown process
func (s *Server) IsShuttingDown() bool {
	return atomic.LoadInt32(&s.isShutdown) == 1
}

func (m *Manager) HandleSignals() {
	m.HandleSignalsWithContext(context.Background())
}

func (m *Manager) HandleSignalsWithContext(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)
	
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				
				if err := m.ShutdownAll(shutdownCtx); err != nil {
					logger.Error("Manager shutdown failed", map[string]interface{}{"error": err})
					os.Exit(1)
				}
				os.Exit(0)
				
			case syscall.SIGHUP:
				if err := m.ReloadAll(); err != nil {
					logger.Error("Manager reload failed", map[string]interface{}{"error": err})
				}
			}
		}
	}
}

// ShutdownCoordinator coordinates shutdown of multiple resources
type ShutdownCoordinator struct {
	server         *Server
	shutdownFuncs  []ShutdownFunc
	mu             sync.Mutex
	shutdownTimeout time.Duration
}

// ShutdownFunc represents a function to be called during shutdown
type ShutdownFunc struct {
	Name     string
	Fn       func(context.Context) error
	Timeout  time.Duration
}

// NewShutdownCoordinator creates a new shutdown coordinator
func NewShutdownCoordinator(server *Server, timeout time.Duration) *ShutdownCoordinator {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ShutdownCoordinator{
		server:          server,
		shutdownFuncs:   make([]ShutdownFunc, 0),
		shutdownTimeout: timeout,
	}
}

// AddShutdownFunc adds a shutdown function to be called during graceful shutdown
func (sc *ShutdownCoordinator) AddShutdownFunc(name string, fn func(context.Context) error, timeout time.Duration) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	sc.shutdownFuncs = append(sc.shutdownFuncs, ShutdownFunc{
		Name:    name,
		Fn:      fn,
		Timeout: timeout,
	})
}

// Shutdown performs coordinated shutdown of all resources
func (sc *ShutdownCoordinator) Shutdown(ctx context.Context) error {
	// First shutdown the HTTP server
	serverErr := sc.server.Shutdown(ctx)
	
	// Then shutdown additional resources in parallel
	sc.mu.Lock()
	funcs := make([]ShutdownFunc, len(sc.shutdownFuncs))
	copy(funcs, sc.shutdownFuncs)
	sc.mu.Unlock()
	
	var wg sync.WaitGroup
	errChan := make(chan error, len(funcs))
	
	for _, sf := range funcs {
		wg.Add(1)
		go func(shutdownFunc ShutdownFunc) {
			defer wg.Done()
			
			// Create context with specific timeout for this resource
			fnCtx, cancel := context.WithTimeout(ctx, shutdownFunc.Timeout)
			defer cancel()
			
			// Execute shutdown function
			if err := shutdownFunc.Fn(fnCtx); err != nil {
				errChan <- fmt.Errorf("%s shutdown failed: %w", shutdownFunc.Name, err)
			}
		}(sf)
	}
	
	// Wait for all shutdowns to complete
	wg.Wait()
	close(errChan)
	
	// Collect all errors
	var errors []error
	if serverErr != nil {
		errors = append(errors, fmt.Errorf("server shutdown failed: %w", serverErr))
	}
	
	for err := range errChan {
		errors = append(errors, err)
	}
	
	// Return aggregated error if any
	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}
	
	return nil
}

// HandleSignals handles OS signals for graceful shutdown
func (sc *ShutdownCoordinator) HandleSignals() {
	sc.HandleSignalsWithContext(context.Background())
}

func (sc *ShutdownCoordinator) HandleSignalsWithContext(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)
	
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				shutdownCtx, cancel := context.WithTimeout(ctx, sc.shutdownTimeout)
				defer cancel()
				
				if err := sc.Shutdown(shutdownCtx); err != nil {
					// Log the error (assuming logger is available)
					fmt.Fprintf(os.Stderr, "Shutdown error: %v\n", err)
					os.Exit(1)
				}
				os.Exit(0)
				
			case syscall.SIGHUP:
				// Reload if server has reload function
				if sc.server.reloadFunc != nil {
					if err := sc.server.Reload(); err != nil {
						fmt.Fprintf(os.Stderr, "Reload error: %v\n", err)
					}
				}
			}
		}
	}
}