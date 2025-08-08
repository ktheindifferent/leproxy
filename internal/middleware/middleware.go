package middleware

import (
	"context"
	"fmt"
	"net/http"
	"plugin"
	"sync"
	"time"
)

// Middleware represents a middleware function
type Middleware func(http.Handler) http.Handler

// Plugin represents a loadable plugin
type Plugin interface {
	// Name returns the plugin name
	Name() string
	
	// Version returns the plugin version
	Version() string
	
	// Init initializes the plugin with configuration
	Init(config map[string]interface{}) error
	
	// Middleware returns the HTTP middleware function
	Middleware() Middleware
	
	// Close cleans up plugin resources
	Close() error
}

// Chain creates a middleware chain
type Chain struct {
	middlewares []Middleware
}

// NewChain creates a new middleware chain
func NewChain(middlewares ...Middleware) *Chain {
	return &Chain{middlewares: middlewares}
}

// Then chains the middleware and returns final handler
func (c *Chain) Then(h http.Handler) http.Handler {
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		h = c.middlewares[i](h)
	}
	return h
}

// Append adds middleware to the chain
func (c *Chain) Append(middlewares ...Middleware) *Chain {
	newMiddlewares := make([]Middleware, len(c.middlewares)+len(middlewares))
	copy(newMiddlewares, c.middlewares)
	copy(newMiddlewares[len(c.middlewares):], middlewares)
	return &Chain{middlewares: newMiddlewares}
}

// PluginManager manages loaded plugins
type PluginManager struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

// NewPluginManager creates a new plugin manager
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make(map[string]Plugin),
	}
}

// LoadPlugin loads a plugin from file
func (pm *PluginManager) LoadPlugin(path string, config map[string]interface{}) error {
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}
	
	// Look for the Plugin symbol
	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("plugin does not export Plugin symbol: %w", err)
	}
	
	// Assert the symbol is a Plugin
	var plug Plugin
	plug, ok := symPlugin.(Plugin)
	if !ok {
		return fmt.Errorf("unexpected type from Plugin symbol")
	}
	
	// Initialize the plugin
	if err := plug.Init(config); err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}
	
	// Store the plugin
	pm.mu.Lock()
	pm.plugins[plug.Name()] = plug
	pm.mu.Unlock()
	
	return nil
}

// GetPlugin returns a loaded plugin by name
func (pm *PluginManager) GetPlugin(name string) (Plugin, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	p, ok := pm.plugins[name]
	return p, ok
}

// GetMiddleware returns middleware for all loaded plugins
func (pm *PluginManager) GetMiddleware() []Middleware {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	middlewares := make([]Middleware, 0, len(pm.plugins))
	for _, p := range pm.plugins {
		middlewares = append(middlewares, p.Middleware())
	}
	return middlewares
}

// Close closes all plugins
func (pm *PluginManager) Close() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	var lastErr error
	for name, p := range pm.plugins {
		if err := p.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close plugin %s: %w", name, err)
		}
		delete(pm.plugins, name)
	}
	return lastErr
}

// Built-in Middleware Functions

// RequestID adds a unique request ID to the context
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = generateRequestID()
		}
		
		ctx := context.WithValue(r.Context(), "request-id", id)
		w.Header().Set("X-Request-ID", id)
		
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logger logs HTTP requests
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		// Log the request (implementation depends on your logger)
		_ = duration // Use duration in actual logging
	})
}

// Recovery recovers from panics
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				// Log the panic (implementation depends on your logger)
			}
		}()
		
		next.ServeHTTP(w, r)
	})
}

// CORS adds CORS headers
func CORS(allowedOrigins []string, allowedMethods []string, allowedHeaders []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			
			// Check if origin is allowed
			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			
			if r.Method == "OPTIONS" {
				// Handle preflight request
				w.Header().Set("Access-Control-Allow-Methods", joinStrings(allowedMethods))
				w.Header().Set("Access-Control-Allow-Headers", joinStrings(allowedHeaders))
				w.Header().Set("Access-Control-Max-Age", "3600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// Compress adds response compression
func Compress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if client accepts compression
		if !acceptsCompression(r) {
			next.ServeHTTP(w, r)
			return
		}
		
		// Wrap response writer with compression
		cw := &compressWriter{
			ResponseWriter: w,
		}
		defer cw.Close()
		
		next.ServeHTTP(cw, r)
	})
}

// Timeout adds request timeout
func Timeout(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			
			done := make(chan bool)
			go func() {
				next.ServeHTTP(w, r.WithContext(ctx))
				done <- true
			}()
			
			select {
			case <-done:
				// Request completed
			case <-ctx.Done():
				// Timeout occurred
				w.WriteHeader(http.StatusGatewayTimeout)
			}
		})
	}
}

// BasicAuth adds basic authentication
func BasicAuth(users map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			
			expectedPassword, userExists := users[username]
			if !userExists || password != expectedPassword {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// Headers adds custom headers
func Headers(headers map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for key, value := range headers {
				w.Header().Set(key, value)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// StripPrefix strips a prefix from the request path
func StripPrefix(prefix string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.StripPrefix(prefix, next)
	}
}

// Rewrite rewrites request paths based on rules
func Rewrite(rules map[string]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for pattern, replacement := range rules {
				if matched, _ := matchPath(r.URL.Path, pattern); matched {
					r.URL.Path = replacement
					break
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(data)
}

// compressWriter wraps http.ResponseWriter with compression
type compressWriter struct {
	http.ResponseWriter
	// Add compression implementation
}

func (cw *compressWriter) Close() error {
	// Close compression
	return nil
}

// Helper functions

func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func acceptsCompression(r *http.Request) bool {
	return r.Header.Get("Accept-Encoding") != ""
}

func joinStrings(strings []string) string {
	result := ""
	for i, s := range strings {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

func matchPath(path, pattern string) (bool, map[string]string) {
	// Simple path matching implementation
	return path == pattern, nil
}

// MiddlewareStack manages ordered middleware execution
type MiddlewareStack struct {
	middlewares []MiddlewareEntry
	mu          sync.RWMutex
}

type MiddlewareEntry struct {
	Name       string
	Middleware Middleware
	Priority   int
	Enabled    bool
}

func NewMiddlewareStack() *MiddlewareStack {
	return &MiddlewareStack{
		middlewares: make([]MiddlewareEntry, 0),
	}
}

func (ms *MiddlewareStack) Add(name string, middleware Middleware, priority int) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	entry := MiddlewareEntry{
		Name:       name,
		Middleware: middleware,
		Priority:   priority,
		Enabled:    true,
	}
	
	// Insert in priority order
	inserted := false
	for i, existing := range ms.middlewares {
		if priority < existing.Priority {
			ms.middlewares = append(ms.middlewares[:i], append([]MiddlewareEntry{entry}, ms.middlewares[i:]...)...)
			inserted = true
			break
		}
	}
	
	if !inserted {
		ms.middlewares = append(ms.middlewares, entry)
	}
}

func (ms *MiddlewareStack) Remove(name string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	for i, entry := range ms.middlewares {
		if entry.Name == name {
			ms.middlewares = append(ms.middlewares[:i], ms.middlewares[i+1:]...)
			break
		}
	}
}

func (ms *MiddlewareStack) Enable(name string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	for i, entry := range ms.middlewares {
		if entry.Name == name {
			ms.middlewares[i].Enabled = true
			break
		}
	}
}

func (ms *MiddlewareStack) Disable(name string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	
	for i, entry := range ms.middlewares {
		if entry.Name == name {
			ms.middlewares[i].Enabled = false
			break
		}
	}
}

func (ms *MiddlewareStack) Handler(next http.Handler) http.Handler {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	
	// Build chain from enabled middlewares
	for i := len(ms.middlewares) - 1; i >= 0; i-- {
		if ms.middlewares[i].Enabled {
			next = ms.middlewares[i].Middleware(next)
		}
	}
	
	return next
}