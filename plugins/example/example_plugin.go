// Package main implements an example plugin for LeProxy
package main

import (
	"fmt"
	"net/http"
	"time"
)

// Plugin is the exported plugin instance
var Plugin examplePlugin

type examplePlugin struct {
	config  map[string]interface{}
	enabled bool
	prefix  string
}

// Name returns the plugin name
func (p *examplePlugin) Name() string {
	return "example-plugin"
}

// Version returns the plugin version
func (p *examplePlugin) Version() string {
	return "1.0.0"
}

// Init initializes the plugin with configuration
func (p *examplePlugin) Init(config map[string]interface{}) error {
	p.config = config
	p.enabled = true
	
	// Read configuration
	if prefix, ok := config["prefix"].(string); ok {
		p.prefix = prefix
	} else {
		p.prefix = "X-Plugin"
	}
	
	fmt.Printf("Example plugin initialized with prefix: %s\n", p.prefix)
	return nil
}

// Middleware returns the HTTP middleware function
func (p *examplePlugin) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !p.enabled {
				next.ServeHTTP(w, r)
				return
			}
			
			// Add custom header
			w.Header().Set(fmt.Sprintf("%s-Timestamp", p.prefix), time.Now().Format(time.RFC3339))
			w.Header().Set(fmt.Sprintf("%s-Version", p.prefix), p.Version())
			
			// Log request
			fmt.Printf("[%s] %s %s %s\n", p.Name(), time.Now().Format(time.RFC3339), r.Method, r.URL.Path)
			
			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}

// Close cleans up plugin resources
func (p *examplePlugin) Close() error {
	p.enabled = false
	fmt.Printf("Example plugin closed\n")
	return nil
}

// Additional plugin functionality

// ProcessRequest can be called to process requests
func (p *examplePlugin) ProcessRequest(r *http.Request) {
	// Custom request processing logic
	fmt.Printf("Processing request: %s %s\n", r.Method, r.URL.Path)
}

// GetStats returns plugin statistics
func (p *examplePlugin) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"name":    p.Name(),
		"version": p.Version(),
		"enabled": p.enabled,
		"prefix":  p.prefix,
	}
}