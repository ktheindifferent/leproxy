// Package reload provides hot configuration reload functionality
package reload

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/artyom/leproxy/internal/logger"
	"gopkg.in/yaml.v2"
)

// ConfigReloader manages hot configuration reloading
type ConfigReloader struct {
	mu            sync.RWMutex
	configFile    string
	mappings      atomic.Value // map[string]string
	lastModified  time.Time
	watchInterval time.Duration
	stopChan      chan struct{}
	handlers      []ReloadHandler
	proxyCache    map[string]*httputil.ReverseProxy
}

// ReloadHandler is called when configuration is reloaded
type ReloadHandler func(oldConfig, newConfig map[string]string) error

// NewConfigReloader creates a new configuration reloader
func NewConfigReloader(configFile string, watchInterval time.Duration) *ConfigReloader {
	cr := &ConfigReloader{
		configFile:    configFile,
		watchInterval: watchInterval,
		stopChan:      make(chan struct{}),
		proxyCache:    make(map[string]*httputil.ReverseProxy),
	}
	
	// Load initial configuration
	if err := cr.Reload(); err != nil {
		logger.Warn("Failed to load initial configuration", "error", err)
	}
	
	return cr
}

// Start begins watching for configuration changes
func (cr *ConfigReloader) Start() {
	go cr.watchLoop()
	logger.Info("Configuration reloader started", "file", cr.configFile, "interval", cr.watchInterval)
}

// Stop stops watching for configuration changes
func (cr *ConfigReloader) Stop() {
	close(cr.stopChan)
	logger.Info("Configuration reloader stopped")
}

// watchLoop monitors the configuration file for changes
func (cr *ConfigReloader) watchLoop() {
	ticker := time.NewTicker(cr.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cr.checkAndReload()
		case <-cr.stopChan:
			return
		}
	}
}

// checkAndReload checks if the configuration file has been modified and reloads if necessary
func (cr *ConfigReloader) checkAndReload() {
	info, err := os.Stat(cr.configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error("Failed to stat config file", "error", err)
		}
		return
	}

	if info.ModTime().After(cr.lastModified) {
		logger.Info("Configuration file changed, reloading", "file", cr.configFile)
		if err := cr.Reload(); err != nil {
			logger.Error("Failed to reload configuration", "error", err)
		}
	}
}

// Reload forces a configuration reload
func (cr *ConfigReloader) Reload() error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	// Read the configuration file
	newMappings, err := cr.readConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Get the old mappings
	oldMappings := cr.GetMappings()

	// Update the mappings atomically
	cr.mappings.Store(newMappings)

	// Update last modified time
	if info, err := os.Stat(cr.configFile); err == nil {
		cr.lastModified = info.ModTime()
	}

	// Clear proxy cache for changed mappings
	cr.clearChangedProxies(oldMappings, newMappings)

	// Call reload handlers
	for _, handler := range cr.handlers {
		if err := handler(oldMappings, newMappings); err != nil {
			logger.Error("Reload handler failed", "error", err)
		}
	}

	logger.Info("Configuration reloaded successfully", 
		"mappings", len(newMappings),
		"added", countAdded(oldMappings, newMappings),
		"removed", countRemoved(oldMappings, newMappings),
		"modified", countModified(oldMappings, newMappings))

	return nil
}

// readConfig reads the configuration file
func (cr *ConfigReloader) readConfig() (map[string]string, error) {
	data, err := ioutil.ReadFile(cr.configFile)
	if err != nil {
		return nil, err
	}

	// Try to parse as YAML first
	var yamlConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlConfig); err == nil {
		return cr.parseYAMLConfig(yamlConfig)
	}

	// Try to parse as JSON
	var jsonConfig map[string]interface{}
	if err := json.Unmarshal(data, &jsonConfig); err == nil {
		return cr.parseJSONConfig(jsonConfig)
	}

	// Parse as simple text format (host:backend)
	return cr.parseTextConfig(string(data))
}

// parseYAMLConfig parses YAML configuration
func (cr *ConfigReloader) parseYAMLConfig(config map[string]interface{}) (map[string]string, error) {
	mappings := make(map[string]string)

	// Check for mappings section
	if mappingsSection, ok := config["mappings"].(map[interface{}]interface{}); ok {
		for k, v := range mappingsSection {
			host := fmt.Sprintf("%v", k)
			
			// Handle different backend formats
			switch backend := v.(type) {
			case string:
				mappings[host] = backend
			case map[interface{}]interface{}:
				if url, ok := backend["url"].(string); ok {
					mappings[host] = url
				}
			}
		}
	}

	return mappings, nil
}

// parseJSONConfig parses JSON configuration
func (cr *ConfigReloader) parseJSONConfig(config map[string]interface{}) (map[string]string, error) {
	mappings := make(map[string]string)

	// Check for mappings section
	if mappingsSection, ok := config["mappings"].(map[string]interface{}); ok {
		for host, v := range mappingsSection {
			switch backend := v.(type) {
			case string:
				mappings[host] = backend
			case map[string]interface{}:
				if url, ok := backend["url"].(string); ok {
					mappings[host] = url
				}
			}
		}
	}

	return mappings, nil
}

// parseTextConfig parses simple text configuration
func (cr *ConfigReloader) parseTextConfig(data string) (map[string]string, error) {
	mappings := make(map[string]string)
	
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse host:backend format
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			host := strings.TrimSpace(parts[0])
			backend := strings.TrimSpace(parts[1])
			mappings[host] = backend
		}
	}
	
	return mappings, nil
}

// GetMappings returns the current mappings
func (cr *ConfigReloader) GetMappings() map[string]string {
	if val := cr.mappings.Load(); val != nil {
		return val.(map[string]string)
	}
	return make(map[string]string)
}

// GetMapping returns the backend for a specific host
func (cr *ConfigReloader) GetMapping(host string) (string, bool) {
	mappings := cr.GetMappings()
	backend, ok := mappings[host]
	return backend, ok
}

// SetMapping updates a single mapping (runtime change, not persisted)
func (cr *ConfigReloader) SetMapping(host, backend string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	
	mappings := cr.GetMappings()
	newMappings := make(map[string]string)
	for k, v := range mappings {
		newMappings[k] = v
	}
	newMappings[host] = backend
	
	cr.mappings.Store(newMappings)
	logger.Info("Mapping updated", "host", host, "backend", backend)
}

// RemoveMapping removes a single mapping (runtime change, not persisted)
func (cr *ConfigReloader) RemoveMapping(host string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	
	mappings := cr.GetMappings()
	newMappings := make(map[string]string)
	for k, v := range mappings {
		if k != host {
			newMappings[k] = v
		}
	}
	
	cr.mappings.Store(newMappings)
	logger.Info("Mapping removed", "host", host)
}

// RegisterReloadHandler registers a handler to be called on configuration reload
func (cr *ConfigReloader) RegisterReloadHandler(handler ReloadHandler) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.handlers = append(cr.handlers, handler)
}

// GetProxy returns a reverse proxy for the given host
func (cr *ConfigReloader) GetProxy(host string) (*httputil.ReverseProxy, error) {
	cr.mu.RLock()
	
	// Check cache first
	if proxy, ok := cr.proxyCache[host]; ok {
		cr.mu.RUnlock()
		return proxy, nil
	}
	cr.mu.RUnlock()
	
	// Get backend URL
	backend, ok := cr.GetMapping(host)
	if !ok {
		return nil, fmt.Errorf("no mapping found for host: %s", host)
	}
	
	// Parse backend URL
	backendURL, err := url.Parse(backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL for %s: %w", host, err)
	}
	
	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	
	// Customize the director
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Add custom headers
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Real-IP", getClientIP(req))
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	
	// Cache the proxy
	cr.mu.Lock()
	cr.proxyCache[host] = proxy
	cr.mu.Unlock()
	
	return proxy, nil
}

// clearChangedProxies clears cached proxies for changed mappings
func (cr *ConfigReloader) clearChangedProxies(oldMappings, newMappings map[string]string) {
	for host, oldBackend := range oldMappings {
		newBackend, exists := newMappings[host]
		if !exists || oldBackend != newBackend {
			delete(cr.proxyCache, host)
		}
	}
	
	// Also clear proxies for removed hosts
	for host := range oldMappings {
		if _, exists := newMappings[host]; !exists {
			delete(cr.proxyCache, host)
		}
	}
}

// Persistence saves the current configuration to disk
func (cr *ConfigReloader) Persist() error {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	
	mappings := cr.GetMappings()
	
	// Determine file format based on extension
	ext := filepath.Ext(cr.configFile)
	
	var data []byte
	var err error
	
	switch ext {
	case ".yaml", ".yml":
		config := map[string]interface{}{
			"mappings": mappings,
		}
		data, err = yaml.Marshal(config)
	case ".json":
		config := map[string]interface{}{
			"mappings": mappings,
		}
		data, err = json.MarshalIndent(config, "", "  ")
	default:
		// Simple text format
		var lines []string
		for host, backend := range mappings {
			lines = append(lines, fmt.Sprintf("%s:%s", host, backend))
		}
		data = []byte(strings.Join(lines, "\n"))
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Write to file atomically
	tempFile := cr.configFile + ".tmp"
	if err := ioutil.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	
	if err := os.Rename(tempFile, cr.configFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	
	// Update last modified time to prevent reload
	if info, err := os.Stat(cr.configFile); err == nil {
		cr.lastModified = info.ModTime()
	}
	
	logger.Info("Configuration persisted", "file", cr.configFile, "mappings", len(mappings))
	return nil
}

// Helper functions

func countAdded(old, new map[string]string) int {
	count := 0
	for host := range new {
		if _, exists := old[host]; !exists {
			count++
		}
	}
	return count
}

func countRemoved(old, new map[string]string) int {
	count := 0
	for host := range old {
		if _, exists := new[host]; !exists {
			count++
		}
	}
	return count
}

func countModified(old, new map[string]string) int {
	count := 0
	for host, newBackend := range new {
		if oldBackend, exists := old[host]; exists && oldBackend != newBackend {
			count++
		}
	}
	return count
}

func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	host, _, _ := strings.Cut(req.RemoteAddr, ":")
	return host
}