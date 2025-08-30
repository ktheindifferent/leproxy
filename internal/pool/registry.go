package pool

import (
	"context"
	"fmt"
	"sync"
	"time"
	
	"github.com/artyom/leproxy/internal/logger"
)

// Registry tracks all active connection pools
type Registry struct {
	mu    sync.RWMutex
	pools map[string]*Pool
}

var (
	// globalRegistry is the default pool registry
	globalRegistry = &Registry{
		pools: make(map[string]*Pool),
	}
)

// GlobalRegistry returns the global pool registry
func GlobalRegistry() *Registry {
	return globalRegistry
}

// Register adds a pool to the registry
func (r *Registry) Register(name string, pool *Pool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.pools[name] = pool
	logger.Info("Pool registered", map[string]interface{}{
		"name": name,
		"max_conns": pool.maxConns,
	})
}

// Unregister removes a pool from the registry
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	delete(r.pools, name)
	logger.Info("Pool unregistered", map[string]interface{}{
		"name": name,
	})
}

// Get returns a pool by name
func (r *Registry) Get(name string) (*Pool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	pool, ok := r.pools[name]
	return pool, ok
}

// GetAll returns all registered pools
func (r *Registry) GetAll() map[string]*Pool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	result := make(map[string]*Pool)
	for name, pool := range r.pools {
		result[name] = pool
	}
	return result
}

// ShutdownAll gracefully shuts down all registered pools
func (r *Registry) ShutdownAll(ctx context.Context) error {
	r.mu.Lock()
	pools := make(map[string]*Pool)
	for name, pool := range r.pools {
		pools[name] = pool
	}
	r.mu.Unlock()
	
	logger.Info("Shutting down all connection pools", map[string]interface{}{
		"count": len(pools),
	})
	
	var wg sync.WaitGroup
	errChan := make(chan error, len(pools))
	
	for name, pool := range pools {
		wg.Add(1)
		go func(poolName string, p *Pool) {
			defer wg.Done()
			
			// First, drain the pool to prevent new connections
			p.Drain()
			
			// Wait a bit for active connections to complete
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
			}
			
			// Now close the pool
			if err := p.Close(); err != nil {
				errChan <- fmt.Errorf("failed to close pool %s: %w", poolName, err)
			} else {
				logger.Info("Pool closed successfully", map[string]interface{}{
					"name": poolName,
				})
			}
			
			// Unregister the pool
			r.Unregister(poolName)
		}(name, pool)
	}
	
	// Wait for all pools to close
	wg.Wait()
	close(errChan)
	
	// Collect any errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to close %d pools: %v", len(errors), errors)
	}
	
	logger.Info("All connection pools shut down successfully")
	return nil
}

// GetStats returns statistics for all pools
func (r *Registry) GetStats() map[string]PoolStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	stats := make(map[string]PoolStats)
	for name, pool := range r.pools {
		stats[name] = pool.GetStats()
	}
	return stats
}

// Register adds a pool to the global registry
func Register(name string, pool *Pool) {
	globalRegistry.Register(name, pool)
}

// Unregister removes a pool from the global registry
func Unregister(name string) {
	globalRegistry.Unregister(name)
}

// ShutdownAll shuts down all pools in the global registry
func ShutdownAll(ctx context.Context) error {
	return globalRegistry.ShutdownAll(ctx)
}