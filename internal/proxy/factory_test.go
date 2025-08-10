package proxy

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	if factory == nil {
		t.Fatal("NewFactory returned nil")
	}
	
	if factory.registry == nil {
		t.Fatal("Factory registry not initialized")
	}
	
	// Check that default proxies are registered
	types := factory.GetSupportedTypes()
	if len(types) == 0 {
		t.Error("No proxy types registered")
	}
}

func TestFactoryRegister(t *testing.T) {
	factory := NewFactory()
	
	// Register a custom proxy type
	customType := Type("custom")
	registered := false
	
	factory.Register(customType, func(config *Config) (Proxy, error) {
		registered = true
		return &mockProxy{config: config}, nil
	})
	
	// Try to create the custom proxy
	config := &Config{
		Type:       customType,
		ListenAddr: ":9999",
		Backend:    "localhost:9998",
	}
	
	proxy, err := factory.Create(config)
	if err != nil {
		t.Errorf("Failed to create custom proxy: %v", err)
	}
	
	if !registered {
		t.Error("Custom proxy creator was not called")
	}
	
	if proxy == nil {
		t.Error("Created proxy is nil")
	}
}

func TestFactoryCreateUnknownType(t *testing.T) {
	factory := NewFactory()
	
	config := &Config{
		Type: Type("unknown"),
	}
	
	_, err := factory.Create(config)
	if err == nil {
		t.Error("Expected error for unknown proxy type")
	}
}

func TestFactoryGetSupportedTypes(t *testing.T) {
	factory := NewFactory()
	types := factory.GetSupportedTypes()
	
	expectedTypes := map[Type]bool{
		TypeMySQL:    true,
		TypePostgres: true,
		TypeMongoDB:  true,
		TypeRedis:    true,
	}
	
	for _, typ := range types {
		if !expectedTypes[typ] {
			t.Logf("Found registered type: %s", typ)
		}
	}
	
	// Check minimum expected types
	if len(types) < 4 {
		t.Errorf("Expected at least 4 proxy types, got %d", len(types))
	}
}

func TestProxyManager(t *testing.T) {
	factory := NewFactory()
	manager := NewManager(factory)
	
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}
	
	if manager.factory != factory {
		t.Error("Manager factory mismatch")
	}
	
	if manager.proxies == nil {
		t.Error("Manager proxies map not initialized")
	}
}

func TestProxyManagerStartStop(t *testing.T) {
	factory := NewFactory()
	
	// Register a mock proxy type
	factory.Register(Type("mock"), func(config *Config) (Proxy, error) {
		return &mockProxy{config: config}, nil
	})
	
	manager := NewManager(factory)
	
	config := &Config{
		Type:       Type("mock"),
		ListenAddr: ":19999",
		Backend:    "localhost:19998",
	}
	
	// Start proxy
	err := manager.StartProxy(config)
	if err != nil {
		t.Errorf("Failed to start proxy: %v", err)
	}
	
	// Check status
	status := manager.GetStatus()
	if len(status) != 1 {
		t.Errorf("Expected 1 proxy, got %d", len(status))
	}
	
	// Stop proxy
	err = manager.StopProxy(config.ListenAddr)
	if err != nil {
		t.Errorf("Failed to stop proxy: %v", err)
	}
	
	// Check status after stop
	status = manager.GetStatus()
	if len(status) != 0 {
		t.Errorf("Expected 0 proxies after stop, got %d", len(status))
	}
}

func TestProxyManagerStopAll(t *testing.T) {
	factory := NewFactory()
	
	// Register a mock proxy type
	factory.Register(Type("mock"), func(config *Config) (Proxy, error) {
		return &mockProxy{config: config}, nil
	})
	
	manager := NewManager(factory)
	
	// Start multiple proxies
	for i := 0; i < 3; i++ {
		config := &Config{
			Type:       Type("mock"),
			ListenAddr: fmt.Sprintf(":%d", 20000+i),
			Backend:    "localhost:19998",
		}
		manager.StartProxy(config)
	}
	
	// Check that all are running
	status := manager.GetStatus()
	if len(status) != 3 {
		t.Errorf("Expected 3 proxies, got %d", len(status))
	}
	
	// Stop all
	manager.StopAll()
	
	// Check that all are stopped
	status = manager.GetStatus()
	if len(status) != 0 {
		t.Errorf("Expected 0 proxies after StopAll, got %d", len(status))
	}
}

func TestParseProxyType(t *testing.T) {
	tests := []struct {
		input    string
		expected Type
		wantErr  bool
	}{
		{"mysql", TypeMySQL, false},
		{"MySQL", TypeMySQL, false},
		{"postgres", TypePostgres, false},
		{"postgresql", TypePostgres, false},
		{"mongodb", TypeMongoDB, false},
		{"mongo", TypeMongoDB, false},
		{"redis", TypeRedis, false},
		{"unknown", "", true},
		{"", "", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseProxyType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Got %s, expected %s", result, tt.expected)
				}
			}
		})
	}
}

func TestConcurrentProxyOperations(t *testing.T) {
	factory := NewFactory()
	
	// Register a mock proxy type
	factory.Register(Type("mock"), func(config *Config) (Proxy, error) {
		return &mockProxy{config: config}, nil
	})
	
	manager := NewManager(factory)
	
	var wg sync.WaitGroup
	
	// Start 10 proxies concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			config := &Config{
				Type:       Type("mock"),
				ListenAddr: fmt.Sprintf(":%d", 30000+port),
				Backend:    "localhost:19998",
			}
			manager.StartProxy(config)
		}(i)
	}
	
	wg.Wait()
	
	// Check that all started
	status := manager.GetStatus()
	if len(status) != 10 {
		t.Errorf("Expected 10 proxies, got %d", len(status))
	}
	
	// Stop all concurrently
	for addr := range status {
		wg.Add(1)
		go func(address string) {
			defer wg.Done()
			manager.StopProxy(address)
		}(addr)
	}
	
	wg.Wait()
	
	// Check that all stopped
	status = manager.GetStatus()
	if len(status) != 0 {
		t.Errorf("Expected 0 proxies after concurrent stop, got %d", len(status))
	}
}

// Mock proxy for testing
type mockProxy struct {
	config  *Config
	started bool
	stopped bool
	mu      sync.Mutex
}

func (p *mockProxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = true
	return nil
}

func (p *mockProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	return nil
}

func (p *mockProxy) GetType() Type {
	return p.config.Type
}

func (p *mockProxy) GetListenAddr() string {
	return p.config.ListenAddr
}

func BenchmarkFactoryCreate(b *testing.B) {
	factory := NewFactory()
	
	config := &Config{
		Type:       TypeMySQL,
		ListenAddr: ":3306",
		Backend:    "localhost:3307",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		factory.Create(config)
	}
}

func BenchmarkProxyManagerOperations(b *testing.B) {
	factory := NewFactory()
	factory.Register(Type("bench"), func(config *Config) (Proxy, error) {
		return &mockProxy{config: config}, nil
	})
	
	manager := NewManager(factory)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := &Config{
			Type:       Type("bench"),
			ListenAddr: fmt.Sprintf(":%d", 40000+(i%100)),
			Backend:    "localhost:19998",
		}
		
		manager.StartProxy(config)
		manager.GetStatus()
		manager.StopProxy(config.ListenAddr)
	}
}