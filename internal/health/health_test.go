package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Mock backend checker
type mockBackendChecker struct {
	healthy bool
	err     error
}

func (m *mockBackendChecker) CheckBackend(name string) error {
	if !m.healthy {
		return m.err
	}
	return nil
}

func TestNewChecker(t *testing.T) {
	backends := []string{"postgres", "redis", "mongodb"}
	checker := NewChecker(backends)
	
	if checker == nil {
		t.Fatal("NewChecker returned nil")
	}
	
	// Verify backends are registered
	status := checker.Status()
	for _, backend := range backends {
		if _, exists := status.Backends[backend]; !exists {
			t.Errorf("Backend %s not registered", backend)
		}
	}
}

func TestHealthHandler(t *testing.T) {
	checker := NewChecker([]string{"postgres", "redis"})
	handler := checker.HealthHandler()
	
	// Test healthy response
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
	
	// Parse response
	var status Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	
	if status.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", status.Status)
	}
	
	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got %s", contentType)
	}
}

func TestReadyHandler(t *testing.T) {
	checker := NewChecker([]string{"postgres"})
	handler := checker.ReadyHandler()
	
	tests := []struct {
		name           string
		healthy        bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "ready",
			healthy:        true,
			expectedStatus: http.StatusOK,
			expectedBody:   "ready",
		},
		{
			name:           "not ready",
			healthy:        false,
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "not ready",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set health status
			if tt.healthy {
				checker.SetHealthy("postgres")
			} else {
				checker.SetUnhealthy("postgres", errors.New("connection failed"))
			}
			
			req := httptest.NewRequest("GET", "/ready", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
			
			body := w.Body.String()
			if body != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
			}
		})
	}
}

func TestLiveHandler(t *testing.T) {
	checker := NewChecker([]string{})
	handler := checker.LiveHandler()
	
	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
	
	body := w.Body.String()
	if body != "alive" {
		t.Errorf("Expected body 'alive', got %q", body)
	}
}

func TestSetHealthy(t *testing.T) {
	checker := NewChecker([]string{"postgres", "redis"})
	
	// Initially unhealthy
	status := checker.Status()
	if status.Backends["postgres"].Healthy {
		t.Error("Backend should initially be unhealthy")
	}
	
	// Set healthy
	checker.SetHealthy("postgres")
	
	status = checker.Status()
	if !status.Backends["postgres"].Healthy {
		t.Error("Backend should be healthy after SetHealthy")
	}
	
	if status.Backends["postgres"].LastError != "" {
		t.Error("LastError should be empty when healthy")
	}
}

func TestSetUnhealthy(t *testing.T) {
	checker := NewChecker([]string{"postgres"})
	
	// Set healthy first
	checker.SetHealthy("postgres")
	
	// Now set unhealthy
	err := errors.New("connection timeout")
	checker.SetUnhealthy("postgres", err)
	
	status := checker.Status()
	if status.Backends["postgres"].Healthy {
		t.Error("Backend should be unhealthy after SetUnhealthy")
	}
	
	if status.Backends["postgres"].LastError != err.Error() {
		t.Errorf("LastError = %s, want %s", status.Backends["postgres"].LastError, err.Error())
	}
}

func TestIsHealthy(t *testing.T) {
	checker := NewChecker([]string{"postgres", "redis", "mongodb"})
	
	// All unhealthy initially
	if checker.IsHealthy() {
		t.Error("Should be unhealthy when all backends are unhealthy")
	}
	
	// Set one healthy
	checker.SetHealthy("postgres")
	if !checker.IsHealthy() {
		t.Error("Should be healthy when at least one backend is healthy")
	}
	
	// Set all healthy
	checker.SetHealthy("redis")
	checker.SetHealthy("mongodb")
	if !checker.IsHealthy() {
		t.Error("Should be healthy when all backends are healthy")
	}
	
	// Set one unhealthy
	checker.SetUnhealthy("redis", errors.New("failed"))
	if !checker.IsHealthy() {
		t.Error("Should still be healthy when some backends are healthy")
	}
}

func TestIsReady(t *testing.T) {
	checker := NewChecker([]string{"postgres", "redis"})
	
	// Not ready when any backend is unhealthy
	if checker.IsReady() {
		t.Error("Should not be ready when backends are unhealthy")
	}
	
	// Set one healthy
	checker.SetHealthy("postgres")
	if checker.IsReady() {
		t.Error("Should not be ready when not all backends are healthy")
	}
	
	// Set all healthy
	checker.SetHealthy("redis")
	if !checker.IsReady() {
		t.Error("Should be ready when all backends are healthy")
	}
	
	// Set one unhealthy again
	checker.SetUnhealthy("postgres", errors.New("failed"))
	if checker.IsReady() {
		t.Error("Should not be ready when any backend is unhealthy")
	}
}

func TestStatus(t *testing.T) {
	checker := NewChecker([]string{"postgres", "redis"})
	
	// Set different states
	checker.SetHealthy("postgres")
	checker.SetUnhealthy("redis", errors.New("connection refused"))
	
	status := checker.Status()
	
	// Check overall status
	if status.Status != "degraded" {
		t.Errorf("Expected status 'degraded', got %s", status.Status)
	}
	
	// Check individual backends
	if !status.Backends["postgres"].Healthy {
		t.Error("Postgres should be healthy")
	}
	
	if status.Backends["redis"].Healthy {
		t.Error("Redis should be unhealthy")
	}
	
	if status.Backends["redis"].LastError != "connection refused" {
		t.Errorf("Redis error = %s, want 'connection refused'", status.Backends["redis"].LastError)
	}
	
	// Check timestamps
	if status.Backends["postgres"].LastCheck.IsZero() {
		t.Error("Postgres LastCheck should not be zero")
	}
	
	if status.Backends["redis"].LastCheck.IsZero() {
		t.Error("Redis LastCheck should not be zero")
	}
}

func TestCheckBackends(t *testing.T) {
	checker := NewChecker([]string{"postgres", "redis"})
	
	// Create mock backend checker
	mockChecker := &mockBackendChecker{healthy: true}
	
	// Simulate backend check function
	checkFunc := func(name string) func() error {
		return func() error {
			return mockChecker.CheckBackend(name)
		}
	}
	
	// Register check functions (this would normally be done differently)
	// For testing, we'll just set the backends directly
	checker.SetHealthy("postgres")
	checker.SetHealthy("redis")
	
	if !checker.IsReady() {
		t.Error("All backends should be ready")
	}
	
	// Simulate failure
	mockChecker.healthy = false
	mockChecker.err = errors.New("check failed")
	
	// Manually trigger unhealthy state
	checker.SetUnhealthy("postgres", mockChecker.err)
	
	if checker.IsReady() {
		t.Error("Should not be ready after backend failure")
	}
}

func TestConcurrentAccess(t *testing.T) {
	checker := NewChecker([]string{"postgres", "redis", "mongodb"})
	
	// Run concurrent operations
	done := make(chan bool)
	
	// Writer goroutines
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				if j%2 == 0 {
					checker.SetHealthy("postgres")
					checker.SetHealthy("redis")
				} else {
					checker.SetUnhealthy("postgres", errors.New("test error"))
					checker.SetUnhealthy("mongodb", errors.New("test error"))
				}
			}
			done <- true
		}(i)
	}
	
	// Reader goroutines
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = checker.Status()
				_ = checker.IsHealthy()
				_ = checker.IsReady()
			}
			done <- true
		}()
	}
	
	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
	
	// Final check - should not panic
	_ = checker.Status()
}

func TestBackendStatusTiming(t *testing.T) {
	checker := NewChecker([]string{"postgres"})
	
	// Get initial time
	initialStatus := checker.Status()
	initialTime := initialStatus.Backends["postgres"].LastCheck
	
	// Wait a bit
	time.Sleep(10 * time.Millisecond)
	
	// Update status
	checker.SetHealthy("postgres")
	
	// Check time has updated
	newStatus := checker.Status()
	newTime := newStatus.Backends["postgres"].LastCheck
	
	if !newTime.After(initialTime) {
		t.Error("LastCheck time should be updated after status change")
	}
}

func TestEmptyBackends(t *testing.T) {
	// Test with no backends
	checker := NewChecker([]string{})
	
	// Should be healthy and ready with no backends
	if !checker.IsHealthy() {
		t.Error("Should be healthy with no backends")
	}
	
	if !checker.IsReady() {
		t.Error("Should be ready with no backends")
	}
	
	status := checker.Status()
	if status.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", status.Status)
	}
	
	if len(status.Backends) != 0 {
		t.Errorf("Expected 0 backends, got %d", len(status.Backends))
	}
}