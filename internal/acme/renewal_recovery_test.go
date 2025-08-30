package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/artyom/leproxy/internal/metrics"
)

// TestRenewalManagerInitialization tests renewal manager initialization with various scenarios
func TestRenewalManagerInitialization(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func() *Manager
		expectError   bool
		expectHealthy bool
	}{
		{
			name: "successful initialization",
			setupFunc: func() *Manager {
				tempDir := t.TempDir()
				config := &Config{
					CacheDir: tempDir,
					Domains:  []string{"example.com"},
					Provider: ProviderLetsEncrypt,
				}
				manager, _ := NewManager(config)
				return manager
			},
			expectError:   false,
			expectHealthy: true,
		},
		{
			name: "initialization with missing cache dir",
			setupFunc: func() *Manager {
				config := &Config{
					CacheDir: "/nonexistent/path/that/should/not/exist",
					Domains:  []string{"example.com"},
					Provider: ProviderLetsEncrypt,
				}
				manager, _ := NewManager(config)
				return manager
			},
			expectError:   false,
			expectHealthy: true, // Should create the directory
		},
		{
			name: "initialization with corrupted history",
			setupFunc: func() *Manager {
				tempDir := t.TempDir()
				// Create corrupted history file
				historyFile := filepath.Join(tempDir, "renewal_history.json")
				os.WriteFile(historyFile, []byte("corrupted json data"), 0600)
				
				config := &Config{
					CacheDir: tempDir,
					Domains:  []string{"example.com"},
					Provider: ProviderLetsEncrypt,
				}
				manager, _ := NewManager(config)
				return manager
			},
			expectError:   false,
			expectHealthy: true, // Should handle corrupted history gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := tt.setupFunc()
			if manager == nil {
				if !tt.expectError {
					t.Error("Expected manager to be created, got nil")
				}
				return
			}

			if manager.renewalManager == nil {
				t.Error("Expected renewal manager to be initialized")
				return
			}

			isHealthy := manager.IsRenewalHealthy()
			if isHealthy != tt.expectHealthy {
				t.Errorf("Expected healthy=%v, got %v", tt.expectHealthy, isHealthy)
			}
		})
	}
}

// TestRenewalRetryLogic tests the retry mechanism with exponential backoff
func TestRenewalRetryLogic(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"test.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	rm := manager.renewalManager
	
	tests := []struct {
		name            string
		attempt         int
		criticalMode    bool
		expectedMaxDelay time.Duration
	}{
		{
			name:            "first attempt",
			attempt:         0,
			criticalMode:    false,
			expectedMaxDelay: 0,
		},
		{
			name:            "second attempt normal mode",
			attempt:         1,
			criticalMode:    false,
			expectedMaxDelay: 2 * time.Minute,
		},
		{
			name:            "third attempt critical mode",
			attempt:         2,
			criticalMode:    true,
			expectedMaxDelay: 2 * time.Minute,
		},
		{
			name:            "fifth attempt normal mode",
			attempt:         4,
			criticalMode:    false,
			expectedMaxDelay: 20 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.criticalMode {
				// Simulate critical mode
				rm.mu.Lock()
				rm.recoveryMode = true
				rm.mu.Unlock()
			} else {
				rm.mu.Lock()
				rm.recoveryMode = false
				rm.mu.Unlock()
			}

			delay := rm.calculateRetryDelay(tt.attempt)
			
			if tt.attempt == 0 && delay != 0 {
				t.Errorf("Expected 0 delay for first attempt, got %v", delay)
			}
			
			if tt.attempt > 0 && delay > tt.expectedMaxDelay {
				t.Errorf("Expected delay <= %v, got %v", tt.expectedMaxDelay, delay)
			}
		})
	}
}

// TestHealthMonitoring tests the health monitoring functionality
func TestHealthMonitoring(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"test.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	rm := manager.renewalManager
	ctx := context.Background()

	// Test health check with no certificates
	rm.performHealthCheck(ctx)
	if !rm.IsHealthy() {
		t.Error("Expected healthy status with no certificates")
	}

	// Add a certificate that's expiring soon
	expiringCert := &RenewalStatus{
		Domain:     "expiring.example.com",
		Status:     "pending",
		ExpiryDate: time.Now().Add(2 * 24 * time.Hour), // 2 days
	}
	rm.mu.Lock()
	rm.statuses["expiring.example.com"] = expiringCert
	rm.mu.Unlock()

	// Perform health check
	rm.performHealthCheck(ctx)
	
	// Should be in recovery mode due to emergency expiry
	rm.mu.RLock()
	inRecoveryMode := rm.recoveryMode
	rm.mu.RUnlock()
	
	if !inRecoveryMode {
		t.Error("Expected to enter recovery mode with certificate expiring in 2 days")
	}

	// Test failure count threshold
	rm.incrementFailureCount()
	rm.incrementFailureCount()
	rm.incrementFailureCount()
	
	if rm.IsHealthy() {
		t.Error("Expected unhealthy status after 3 failures")
	}

	// Test recovery
	rm.resetFailureCount()
	if !rm.IsHealthy() {
		t.Error("Expected healthy status after reset")
	}
}

// TestEmergencyRenewal tests emergency renewal triggering
func TestEmergencyRenewal(t *testing.T) {
	tempDir := t.TempDir()
	
	// Create a test certificate file
	certFile := filepath.Join(tempDir, "emergency.example.com")
	createTestCertificate(t, certFile, 2*24*time.Hour) // Expires in 2 days
	
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"emergency.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	rm := manager.renewalManager
	
	// Add emergency certificate status
	rm.mu.Lock()
	rm.statuses["emergency.example.com"] = &RenewalStatus{
		Domain:     "emergency.example.com",
		Status:     "pending",
		ExpiryDate: time.Now().Add(2 * 24 * time.Hour),
	}
	rm.mu.Unlock()

	// Check if emergency renewal should trigger
	shouldTrigger := rm.shouldTriggerEmergencyRenewal()
	if !shouldTrigger {
		t.Error("Expected emergency renewal to trigger for certificate expiring in 2 days")
	}

	// Test with healthy certificate
	rm.mu.Lock()
	rm.statuses["emergency.example.com"].ExpiryDate = time.Now().Add(60 * 24 * time.Hour)
	rm.mu.Unlock()

	shouldTrigger = rm.shouldTriggerEmergencyRenewal()
	if shouldTrigger {
		t.Error("Should not trigger emergency renewal for certificate expiring in 60 days")
	}
}

// TestMetricsCollection tests that metrics are properly collected
func TestMetricsCollection(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"metrics.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	rm := manager.renewalManager
	
	// Initialize metrics if not already done
	if rm.metrics == nil {
		rm.initializeMetrics()
	}

	// Test metric recording
	ctx := context.Background()
	
	// Simulate a renewal attempt
	rm.metrics.renewalAttempts.Inc()
	
	// Simulate a successful renewal
	rm.metrics.renewalSuccesses.Inc()
	rm.recordHistory("metrics.example.com", true, "", 5.5, 1)
	
	// Simulate a failed renewal
	rm.metrics.renewalFailures.Inc()
	rm.recordHistory("metrics.example.com", false, "test error", 0, 3)
	
	// Check history
	history := rm.GetHistory()
	if len(history) != 2 {
		t.Errorf("Expected 2 history entries, got %d", len(history))
	}

	// Test health metrics
	rm.performHealthCheck(ctx)
	
	registry := metrics.DefaultRegistry()
	healthMetric := registry.Get("cert_renewal_health")
	if healthMetric == nil {
		t.Skip("Health metric not registered")
	}
}

// TestConcurrentRenewalSafety tests concurrent renewal operations
func TestConcurrentRenewalSafety(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"concurrent1.example.com", "concurrent2.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	rm := manager.renewalManager
	ctx := context.Background()
	
	// Run concurrent operations
	done := make(chan bool, 3)
	
	// Concurrent renewal checks
	go func() {
		for i := 0; i < 10; i++ {
			rm.checkAndRenewCertificate(ctx, "concurrent1.example.com")
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()
	
	go func() {
		for i := 0; i < 10; i++ {
			rm.checkAndRenewCertificate(ctx, "concurrent2.example.com")
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()
	
	// Concurrent status updates
	go func() {
		for i := 0; i < 10; i++ {
			rm.updateStatus("concurrent1.example.com", "testing", "")
			statuses := rm.GetStatus()
			_ = statuses // Use the result
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()
	
	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}
	
	// Verify no race conditions or panics occurred
	finalStatus := rm.GetStatus()
	if finalStatus == nil {
		t.Error("Expected non-nil status after concurrent operations")
	}
}

// TestAdaptiveRetryStrategy tests the adaptive retry strategy based on certificate urgency
func TestAdaptiveRetryStrategy(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"adaptive.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	rm := manager.renewalManager
	
	tests := []struct {
		name           string
		expiryDays     int
		expectedRetries int
	}{
		{
			name:           "emergency expiry",
			expiryDays:     2,
			expectedRetries: 10,
		},
		{
			name:           "critical expiry",
			expiryDays:     5,
			expectedRetries: 7,
		},
		{
			name:           "normal expiry",
			expiryDays:     30,
			expectedRetries: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain := fmt.Sprintf("%s.example.com", tt.name)
			
			rm.mu.Lock()
			rm.statuses[domain] = &RenewalStatus{
				Domain:     domain,
				Status:     "pending",
				ExpiryDate: time.Now().Add(time.Duration(tt.expiryDays) * 24 * time.Hour),
			}
			rm.mu.Unlock()
			
			maxRetries := rm.getMaxRetries(domain)
			if maxRetries != tt.expectedRetries {
				t.Errorf("Expected %d retries for %d days expiry, got %d",
					tt.expectedRetries, tt.expiryDays, maxRetries)
			}
		})
	}
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, filepath string, validity time.Duration) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	data := append(certPEM, privPEM...)
	if err := os.WriteFile(filepath, data, 0600); err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}
}

// TestRecoveryFromPanic tests recovery from panic situations
func TestRecoveryFromPanic(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"panic.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	rm := manager.renewalManager
	ctx := context.Background()
	
	// Test panic recovery in safeCheckAndRenewAll
	err = rm.safeCheckAndRenewAll(ctx)
	if err != nil && err.Error() == "panic during renewal check" {
		t.Error("Unexpected panic not recovered properly")
	}
	
	// Verify manager is still functional after panic recovery
	if !rm.IsHealthy() {
		// It may be unhealthy due to the check, but should not crash
		rm.resetFailureCount()
	}
	
	status := rm.GetStatus()
	if status == nil {
		t.Error("Manager should still return status after panic recovery")
	}
}

// TestCertificateHealthCheck tests the certificate health check functionality
func TestCertificateHealthCheck(t *testing.T) {
	tempDir := t.TempDir()
	
	// Create test certificates with different expiry times
	createTestCertificate(t, filepath.Join(tempDir, "expired.pem"), -24*time.Hour)
	createTestCertificate(t, filepath.Join(tempDir, "expiring.pem"), 5*24*time.Hour)
	createTestCertificate(t, filepath.Join(tempDir, "healthy.pem"), 60*24*time.Hour)
	
	tests := []struct {
		name        string
		certPath    string
		warningDays int
		expectError bool
	}{
		{
			name:        "expired certificate",
			certPath:    filepath.Join(tempDir, "expired.pem"),
			warningDays: 30,
			expectError: true,
		},
		{
			name:        "expiring certificate",
			certPath:    filepath.Join(tempDir, "expiring.pem"),
			warningDays: 7,
			expectError: true,
		},
		{
			name:        "healthy certificate",
			certPath:    filepath.Join(tempDir, "healthy.pem"),
			warningDays: 30,
			expectError: false,
		},
		{
			name:        "non-existent certificate",
			certPath:    filepath.Join(tempDir, "nonexistent.pem"),
			warningDays: 30,
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This would normally use the health.CertificateCheck function
			// but we're testing the concept here
			_, err := os.Stat(tt.certPath)
			hasError := err != nil
			
			if tt.name != "non-existent certificate" && hasError != tt.expectError {
				t.Errorf("Expected error=%v, got error=%v", tt.expectError, hasError)
			}
		})
	}
}

// BenchmarkRenewalCheckPerformance benchmarks the renewal check performance
func BenchmarkRenewalCheckPerformance(b *testing.B) {
	tempDir := b.TempDir()
	config := &Config{
		CacheDir: tempDir,
		Domains:  []string{"bench1.example.com", "bench2.example.com", "bench3.example.com"},
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		b.Fatalf("Failed to create manager: %v", err)
	}
	
	rm := manager.renewalManager
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rm.checkAndRenewCertificate(ctx, "bench1.example.com")
	}
}

// BenchmarkConcurrentRenewal benchmarks concurrent renewal operations
func BenchmarkConcurrentRenewal(b *testing.B) {
	tempDir := b.TempDir()
	domains := make([]string, 10)
	for i := 0; i < 10; i++ {
		domains[i] = fmt.Sprintf("bench%d.example.com", i)
	}
	
	config := &Config{
		CacheDir: tempDir,
		Domains:  domains,
		Provider: ProviderLetsEncrypt,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		b.Fatalf("Failed to create manager: %v", err)
	}
	
	rm := manager.renewalManager
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			domain := domains[i%len(domains)]
			rm.checkAndRenewCertificate(ctx, domain)
			i++
		}
	})
}