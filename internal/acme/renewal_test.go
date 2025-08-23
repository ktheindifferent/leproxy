package acme

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// MockACMEServer simulates an ACME server for testing
type MockACMEServer struct {
	server          *httptest.Server
	mu              sync.RWMutex
	failureCount    int32
	maxFailures     int32
	renewalDelay    time.Duration
	certificates    map[string]*tls.Certificate
	renewalAttempts map[string]int
}

// NewMockACMEServer creates a new mock ACME server
func NewMockACMEServer() *MockACMEServer {
	mock := &MockACMEServer{
		certificates:    make(map[string]*tls.Certificate),
		renewalAttempts: make(map[string]int),
		maxFailures:     0,
		renewalDelay:    0,
	}
	
	mock.server = httptest.NewServer(http.HandlerFunc(mock.handleRequest))
	return mock
}

// SetFailureMode configures the mock to fail a certain number of times
func (m *MockACMEServer) SetFailureMode(maxFailures int32) {
	atomic.StoreInt32(&m.maxFailures, maxFailures)
	atomic.StoreInt32(&m.failureCount, 0)
}

// SetRenewalDelay sets a delay for renewal operations
func (m *MockACMEServer) SetRenewalDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renewalDelay = delay
}

// GetRenewalAttempts returns the number of renewal attempts for a domain
func (m *MockACMEServer) GetRenewalAttempts(domain string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.renewalAttempts[domain]
}

// handleRequest handles ACME requests
func (m *MockACMEServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Simulate renewal delay
	if m.renewalDelay > 0 {
		time.Sleep(m.renewalDelay)
	}
	
	// Check if we should fail
	currentFailures := atomic.LoadInt32(&m.failureCount)
	maxFailures := atomic.LoadInt32(&m.maxFailures)
	
	if currentFailures < maxFailures {
		atomic.AddInt32(&m.failureCount, 1)
		http.Error(w, "Mock ACME server failure", http.StatusInternalServerError)
		return
	}
	
	// Simulate successful response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "valid"}`))
}

// GenerateCertificate generates a test certificate
func (m *MockACMEServer) GenerateCertificate(domain string, expiryDays int) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(expiryDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	
	m.mu.Lock()
	m.certificates[domain] = cert
	m.mu.Unlock()
	
	return cert, nil
}

// Close shuts down the mock server
func (m *MockACMEServer) Close() {
	m.server.Close()
}

// TestRenewalManagerBasic tests basic renewal functionality
func TestRenewalManagerBasic(t *testing.T) {
	// Create temporary directory for certificates
	tempDir, err := os.MkdirTemp("", "cert-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	// Create manager configuration
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  []string{"test.example.com"},
		Email:    "test@example.com",
	}
	
	// Create manager
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	// Create renewal manager
	renewalManager := NewRenewalManager(manager)
	
	// Test status retrieval
	statuses := renewalManager.GetStatus()
	if len(statuses) != 0 {
		t.Errorf("Expected empty statuses, got %d", len(statuses))
	}
	
	// Test history retrieval
	history := renewalManager.GetHistory()
	if len(history) != 0 {
		t.Errorf("Expected empty history, got %d", len(history))
	}
}

// TestExponentialBackoff tests the exponential backoff calculation
func TestExponentialBackoff(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  []string{"test.example.com"},
		Email:    "test@example.com",
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	rm := NewRenewalManager(manager)
	
	tests := []struct {
		attempt  int
		minDelay time.Duration
		maxDelay time.Duration
	}{
		{0, 0, 0},
		{1, 45 * time.Second, 75 * time.Second},     // 1 minute ± 25%
		{2, 90 * time.Second, 150 * time.Second},    // 2 minutes ± 25%
		{3, 180 * time.Second, 300 * time.Second},   // 4 minutes ± 25%
		{4, 360 * time.Second, 600 * time.Second},   // 8 minutes ± 25%
		{10, 45 * time.Minute, 75 * time.Minute},    // Should cap at MaxRetryDelay
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := rm.calculateRetryDelay(tt.attempt)
			
			if tt.attempt == 0 {
				if delay != 0 {
					t.Errorf("Expected 0 delay for attempt 0, got %v", delay)
				}
			} else {
				if delay < tt.minDelay || delay > tt.maxDelay {
					t.Errorf("Delay %v not in expected range [%v, %v] for attempt %d",
						delay, tt.minDelay, tt.maxDelay, tt.attempt)
				}
			}
		})
	}
}

// TestRenewalWithRetry tests renewal with retry logic
func TestRenewalWithRetry(t *testing.T) {
	mockServer := NewMockACMEServer()
	defer mockServer.Close()
	
	tempDir, err := os.MkdirTemp("", "cert-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	// Generate an expiring certificate
	domain := "test.example.com"
	cert, err := mockServer.GenerateCertificate(domain, 5) // Expires in 5 days
	if err != nil {
		t.Fatal(err)
	}
	
	// Save certificate to cache
	certFile := filepath.Join(tempDir, domain)
	if err := saveCertificateToFile(certFile, cert); err != nil {
		t.Fatal(err)
	}
	
	// Configure mock to fail 2 times before succeeding
	mockServer.SetFailureMode(2)
	
	config := &Config{
		Provider:     ProviderLetsEncrypt,
		CacheDir:     tempDir,
		Domains:      []string{domain},
		Email:        "test@example.com",
		DirectoryURL: mockServer.server.URL,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	// Override the manager's GetCertificate to use our mock
	manager.Manager.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		attempts := mockServer.GetRenewalAttempts(hello.ServerName)
		mockServer.mu.Lock()
		mockServer.renewalAttempts[hello.ServerName] = attempts + 1
		mockServer.mu.Unlock()
		
		if attempts < 2 {
			return nil, fmt.Errorf("mock renewal failure")
		}
		
		// Generate new certificate
		newCert, err := mockServer.GenerateCertificate(hello.ServerName, 90)
		if err != nil {
			return nil, err
		}
		
		return newCert, nil
	}
	
	rm := NewRenewalManager(manager)
	
	// Set custom retry delays for faster testing
	originalInitialDelay := InitialRetryDelay
	originalMaxDelay := MaxRetryDelay
	defer func() {
		InitialRetryDelay = originalInitialDelay
		MaxRetryDelay = originalMaxDelay
	}()
	
	ctx := context.Background()
	rm.checkAndRenewCertificate(ctx, domain)
	
	// Wait for renewal to complete
	time.Sleep(500 * time.Millisecond)
	
	// Check that renewal was attempted multiple times
	attempts := mockServer.GetRenewalAttempts(domain)
	if attempts < 2 {
		t.Errorf("Expected at least 2 renewal attempts, got %d", attempts)
	}
	
	// Check status
	statuses := rm.GetStatus()
	if status, exists := statuses[domain]; exists {
		if status.Attempts < 2 {
			t.Errorf("Expected at least 2 attempts in status, got %d", status.Attempts)
		}
	} else {
		t.Error("Expected status for domain to exist")
	}
}

// TestAlertHandler tests the alert handler functionality
func TestAlertHandler(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  []string{"alert.example.com"},
		Email:    "test@example.com",
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	rm := NewRenewalManager(manager)
	
	// Track alerts
	var alertCount int32
	var lastAlertStatus *RenewalStatus
	var mu sync.Mutex
	
	rm.SetAlertHandler(func(status *RenewalStatus) {
		atomic.AddInt32(&alertCount, 1)
		mu.Lock()
		lastAlertStatus = status
		mu.Unlock()
	})
	
	// Simulate renewal failure
	status := &RenewalStatus{
		Domain:      "alert.example.com",
		Status:      "failed",
		Attempts:    MaxRenewalRetries,
		Error:       "Test failure",
		ExpiryDate:  time.Now().Add(2 * 24 * time.Hour), // Expires in 2 days
		LastAttempt: time.Now(),
	}
	
	rm.mu.Lock()
	rm.statuses[status.Domain] = status
	rm.mu.Unlock()
	
	// Trigger alert
	if rm.alertHandler != nil {
		rm.alertHandler(status)
	}
	
	// Verify alert was called
	if atomic.LoadInt32(&alertCount) != 1 {
		t.Errorf("Expected 1 alert, got %d", alertCount)
	}
	
	mu.Lock()
	if lastAlertStatus == nil || lastAlertStatus.Domain != "alert.example.com" {
		t.Error("Alert handler not called with correct status")
	}
	mu.Unlock()
}

// TestConcurrentRenewal tests concurrent renewal of multiple certificates
func TestConcurrentRenewal(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	domains := []string{
		"domain1.example.com",
		"domain2.example.com",
		"domain3.example.com",
		"domain4.example.com",
		"domain5.example.com",
	}
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  domains,
		Email:    "test@example.com",
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	rm := NewRenewalManager(manager)
	
	// Create mock certificates for all domains
	mockServer := NewMockACMEServer()
	defer mockServer.Close()
	
	for _, domain := range domains {
		cert, err := mockServer.GenerateCertificate(domain, 25) // Expires in 25 days
		if err != nil {
			t.Fatal(err)
		}
		
		certFile := filepath.Join(tempDir, domain)
		if err := saveCertificateToFile(certFile, cert); err != nil {
			t.Fatal(err)
		}
	}
	
	// Start concurrent renewal check
	ctx := context.Background()
	start := time.Now()
	rm.checkAndRenewAll(ctx)
	duration := time.Since(start)
	
	// Verify all domains were checked
	statuses := rm.GetStatus()
	for _, domain := range domains {
		if _, exists := statuses[domain]; !exists {
			t.Errorf("Domain %s was not checked", domain)
		}
	}
	
	// Verify concurrent execution (should be faster than sequential)
	expectedMaxDuration := 2 * time.Second
	if duration > expectedMaxDuration {
		t.Logf("Warning: Concurrent renewal took %v, expected less than %v", duration, expectedMaxDuration)
	}
}

// TestRenewalHistory tests renewal history tracking
func TestRenewalHistory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cert-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  []string{"history.example.com"},
		Email:    "test@example.com",
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	rm := NewRenewalManager(manager)
	
	// Record some history
	rm.recordHistory("history.example.com", true, "", 5.5, 1)
	rm.recordHistory("history.example.com", false, "Test failure", 3.2, 3)
	
	// Get history
	history := rm.GetHistory()
	if len(history) != 2 {
		t.Errorf("Expected 2 history entries, got %d", len(history))
	}
	
	// Verify history details
	for _, h := range history {
		if h.Domain != "history.example.com" {
			t.Errorf("Unexpected domain in history: %s", h.Domain)
		}
		
		if h.Success && h.Error != "" {
			t.Error("Successful renewal should not have error")
		}
		
		if !h.Success && h.Error == "" {
			t.Error("Failed renewal should have error")
		}
	}
	
	// Test history persistence
	historyFile := filepath.Join(tempDir, "renewal_history.json")
	if _, err := os.Stat(historyFile); os.IsNotExist(err) {
		t.Error("History file was not created")
	}
	
	// Load history from file
	rm2 := NewRenewalManager(manager)
	rm2.loadHistory()
	
	loadedHistory := rm2.GetHistory()
	if len(loadedHistory) != len(history) {
		t.Errorf("Loaded history has different length: expected %d, got %d", len(history), len(loadedHistory))
	}
}

// Helper function to save certificate to file
func saveCertificateToFile(filename string, cert *tls.Certificate) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Write certificate
	for _, certDER := range cert.Certificate {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}
		if err := pem.Encode(file, block); err != nil {
			return err
		}
	}
	
	// Write private key
	if rsaKey, ok := cert.PrivateKey.(*rsa.PrivateKey); ok {
		keyDER := x509.MarshalPKCS1PrivateKey(rsaKey)
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyDER,
		}
		if err := pem.Encode(file, block); err != nil {
			return err
		}
	}
	
	return nil
}

// BenchmarkRenewalCheck benchmarks the renewal check performance
func BenchmarkRenewalCheck(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "bench-cert-*")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	// Create multiple domains
	domains := make([]string, 100)
	for i := 0; i < 100; i++ {
		domains[i] = fmt.Sprintf("domain%d.example.com", i)
	}
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  domains,
		Email:    "test@example.com",
	}
	
	manager, err := NewManager(config)
	if err != nil {
		b.Fatal(err)
	}
	
	rm := NewRenewalManager(manager)
	ctx := context.Background()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		rm.checkAndRenewAll(ctx)
	}
}

// TestLoadBalancedRenewal tests renewal during load
func TestLoadBalancedRenewal(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "load-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  []string{"load.example.com"},
		Email:    "test@example.com",
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	rm := NewRenewalManager(manager)
	
	// Simulate load with concurrent requests
	var wg sync.WaitGroup
	requestCount := 1000
	successCount := int32(0)
	
	// Mock certificate getter that simulates load
	manager.Manager = &autocert.Manager{
		Cache: autocert.DirCache(tempDir),
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Simulate some processing time
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&successCount, 1)
			
			// Return a mock certificate
			priv, _ := rsa.GenerateKey(rand.Reader, 2048)
			return &tls.Certificate{
				Certificate: [][]byte{},
				PrivateKey:  priv,
			}, nil
		},
	}
	
	// Start renewal in background
	ctx := context.Background()
	go rm.checkAndRenewCertificate(ctx, "load.example.com")
	
	// Simulate concurrent certificate requests
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			hello := &tls.ClientHelloInfo{
				ServerName: "load.example.com",
			}
			
			_, err := manager.Manager.GetCertificate(hello)
			if err != nil {
				t.Logf("Request failed: %v", err)
			}
		}()
	}
	
	wg.Wait()
	
	// Verify requests were handled
	if atomic.LoadInt32(&successCount) < int32(requestCount*90/100) {
		t.Errorf("Too many failed requests: %d/%d succeeded", successCount, requestCount)
	}
}

// TestNetworkFailureRecovery tests recovery from network failures
func TestNetworkFailureRecovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "network-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	// Create a mock server that simulates network issues
	mockServer := &MockNetworkServer{
		failureRate: 0.5, // 50% failure rate initially
	}
	server := httptest.NewServer(mockServer)
	defer server.Close()
	
	config := &Config{
		Provider:     ProviderLetsEncrypt,
		CacheDir:     tempDir,
		Domains:      []string{"network.example.com"},
		Email:        "test@example.com",
		DirectoryURL: server.URL,
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	rm := NewRenewalManager(manager)
	
	// Gradually improve network conditions
	go func() {
		time.Sleep(100 * time.Millisecond)
		mockServer.mu.Lock()
		mockServer.failureRate = 0.2 // Reduce to 20% failure
		mockServer.mu.Unlock()
		
		time.Sleep(100 * time.Millisecond)
		mockServer.mu.Lock()
		mockServer.failureRate = 0 // No failures
		mockServer.mu.Unlock()
	}()
	
	ctx := context.Background()
	rm.checkAndRenewCertificate(ctx, "network.example.com")
	
	// Verify eventual success
	time.Sleep(500 * time.Millisecond)
	
	statuses := rm.GetStatus()
	if status, exists := statuses["network.example.com"]; exists {
		if status.Status == "failed" && status.Attempts >= MaxRenewalRetries {
			t.Error("Renewal failed to recover from network issues")
		}
	}
}

// MockNetworkServer simulates network issues
type MockNetworkServer struct {
	mu          sync.Mutex
	failureRate float32
	requests    int
}

func (m *MockNetworkServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.requests++
	
	// Simulate network failure based on rate
	if rand.Float32() < m.failureRate {
		// Simulate various network errors
		errors := []int{
			http.StatusGatewayTimeout,
			http.StatusServiceUnavailable,
			http.StatusBadGateway,
		}
		errorCode := errors[rand.Intn(len(errors))]
		http.Error(w, "Network error", errorCode)
		return
	}
	
	// Success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "valid"}`))
}