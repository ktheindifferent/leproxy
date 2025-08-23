//go:build integration
// +build integration

package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCertificateRotationWithoutDowntime tests certificate rotation without service interruption
func TestCertificateRotationWithoutDowntime(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	tempDir, err := os.MkdirTemp("", "rotation-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	// Use staging environment for testing
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  []string{"test.leproxy.local"},
		Email:    os.Getenv("ACME_TEST_EMAIL"),
		TestMode: true, // Use staging
	}
	
	if config.Email == "" {
		t.Skip("ACME_TEST_EMAIL environment variable not set")
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	// Start renewal manager
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	manager.StartRenewalManager(ctx)
	defer manager.StopRenewalManager()
	
	// Track successful requests
	var requestCount int32
	var errorCount int32
	
	// Start a test server using the manager's TLS config
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: manager.GetTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}),
	}
	
	// Start server in background
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Shutdown(context.Background())
	
	// Wait for server to start
	time.Sleep(2 * time.Second)
	
	// Create client with custom transport
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing
			},
		},
		Timeout: 5 * time.Second,
	}
	
	// Continuously make requests during renewal
	stopRequests := make(chan struct{})
	var wg sync.WaitGroup
	
	// Start multiple concurrent clients
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			
			for {
				select {
				case <-stopRequests:
					return
				case <-ticker.C:
					resp, err := client.Get("https://test.leproxy.local:8443/")
					if err != nil {
						atomic.AddInt32(&errorCount, 1)
						t.Logf("Client %d request failed: %v", clientID, err)
						continue
					}
					resp.Body.Close()
					
					if resp.StatusCode != http.StatusOK {
						atomic.AddInt32(&errorCount, 1)
						t.Logf("Client %d got status %d", clientID, resp.StatusCode)
					}
				}
			}
		}(i)
	}
	
	// Trigger certificate renewal
	t.Log("Triggering certificate renewal...")
	if err := manager.RenewCertificates(ctx); err != nil {
		t.Logf("Renewal error (expected in test): %v", err)
	}
	
	// Let requests run for a while during renewal
	time.Sleep(10 * time.Second)
	
	// Stop requests
	close(stopRequests)
	wg.Wait()
	
	// Check results
	totalRequests := atomic.LoadInt32(&requestCount)
	totalErrors := atomic.LoadInt32(&errorCount)
	
	t.Logf("Total requests: %d, Errors: %d", totalRequests, totalErrors)
	
	// Calculate error rate
	if totalRequests > 0 {
		errorRate := float64(totalErrors) / float64(totalRequests) * 100
		t.Logf("Error rate: %.2f%%", errorRate)
		
		// Allow up to 1% error rate during rotation
		if errorRate > 1.0 {
			t.Errorf("Error rate too high during certificate rotation: %.2f%%", errorRate)
		}
	}
	
	// Verify certificate was renewed
	statuses := manager.GetRenewalStatus()
	if len(statuses) == 0 {
		t.Error("No renewal status available")
	}
}

// TestStagingProviderIntegration tests integration with staging ACME providers
func TestStagingProviderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	email := os.Getenv("ACME_TEST_EMAIL")
	if email == "" {
		t.Skip("ACME_TEST_EMAIL environment variable not set")
	}
	
	providers := []struct {
		name     string
		provider string
		needsEAB bool
	}{
		{"Let's Encrypt Staging", ProviderLetsEncrypt, false},
		{"Buypass Staging", ProviderBuypass, false},
		{"Google Staging", ProviderGoogle, true},
	}
	
	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			if p.needsEAB {
				kid := os.Getenv(fmt.Sprintf("%s_EAB_KID", p.provider))
				hmac := os.Getenv(fmt.Sprintf("%s_EAB_HMAC", p.provider))
				if kid == "" || hmac == "" {
					t.Skipf("EAB credentials not set for %s", p.name)
				}
			}
			
			tempDir, err := os.MkdirTemp("", fmt.Sprintf("staging-%s-*", p.provider))
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(tempDir)
			
			config := &Config{
				Provider: p.provider,
				CacheDir: tempDir,
				Domains:  []string{fmt.Sprintf("test-%s.leproxy.local", p.provider)},
				Email:    email,
				TestMode: true,
			}
			
			if p.needsEAB {
				config.EABKID = os.Getenv(fmt.Sprintf("%s_EAB_KID", p.provider))
				config.EABHMAC = os.Getenv(fmt.Sprintf("%s_EAB_HMAC", p.provider))
			}
			
			manager, err := NewManager(config)
			if err != nil {
				t.Fatal(err)
			}
			
			// Test certificate retrieval
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			
			// Start renewal manager
			manager.StartRenewalManager(ctx)
			defer manager.StopRenewalManager()
			
			// Wait for initial certificate
			time.Sleep(5 * time.Second)
			
			// Check status
			statuses := manager.GetRenewalStatus()
			t.Logf("%s: Got %d certificate statuses", p.name, len(statuses))
			
			for domain, status := range statuses {
				t.Logf("%s - Domain: %s, Status: %s, Attempts: %d",
					p.name, domain, status.Status, status.Attempts)
				
				if status.Error != "" {
					t.Logf("%s - Error: %s", p.name, status.Error)
				}
			}
		})
	}
}

// TestLoadDuringRenewal performs load testing during certificate renewal
func TestLoadDuringRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	tempDir, err := os.MkdirTemp("", "load-renewal-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  []string{"load.leproxy.local"},
		Email:    os.Getenv("ACME_TEST_EMAIL"),
		TestMode: true,
	}
	
	if config.Email == "" {
		t.Skip("ACME_TEST_EMAIL environment variable not set")
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Set up metrics tracking
	var (
		totalRequests   int64
		successRequests int64
		failedRequests  int64
		totalLatency    int64
		maxLatency      int64
	)
	
	// Start renewal manager
	manager.StartRenewalManager(ctx)
	defer manager.StopRenewalManager()
	
	// Create test server
	server := &http.Server{
		Addr:      ":8444",
		TLSConfig: manager.GetTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			atomic.AddInt64(&totalRequests, 1)
			
			// Simulate some processing
			time.Sleep(10 * time.Millisecond)
			
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			
			latency := time.Since(start).Microseconds()
			atomic.AddInt64(&totalLatency, latency)
			
			// Update max latency
			for {
				oldMax := atomic.LoadInt64(&maxLatency)
				if latency <= oldMax || atomic.CompareAndSwapInt64(&maxLatency, oldMax, latency) {
					break
				}
			}
			
			atomic.AddInt64(&successRequests, 1)
		}),
	}
	
	// Start server
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Shutdown(context.Background())
	
	// Wait for server to start
	time.Sleep(2 * time.Second)
	
	// Create load generator
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: 5 * time.Second,
	}
	
	// Start load generation
	stopLoad := make(chan struct{})
	var loadWg sync.WaitGroup
	
	// Number of concurrent clients
	numClients := 50
	requestsPerClient := 100
	
	t.Logf("Starting load test with %d clients, %d requests each", numClients, requestsPerClient)
	
	startTime := time.Now()
	
	for i := 0; i < numClients; i++ {
		loadWg.Add(1)
		go func(clientID int) {
			defer loadWg.Done()
			
			for j := 0; j < requestsPerClient; j++ {
				select {
				case <-stopLoad:
					return
				default:
					resp, err := client.Get("https://load.leproxy.local:8444/")
					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						continue
					}
					resp.Body.Close()
					
					if resp.StatusCode != http.StatusOK {
						atomic.AddInt64(&failedRequests, 1)
					}
				}
				
				// Small delay between requests
				time.Sleep(10 * time.Millisecond)
			}
		}(i)
	}
	
	// Trigger renewal during load
	go func() {
		time.Sleep(5 * time.Second)
		t.Log("Triggering certificate renewal during load...")
		manager.RenewCertificates(ctx)
	}()
	
	// Wait for load to complete
	loadWg.Wait()
	duration := time.Since(startTime)
	
	// Calculate statistics
	total := atomic.LoadInt64(&totalRequests)
	success := atomic.LoadInt64(&successRequests)
	failed := atomic.LoadInt64(&failedRequests)
	avgLatency := float64(atomic.LoadInt64(&totalLatency)) / float64(total) / 1000.0 // Convert to ms
	maxLat := float64(atomic.LoadInt64(&maxLatency)) / 1000.0                        // Convert to ms
	throughput := float64(total) / duration.Seconds()
	
	t.Logf("Load Test Results:")
	t.Logf("  Duration: %v", duration)
	t.Logf("  Total Requests: %d", total)
	t.Logf("  Successful: %d (%.2f%%)", success, float64(success)/float64(total)*100)
	t.Logf("  Failed: %d (%.2f%%)", failed, float64(failed)/float64(total)*100)
	t.Logf("  Throughput: %.2f req/s", throughput)
	t.Logf("  Avg Latency: %.2f ms", avgLatency)
	t.Logf("  Max Latency: %.2f ms", maxLat)
	
	// Check acceptable performance
	successRate := float64(success) / float64(total) * 100
	if successRate < 99.0 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 99%%)", successRate)
	}
	
	if avgLatency > 100 {
		t.Errorf("Average latency too high: %.2f ms (expected < 100ms)", avgLatency)
	}
	
	if throughput < 10 {
		t.Errorf("Throughput too low: %.2f req/s (expected >= 10 req/s)", throughput)
	}
}

// TestMultiDomainRenewal tests renewal of multiple domain certificates
func TestMultiDomainRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	tempDir, err := os.MkdirTemp("", "multi-domain-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	
	domains := []string{
		"test1.leproxy.local",
		"test2.leproxy.local",
		"test3.leproxy.local",
		"*.wildcard.leproxy.local",
	}
	
	config := &Config{
		Provider: ProviderLetsEncrypt,
		CacheDir: tempDir,
		Domains:  domains,
		Email:    os.Getenv("ACME_TEST_EMAIL"),
		TestMode: true,
	}
	
	if config.Email == "" {
		t.Skip("ACME_TEST_EMAIL environment variable not set")
	}
	
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	
	// Start renewal manager
	manager.StartRenewalManager(ctx)
	defer manager.StopRenewalManager()
	
	// Set up alert tracking
	alertCount := 0
	var alertMu sync.Mutex
	
	manager.SetRenewalAlertHandler(func(status *RenewalStatus) {
		alertMu.Lock()
		alertCount++
		alertMu.Unlock()
		t.Logf("Alert triggered for domain: %s, status: %s, error: %s",
			status.Domain, status.Status, status.Error)
	})
	
	// Wait for initial certificates
	time.Sleep(10 * time.Second)
	
	// Check all domains have certificates
	statuses := manager.GetRenewalStatus()
	
	for _, domain := range domains {
		if status, exists := statuses[domain]; exists {
			t.Logf("Domain %s: Status=%s, Attempts=%d",
				domain, status.Status, status.Attempts)
			
			if status.Status == "failed" && status.Attempts >= MaxRenewalRetries {
				t.Errorf("Domain %s failed to get certificate after %d attempts",
					domain, status.Attempts)
			}
		} else {
			t.Errorf("No status found for domain %s", domain)
		}
	}
	
	// Check history
	history := manager.GetRenewalHistory()
	t.Logf("Renewal history contains %d entries", len(history))
	
	// Verify metrics are being tracked
	// This would normally check actual Prometheus metrics
	// but we'll just verify the renewal manager has metrics configured
	if manager.renewalManager.metrics == nil {
		t.Error("Renewal metrics not initialized")
	}
}