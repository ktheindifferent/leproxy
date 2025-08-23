package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/artyom/leproxy/internal/errors"
	"github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/metrics"
)

const (
	// Pre-expiry renewal window (30 days)
	RenewalWindow = 30 * 24 * time.Hour
	
	// Renewal check interval (every 12 hours)
	RenewalCheckInterval = 12 * time.Hour
	
	// Maximum retry attempts for renewal
	MaxRenewalRetries = 5
	
	// Initial retry delay
	InitialRetryDelay = 1 * time.Minute
	
	// Maximum retry delay
	MaxRetryDelay = 1 * time.Hour
	
	// Renewal history retention period
	RenewalHistoryRetention = 90 * 24 * time.Hour
)

// RenewalStatus represents the status of a certificate renewal
type RenewalStatus struct {
	Domain      string    `json:"domain"`
	Status      string    `json:"status"` // pending, in_progress, success, failed
	LastAttempt time.Time `json:"last_attempt"`
	NextAttempt time.Time `json:"next_attempt,omitempty"`
	Attempts    int       `json:"attempts"`
	Error       string    `json:"error,omitempty"`
	ExpiryDate  time.Time `json:"expiry_date"`
	RenewedAt   time.Time `json:"renewed_at,omitempty"`
}

// RenewalHistory represents the history of certificate renewals
type RenewalHistory struct {
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Duration  float64   `json:"duration_seconds"`
	Attempts  int       `json:"attempts"`
}

// RenewalManager handles certificate renewal with retry logic
type RenewalManager struct {
	manager       *Manager
	mu            sync.RWMutex
	statuses      map[string]*RenewalStatus
	history       []RenewalHistory
	metrics       *RenewalMetrics
	alertHandler  AlertHandler
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// AlertHandler is called when renewal failures occur
type AlertHandler func(status *RenewalStatus)

// RenewalMetrics tracks renewal-related metrics
type RenewalMetrics struct {
	renewalAttempts   *metrics.Metric
	renewalSuccesses  *metrics.Metric
	renewalFailures   *metrics.Metric
	renewalDuration   *metrics.Metric
	certificatesTotal *metrics.Metric
	expiryDays        *metrics.Metric
}

// NewRenewalManager creates a new renewal manager
func NewRenewalManager(manager *Manager) *RenewalManager {
	rm := &RenewalManager{
		manager:  manager,
		statuses: make(map[string]*RenewalStatus),
		history:  make([]RenewalHistory, 0),
		stopCh:   make(chan struct{}),
	}
	
	// Initialize metrics
	registry := metrics.DefaultRegistry()
	rm.metrics = &RenewalMetrics{
		renewalAttempts:   registry.Register("cert_renewal_attempts_total", metrics.MetricTypeCounter, "Total certificate renewal attempts"),
		renewalSuccesses:  registry.Register("cert_renewal_successes_total", metrics.MetricTypeCounter, "Total successful certificate renewals"),
		renewalFailures:   registry.Register("cert_renewal_failures_total", metrics.MetricTypeCounter, "Total failed certificate renewals"),
		renewalDuration:   registry.Register("cert_renewal_duration_seconds", metrics.MetricTypeHistogram, "Certificate renewal duration"),
		certificatesTotal: registry.Register("certificates_total", metrics.MetricTypeGauge, "Total number of certificates"),
		expiryDays:        registry.Register("cert_expiry_days", metrics.MetricTypeGauge, "Days until certificate expiry"),
	}
	
	return rm
}

// SetAlertHandler sets the alert handler for renewal failures
func (rm *RenewalManager) SetAlertHandler(handler AlertHandler) {
	rm.alertHandler = handler
}

// Start begins the automatic renewal process
func (rm *RenewalManager) Start(ctx context.Context) {
	rm.wg.Add(1)
	go rm.renewalLoop(ctx)
}

// Stop gracefully stops the renewal manager
func (rm *RenewalManager) Stop() {
	close(rm.stopCh)
	rm.wg.Wait()
}

// renewalLoop runs the periodic renewal check
func (rm *RenewalManager) renewalLoop(ctx context.Context) {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(RenewalCheckInterval)
	defer ticker.Stop()
	
	// Initial check
	rm.checkAndRenewAll(ctx)
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopCh:
			return
		case <-ticker.C:
			rm.checkAndRenewAll(ctx)
		}
	}
}

// checkAndRenewAll checks all certificates and renews if necessary
func (rm *RenewalManager) checkAndRenewAll(ctx context.Context) {
	logger.Info("Starting certificate renewal check")
	
	domains := rm.manager.config.Domains
	if len(domains) == 0 {
		// Get domains from cache directory
		domains = rm.getDomainsFromCache()
	}
	
	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			rm.checkAndRenewCertificate(ctx, d)
		}(domain)
	}
	wg.Wait()
	
	// Clean up old history entries
	rm.cleanupHistory()
}

// checkAndRenewCertificate checks and renews a single certificate with retry logic
func (rm *RenewalManager) checkAndRenewCertificate(ctx context.Context, domain string) {
	rm.mu.Lock()
	status, exists := rm.statuses[domain]
	if !exists {
		status = &RenewalStatus{
			Domain: domain,
			Status: "pending",
		}
		rm.statuses[domain] = status
	}
	rm.mu.Unlock()
	
	// Check if certificate needs renewal
	cert, err := rm.getCertificate(domain)
	if err != nil {
		logger.Error("Failed to get certificate", "domain", domain, "error", err)
		rm.updateStatus(domain, "failed", err.Error())
		return
	}
	
	if cert == nil {
		// Certificate doesn't exist, need to obtain
		rm.renewWithRetry(ctx, domain, 0)
		return
	}
	
	// Parse certificate to check expiry
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		logger.Error("Failed to parse certificate", "domain", domain, "error", err)
		rm.updateStatus(domain, "failed", err.Error())
		return
	}
	
	// Update expiry date in status
	rm.mu.Lock()
	status.ExpiryDate = x509Cert.NotAfter
	rm.mu.Unlock()
	
	// Update expiry metric
	daysUntilExpiry := time.Until(x509Cert.NotAfter).Hours() / 24
	rm.metrics.expiryDays.WithLabels(map[string]string{"domain": domain}).Set(daysUntilExpiry)
	
	// Check if renewal is needed
	if time.Until(x509Cert.NotAfter) <= RenewalWindow {
		logger.Info("Certificate needs renewal", 
			"domain", domain, 
			"expiry", x509Cert.NotAfter,
			"days_remaining", int(daysUntilExpiry))
		rm.renewWithRetry(ctx, domain, 0)
	} else {
		logger.Debug("Certificate is valid", 
			"domain", domain, 
			"expiry", x509Cert.NotAfter,
			"days_remaining", int(daysUntilExpiry))
		rm.updateStatus(domain, "valid", "")
	}
}

// renewWithRetry attempts to renew a certificate with exponential backoff retry
func (rm *RenewalManager) renewWithRetry(ctx context.Context, domain string, attempt int) {
	if attempt >= MaxRenewalRetries {
		err := fmt.Sprintf("Max renewal attempts (%d) exceeded", MaxRenewalRetries)
		logger.Error("Certificate renewal failed", "domain", domain, "error", err)
		rm.updateStatus(domain, "failed", err)
		rm.recordHistory(domain, false, err, 0, attempt)
		
		// Trigger alert
		if rm.alertHandler != nil {
			rm.mu.RLock()
			status := rm.statuses[domain]
			rm.mu.RUnlock()
			rm.alertHandler(status)
		}
		return
	}
	
	// Calculate retry delay with exponential backoff and jitter
	delay := rm.calculateRetryDelay(attempt)
	if attempt > 0 {
		logger.Info("Retrying certificate renewal", 
			"domain", domain, 
			"attempt", attempt+1,
			"delay", delay)
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
	
	// Update status
	rm.updateStatus(domain, "in_progress", "")
	rm.mu.Lock()
	rm.statuses[domain].Attempts = attempt + 1
	rm.statuses[domain].LastAttempt = time.Now()
	rm.mu.Unlock()
	
	// Increment attempt metric
	rm.metrics.renewalAttempts.Inc()
	
	// Attempt renewal
	start := time.Now()
	err := rm.performRenewal(ctx, domain)
	duration := time.Since(start).Seconds()
	
	// Record duration metric
	rm.metrics.renewalDuration.Observe(duration)
	
	if err != nil {
		logger.Warn("Certificate renewal attempt failed", 
			"domain", domain, 
			"attempt", attempt+1,
			"error", err)
		
		// Increment failure metric
		rm.metrics.renewalFailures.Inc()
		
		// Calculate next retry time
		nextDelay := rm.calculateRetryDelay(attempt + 1)
		rm.mu.Lock()
		rm.statuses[domain].NextAttempt = time.Now().Add(nextDelay)
		rm.statuses[domain].Error = err.Error()
		rm.mu.Unlock()
		
		// Retry
		rm.renewWithRetry(ctx, domain, attempt+1)
	} else {
		logger.Info("Certificate renewed successfully", 
			"domain", domain, 
			"attempts", attempt+1,
			"duration", duration)
		
		// Update status
		rm.updateStatus(domain, "success", "")
		rm.mu.Lock()
		rm.statuses[domain].RenewedAt = time.Now()
		rm.statuses[domain].Attempts = attempt + 1
		rm.mu.Unlock()
		
		// Increment success metric
		rm.metrics.renewalSuccesses.Inc()
		
		// Record history
		rm.recordHistory(domain, true, "", duration, attempt+1)
	}
}

// performRenewal performs the actual certificate renewal
func (rm *RenewalManager) performRenewal(ctx context.Context, domain string) error {
	// Force renewal by deleting cached certificate
	cacheFile := rm.getCacheFilePath(domain)
	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove cached certificate", "domain", domain, "error", err)
	}
	
	// Request new certificate
	hello := &tls.ClientHelloInfo{
		ServerName: domain,
	}
	
	cert, err := rm.manager.Manager.GetCertificate(hello)
	if err != nil {
		return errors.Wrap(err, errors.ErrorTypeCertificate, "renewal failed", domain)
	}
	
	if cert == nil {
		return errors.New(errors.ErrorTypeCertificate, "renewal", domain, fmt.Errorf("no certificate returned"))
	}
	
	return nil
}

// calculateRetryDelay calculates the retry delay with exponential backoff and jitter
func (rm *RenewalManager) calculateRetryDelay(attempt int) time.Duration {
	if attempt == 0 {
		return 0
	}
	
	// Exponential backoff: 2^attempt * InitialRetryDelay
	backoff := time.Duration(math.Pow(2, float64(attempt-1))) * InitialRetryDelay
	
	// Cap at MaxRetryDelay
	if backoff > MaxRetryDelay {
		backoff = MaxRetryDelay
	}
	
	// Add jitter (±25%)
	jitter := time.Duration(rand.Float64()*0.5-0.25) * backoff
	delay := backoff + jitter
	
	if delay < 0 {
		delay = backoff
	}
	
	return delay
}

// getCertificate retrieves a certificate from cache
func (rm *RenewalManager) getCertificate(domain string) (*tls.Certificate, error) {
	cacheFile := rm.getCacheFilePath(domain)
	
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	
	// Parse PEM blocks
	var certDER [][]byte
	var keyDER []byte
	
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		
		switch block.Type {
		case "CERTIFICATE":
			certDER = append(certDER, block.Bytes)
		case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
			keyDER = block.Bytes
		}
	}
	
	if len(certDER) == 0 || keyDER == nil {
		return nil, fmt.Errorf("invalid certificate cache file")
	}
	
	cert := &tls.Certificate{
		Certificate: certDER,
	}
	
	return cert, nil
}

// getCacheFilePath returns the cache file path for a domain
func (rm *RenewalManager) getCacheFilePath(domain string) string {
	return filepath.Join(rm.manager.config.CacheDir, domain)
}

// getDomainsFromCache gets all domains from the cache directory
func (rm *RenewalManager) getDomainsFromCache() []string {
	var domains []string
	
	files, err := os.ReadDir(rm.manager.config.CacheDir)
	if err != nil {
		logger.Error("Failed to read cache directory", "error", err)
		return domains
	}
	
	for _, file := range files {
		if !file.IsDir() {
			domains = append(domains, file.Name())
		}
	}
	
	return domains
}

// updateStatus updates the renewal status for a domain
func (rm *RenewalManager) updateStatus(domain, status, errorMsg string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if s, exists := rm.statuses[domain]; exists {
		s.Status = status
		s.Error = errorMsg
		if errorMsg == "" && status == "success" {
			s.Error = ""
			s.NextAttempt = time.Time{}
		}
	}
}

// recordHistory records renewal history
func (rm *RenewalManager) recordHistory(domain string, success bool, errorMsg string, duration float64, attempts int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	history := RenewalHistory{
		Domain:    domain,
		Timestamp: time.Now(),
		Success:   success,
		Error:     errorMsg,
		Duration:  duration,
		Attempts:  attempts,
	}
	
	rm.history = append(rm.history, history)
	
	// Save history to file
	rm.saveHistory()
}

// cleanupHistory removes old history entries
func (rm *RenewalManager) cleanupHistory() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	cutoff := time.Now().Add(-RenewalHistoryRetention)
	var newHistory []RenewalHistory
	
	for _, h := range rm.history {
		if h.Timestamp.After(cutoff) {
			newHistory = append(newHistory, h)
		}
	}
	
	rm.history = newHistory
}

// saveHistory saves renewal history to file
func (rm *RenewalManager) saveHistory() {
	historyFile := filepath.Join(rm.manager.config.CacheDir, "renewal_history.json")
	
	data, err := json.MarshalIndent(rm.history, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal renewal history", "error", err)
		return
	}
	
	if err := os.WriteFile(historyFile, data, 0600); err != nil {
		logger.Error("Failed to save renewal history", "error", err)
	}
}

// loadHistory loads renewal history from file
func (rm *RenewalManager) loadHistory() {
	historyFile := filepath.Join(rm.manager.config.CacheDir, "renewal_history.json")
	
	data, err := os.ReadFile(historyFile)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error("Failed to load renewal history", "error", err)
		}
		return
	}
	
	if err := json.Unmarshal(data, &rm.history); err != nil {
		logger.Error("Failed to unmarshal renewal history", "error", err)
	}
}

// GetStatus returns the current renewal status for all domains
func (rm *RenewalManager) GetStatus() map[string]*RenewalStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	statuses := make(map[string]*RenewalStatus)
	for k, v := range rm.statuses {
		statuses[k] = v
	}
	
	return statuses
}

// GetHistory returns the renewal history
func (rm *RenewalManager) GetHistory() []RenewalHistory {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	history := make([]RenewalHistory, len(rm.history))
	copy(history, rm.history)
	
	return history
}

// GetMetrics returns renewal metrics
func (rm *RenewalManager) GetMetrics() *RenewalMetrics {
	return rm.metrics
}