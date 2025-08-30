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
	
	// Critical expiry threshold (triggers immediate retry)
	CriticalExpiryThreshold = 7 * 24 * time.Hour
	
	// Emergency expiry threshold (triggers aggressive retry)
	EmergencyExpiryThreshold = 3 * 24 * time.Hour
	
	// Health check interval
	HealthCheckInterval = 5 * time.Minute
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
	alertManager  *AlertManager
	stopCh        chan struct{}
	wg            sync.WaitGroup
	isHealthy     bool
	lastHealthCheck time.Time
	failureCount  int
	recoveryMode  bool
	initError     error
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

// NewRenewalManager creates a new renewal manager with error recovery
func NewRenewalManager(manager *Manager) *RenewalManager {
	rm := &RenewalManager{
		manager:  manager,
		statuses: make(map[string]*RenewalStatus),
		history:  make([]RenewalHistory, 0),
		stopCh:   make(chan struct{}),
		isHealthy: true,
		lastHealthCheck: time.Now(),
	}
	
	// Initialize metrics with error handling
	if err := rm.initializeMetrics(); err != nil {
		logger.Error("Failed to initialize renewal metrics", map[string]interface{}{"error": err})
		rm.initError = err
		// Continue with degraded functionality
	}
	
	// Load history with error recovery
	if err := rm.loadHistoryWithRecovery(); err != nil {
		logger.Warn("Failed to load renewal history", map[string]interface{}{"error": err})
		// Continue with empty history
	}
	
	// Initialize alert manager with default config
	rm.alertManager = NewAlertManager(nil)
	
	return rm
}

// initializeMetrics initializes metrics with error handling
func (rm *RenewalManager) initializeMetrics() error {
	registry := metrics.DefaultRegistry()
	if registry == nil {
		return fmt.Errorf("metrics registry not available")
	}
	
	rm.metrics = &RenewalMetrics{
		renewalAttempts:   registry.Register("cert_renewal_attempts_total", metrics.MetricTypeCounter, "Total certificate renewal attempts"),
		renewalSuccesses:  registry.Register("cert_renewal_successes_total", metrics.MetricTypeCounter, "Total successful certificate renewals"),
		renewalFailures:   registry.Register("cert_renewal_failures_total", metrics.MetricTypeCounter, "Total failed certificate renewals"),
		renewalDuration:   registry.Register("cert_renewal_duration_seconds", metrics.MetricTypeHistogram, "Certificate renewal duration"),
		certificatesTotal: registry.Register("certificates_total", metrics.MetricTypeGauge, "Total number of certificates"),
		expiryDays:        registry.Register("cert_expiry_days", metrics.MetricTypeGauge, "Days until certificate expiry"),
	}
	
	// Add additional critical metrics
	registry.Register("cert_renewal_health", metrics.MetricTypeGauge, "Certificate renewal manager health (1=healthy, 0=unhealthy)")
	registry.Register("cert_renewal_recovery_mode", metrics.MetricTypeGauge, "Recovery mode active (1=yes, 0=no)")
	registry.Register("cert_critical_expiry_count", metrics.MetricTypeGauge, "Number of certificates in critical expiry window")
	
	return nil
}

// SetAlertHandler sets the alert handler for renewal failures
func (rm *RenewalManager) SetAlertHandler(handler AlertHandler) {
	rm.alertHandler = handler
}

// Start begins the automatic renewal process with recovery handling
func (rm *RenewalManager) Start(ctx context.Context) error {
	// Check for initialization errors
	if rm.initError != nil {
		logger.Warn("Starting renewal manager with initialization errors", map[string]interface{}{"error": rm.initError})
	}
	
	// Start health monitoring
	rm.wg.Add(1)
	go rm.healthMonitorLoop(ctx)
	
	// Start renewal loop
	rm.wg.Add(1)
	go rm.renewalLoop(ctx)
	
	// Start recovery monitor
	rm.wg.Add(1)
	go rm.recoveryMonitorLoop(ctx)
	
	logger.Info("Certificate renewal manager started")
	return nil
}

// Stop gracefully stops the renewal manager
func (rm *RenewalManager) Stop() {
	close(rm.stopCh)
	rm.wg.Wait()
}

// renewalLoop runs the periodic renewal check with adaptive intervals
func (rm *RenewalManager) renewalLoop(ctx context.Context) {
	defer rm.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Renewal loop panic recovered", map[string]interface{}{"error": r})
			rm.setUnhealthy("renewal loop panic")
		}
	}()
	
	// Use adaptive check interval based on health
	getCheckInterval := func() time.Duration {
		rm.mu.RLock()
		defer rm.mu.RUnlock()
		
		if rm.recoveryMode {
			return 5 * time.Minute // Aggressive checking in recovery mode
		}
		if !rm.isHealthy {
			return 30 * time.Minute // More frequent checks when unhealthy
		}
		return RenewalCheckInterval // Normal interval
	}
	
	// Initial check with error handling
	if err := rm.safeCheckAndRenewAll(ctx); err != nil {
		logger.Error("Initial renewal check failed", map[string]interface{}{"error": err})
		rm.setUnhealthy("initial check failed")
	}
	
	for {
		interval := getCheckInterval()
		timer := time.NewTimer(interval)
		
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-rm.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			if err := rm.safeCheckAndRenewAll(ctx); err != nil {
				logger.Error("Renewal check failed", map[string]interface{}{"error": err})
				rm.incrementFailureCount()
			} else {
				rm.resetFailureCount()
			}
		}
	}
}

// safeCheckAndRenewAll wraps checkAndRenewAll with panic recovery
func (rm *RenewalManager) safeCheckAndRenewAll(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during renewal check: %v", r)
		}
	}()
	
	rm.checkAndRenewAll(ctx)
	return nil
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

// checkAndRenewCertificate checks and renews a single certificate with enhanced retry logic
func (rm *RenewalManager) checkAndRenewCertificate(ctx context.Context, domain string) {
	// Add timeout protection
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	
	ctx = checkCtx
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
		logger.Error("Failed to get certificate", map[string]interface{}{"domain": domain, "error": err})
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
		logger.Error("Failed to parse certificate", map[string]interface{}{"domain": domain, "error": err})
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
		logger.Info("Certificate needs renewal", map[string]interface{}{"domain": domain, "expiry": x509Cert.NotAfter, "days_remaining": int(daysUntilExpiry)})
		rm.renewWithRetry(ctx, domain, 0)
	} else {
		logger.Debug("Certificate is valid", map[string]interface{}{"domain": domain, "expiry": x509Cert.NotAfter, "days_remaining": int(daysUntilExpiry)})
		rm.updateStatus(domain, "valid", "")
	}
}

// renewWithRetry attempts to renew a certificate with adaptive retry strategy
func (rm *RenewalManager) renewWithRetry(ctx context.Context, domain string, attempt int) {
	// Determine max retries based on urgency
	maxRetries := rm.getMaxRetries(domain)
	if attempt >= maxRetries {
		err := fmt.Sprintf("Max renewal attempts (%d) exceeded", MaxRenewalRetries)
		logger.Error("Certificate renewal failed", map[string]interface{}{"domain": domain, "error": err})
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
		logger.Info("Retrying certificate renewal", map[string]interface{}{"domain": domain, "attempt": attempt+1, "delay": delay})
		
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
		logger.Warn("Certificate renewal attempt failed", map[string]interface{}{"domain": domain, "attempt": attempt+1, "error": err})
		
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
		logger.Info("Certificate renewed successfully", map[string]interface{}{"domain": domain, "attempts": attempt+1, "duration": duration})
		
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
		logger.Warn("Failed to remove cached certificate", map[string]interface{}{"domain": domain, "error": err})
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

// calculateRetryDelay calculates the retry delay with adaptive strategy based on urgency
func (rm *RenewalManager) calculateRetryDelay(attempt int) time.Duration {
	if attempt == 0 {
		return 0
	}
	
	// Check if any certificate is in critical/emergency state
	criticalMode := rm.isInCriticalMode()
	
	var baseDelay time.Duration
	if criticalMode {
		// Aggressive retry for critical certificates
		baseDelay = 30 * time.Second
	} else {
		baseDelay = InitialRetryDelay
	}
	
	// Exponential backoff: 2^attempt * baseDelay
	backoff := time.Duration(math.Pow(2, float64(attempt-1))) * baseDelay
	
	// Adaptive max delay based on urgency
	maxDelay := MaxRetryDelay
	if criticalMode {
		maxDelay = 5 * time.Minute // Much shorter max delay in critical mode
	}
	
	// Cap at maxDelay
	if backoff > maxDelay {
		backoff = maxDelay
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
		logger.Error("Failed to read cache directory", map[string]interface{}{"error": err})
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
		logger.Error("Failed to marshal renewal history", map[string]interface{}{"error": err})
		return
	}
	
	if err := os.WriteFile(historyFile, data, 0600); err != nil {
		logger.Error("Failed to save renewal history", map[string]interface{}{"error": err})
	}
}

// loadHistory loads renewal history from file
func (rm *RenewalManager) loadHistory() {
	historyFile := filepath.Join(rm.manager.config.CacheDir, "renewal_history.json")
	
	data, err := os.ReadFile(historyFile)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error("Failed to load renewal history", map[string]interface{}{"error": err})
		}
		return
	}
	
	if err := json.Unmarshal(data, &rm.history); err != nil {
		logger.Error("Failed to unmarshal renewal history", map[string]interface{}{"error": err})
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

// Additional helper methods for enhanced error recovery

// healthMonitorLoop monitors the health of the renewal manager
func (rm *RenewalManager) healthMonitorLoop(ctx context.Context) {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopCh:
			return
		case <-ticker.C:
			rm.performHealthCheck(ctx)
		}
	}
}

// performHealthCheck checks the health of the renewal system
func (rm *RenewalManager) performHealthCheck(ctx context.Context) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.lastHealthCheck = time.Now()
	
	// Check for critical certificates
	criticalCount := 0
	emergencyCount := 0
	
	for _, status := range rm.statuses {
		if !status.ExpiryDate.IsZero() {
			timeUntilExpiry := time.Until(status.ExpiryDate)
			if timeUntilExpiry <= EmergencyExpiryThreshold {
				emergencyCount++
			} else if timeUntilExpiry <= CriticalExpiryThreshold {
				criticalCount++
			}
		}
	}
	
	// Update metrics
	if rm.metrics != nil {
		registry := metrics.DefaultRegistry()
		if healthMetric := registry.Get("cert_renewal_health"); healthMetric != nil {
			if rm.isHealthy {
				healthMetric.Set(1)
			} else {
				healthMetric.Set(0)
			}
		}
		
		if criticalMetric := registry.Get("cert_critical_expiry_count"); criticalMetric != nil {
			criticalMetric.Set(float64(criticalCount + emergencyCount))
		}
	}
	
	// Enter recovery mode if needed
	if emergencyCount > 0 && !rm.recoveryMode {
		logger.Warn("Entering recovery mode due to emergency expiry", map[string]interface{}{"count": emergencyCount})
		rm.recoveryMode = true
	} else if criticalCount > 0 && !rm.recoveryMode {
		logger.Info("Monitoring critical certificates", map[string]interface{}{"count": criticalCount})
	}
	
	// Exit recovery mode if all certificates are healthy
	if rm.recoveryMode && emergencyCount == 0 && criticalCount == 0 {
		logger.Info("Exiting recovery mode - all certificates healthy")
		rm.recoveryMode = false
	}
}

// recoveryMonitorLoop monitors for recovery situations
func (rm *RenewalManager) recoveryMonitorLoop(ctx context.Context) {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopCh:
			return
		case <-ticker.C:
			if rm.shouldTriggerEmergencyRenewal() {
				logger.Warn("Triggering emergency renewal")
				go rm.emergencyRenewalCheck(ctx)
			}
		}
	}
}

// shouldTriggerEmergencyRenewal determines if emergency renewal is needed
func (rm *RenewalManager) shouldTriggerEmergencyRenewal() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	for _, status := range rm.statuses {
		if !status.ExpiryDate.IsZero() {
			timeUntilExpiry := time.Until(status.ExpiryDate)
			if timeUntilExpiry <= EmergencyExpiryThreshold && status.Status != "in_progress" {
				return true
			}
		}
	}
	
	return false
}

// emergencyRenewalCheck performs immediate renewal for critical certificates
func (rm *RenewalManager) emergencyRenewalCheck(ctx context.Context) {
	logger.Info("Starting emergency renewal check")
	
	domains := rm.getDomainsFromCache()
	for _, domain := range domains {
		rm.mu.RLock()
		status, exists := rm.statuses[domain]
		rm.mu.RUnlock()
		
		if exists && !status.ExpiryDate.IsZero() {
			timeUntilExpiry := time.Until(status.ExpiryDate)
			if timeUntilExpiry <= EmergencyExpiryThreshold {
				logger.Warn("Emergency renewal for domain", map[string]interface{}{"domain": domain, "expires_in": timeUntilExpiry})
				go rm.renewWithRetry(ctx, domain, 0)
			}
		}
	}
}

// setUnhealthy marks the renewal manager as unhealthy
func (rm *RenewalManager) setUnhealthy(reason string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if rm.isHealthy {
		logger.Error("Renewal manager health degraded", map[string]interface{}{"reason": reason})
		rm.isHealthy = false
		
		// Update health metric
		if rm.metrics != nil {
			registry := metrics.DefaultRegistry()
			if healthMetric := registry.Get("cert_renewal_health"); healthMetric != nil {
				healthMetric.Set(0)
			}
		}
	}
}

// incrementFailureCount increments the failure counter
func (rm *RenewalManager) incrementFailureCount() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.failureCount++
	if rm.failureCount >= 3 && rm.isHealthy {
		rm.isHealthy = false
		logger.Error("Renewal manager marked unhealthy due to repeated failures", map[string]interface{}{"count": rm.failureCount})
	}
}

// resetFailureCount resets the failure counter
func (rm *RenewalManager) resetFailureCount() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	if rm.failureCount > 0 {
		rm.failureCount = 0
		if !rm.isHealthy {
			rm.isHealthy = true
			logger.Info("Renewal manager health restored")
		}
	}
}

// getMaxRetries returns the maximum retry attempts based on certificate urgency
func (rm *RenewalManager) getMaxRetries(domain string) int {
	rm.mu.RLock()
	status, exists := rm.statuses[domain]
	rm.mu.RUnlock()
	
	if !exists || status.ExpiryDate.IsZero() {
		return MaxRenewalRetries
	}
	
	timeUntilExpiry := time.Until(status.ExpiryDate)
	if timeUntilExpiry <= EmergencyExpiryThreshold {
		return 10 // More retries for emergency
	} else if timeUntilExpiry <= CriticalExpiryThreshold {
		return 7 // More retries for critical
	}
	
	return MaxRenewalRetries
}

// isInCriticalMode checks if any certificate is in critical state
func (rm *RenewalManager) isInCriticalMode() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	for _, status := range rm.statuses {
		if !status.ExpiryDate.IsZero() {
			timeUntilExpiry := time.Until(status.ExpiryDate)
			if timeUntilExpiry <= CriticalExpiryThreshold {
				return true
			}
		}
	}
	
	return rm.recoveryMode
}

// loadHistoryWithRecovery loads history with error recovery
func (rm *RenewalManager) loadHistoryWithRecovery() error {
	historyFile := filepath.Join(rm.manager.config.CacheDir, "renewal_history.json")
	
	data, err := os.ReadFile(historyFile)
	if err != nil {
		if os.IsNotExist(err) {
			// No history file is not an error
			return nil
		}
		return err
	}
	
	if err := json.Unmarshal(data, &rm.history); err != nil {
		// Try to backup corrupted file
		backupFile := fmt.Sprintf("%s.corrupt.%d", historyFile, time.Now().Unix())
		os.Rename(historyFile, backupFile)
		logger.Warn("Backed up corrupted history file", map[string]interface{}{"backup": backupFile})
		return err
	}
	
	return nil
}

// IsHealthy returns the health status of the renewal manager
func (rm *RenewalManager) IsHealthy() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.isHealthy
}

// GetHealthStatus returns detailed health information
func (rm *RenewalManager) GetHealthStatus() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	return map[string]interface{}{
		"healthy":           rm.isHealthy,
		"recovery_mode":     rm.recoveryMode,
		"failure_count":     rm.failureCount,
		"last_health_check": rm.lastHealthCheck,
		"init_error":        rm.initError,
	}
}