package health

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"filepath"
	"strings"
	"sync"
	"time"
)

// Global health server instance
var globalServer *http.Server

// GetGlobalServer returns the global health server instance
func GetGlobalServer() *http.Server {
	return globalServer
}

// SetGlobalServer sets the global health server instance
func SetGlobalServer(server *http.Server) {
	globalServer = server
}

type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

type CheckResult struct {
	Name      string        `json:"name"`
	Status    Status        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Latency   time.Duration `json:"latency_ms"`
	Timestamp time.Time     `json:"timestamp"`
}

type HealthStatus struct {
	Status     Status                 `json:"status"`
	Version    string                 `json:"version"`
	Uptime     time.Duration          `json:"uptime_seconds"`
	Checks     []CheckResult          `json:"checks,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

type HealthChecker struct {
	mu        sync.RWMutex
	checks    map[string]CheckFunc
	metadata  map[string]interface{}
	startTime time.Time
	version   string
}

type CheckFunc func(ctx context.Context) error

func New(version string) *HealthChecker {
	return &HealthChecker{
		checks:    make(map[string]CheckFunc),
		metadata:  make(map[string]interface{}),
		startTime: time.Now(),
		version:   version,
	}
}

func (h *HealthChecker) RegisterCheck(name string, check CheckFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = check
}

func (h *HealthChecker) SetMetadata(key string, value interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.metadata[key] = value
}

func (h *HealthChecker) Check(ctx context.Context) HealthStatus {
	h.mu.RLock()
	checks := make(map[string]CheckFunc)
	for name, check := range h.checks {
		checks[name] = check
	}
	metadata := make(map[string]interface{})
	for k, v := range h.metadata {
		metadata[k] = v
	}
	h.mu.RUnlock()

	status := HealthStatus{
		Status:    StatusHealthy,
		Version:   h.version,
		Uptime:    time.Since(h.startTime),
		Checks:    make([]CheckResult, 0, len(checks)),
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	var wg sync.WaitGroup
	resultsCh := make(chan CheckResult, len(checks))

	for name, check := range checks {
		wg.Add(1)
		go func(name string, check CheckFunc) {
			defer wg.Done()
			
			start := time.Now()
			result := CheckResult{
				Name:      name,
				Status:    StatusHealthy,
				Timestamp: time.Now(),
			}

			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			if err := check(checkCtx); err != nil {
				result.Status = StatusUnhealthy
				result.Message = err.Error()
			}
			
			result.Latency = time.Since(start)
			resultsCh <- result
		}(name, check)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	hasUnhealthy := false
	hasDegraded := false
	
	for result := range resultsCh {
		status.Checks = append(status.Checks, result)
		switch result.Status {
		case StatusUnhealthy:
			hasUnhealthy = true
		case StatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		status.Status = StatusUnhealthy
	} else if hasDegraded {
		status.Status = StatusDegraded
	}

	return status
}

func (h *HealthChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")
		
		httpStatus := http.StatusOK
		if status.Status == StatusUnhealthy {
			httpStatus = http.StatusServiceUnavailable
		} else if status.Status == StatusDegraded {
			httpStatus = http.StatusOK
		}

		w.WriteHeader(httpStatus)
		json.NewEncoder(w).Encode(status)
	}
}

func (h *HealthChecker) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")
		
		ready := status.Status != StatusUnhealthy
		response := map[string]interface{}{
			"ready":     ready,
			"timestamp": time.Now(),
		}

		httpStatus := http.StatusOK
		if !ready {
			httpStatus = http.StatusServiceUnavailable
			response["reason"] = "Health checks failed"
			
			var failedChecks []string
			for _, check := range status.Checks {
				if check.Status == StatusUnhealthy {
					failedChecks = append(failedChecks, check.Name)
				}
			}
			response["failed_checks"] = failedChecks
		}

		w.WriteHeader(httpStatus)
		json.NewEncoder(w).Encode(response)
	}
}

func (h *HealthChecker) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"alive":     true,
			"timestamp": time.Now(),
			"uptime":    time.Since(h.startTime).Seconds(),
		})
	}
}

func TCPCheck(address string) CheckFunc {
	return func(ctx context.Context) error {
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return fmt.Errorf("tcp check failed: %w", err)
		}
		conn.Close()
		return nil
	}
}

func HTTPCheck(url string) CheckFunc {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("http check failed: %w", err)
		}

		client := &http.Client{
			Timeout: 3 * time.Second,
		}
		
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("http check failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			return fmt.Errorf("http check failed: status %d", resp.StatusCode)
		}

		return nil
	}
}

// CertificateCheck checks the validity of certificates
func CertificateCheck(certPath string, warningDays int) CheckFunc {
	return func(ctx context.Context) error {
		info, err := os.Stat(certPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("certificate path does not exist: %s", certPath)
			}
			return fmt.Errorf("failed to check certificate path: %w", err)
		}
		
		if info.IsDir() {
			// Check all certificates in directory
			return checkCertificatesInDirectory(certPath, warningDays)
		}
		
		// Check single certificate file
		return checkCertificateFile(certPath, warningDays)
	}
}

// ACMERenewalHealthCheck checks the health of the ACME renewal system
func ACMERenewalHealthCheck(getRenewalHealth func() map[string]interface{}) CheckFunc {
	return func(ctx context.Context) error {
		if getRenewalHealth == nil {
			return fmt.Errorf("renewal health function not provided")
		}
		
		health := getRenewalHealth()
		
		// Check if healthy
		if healthy, ok := health["healthy"].(bool); ok && !healthy {
			if errMsg, ok := health["error"]; ok {
				return fmt.Errorf("renewal manager unhealthy: %v", errMsg)
			}
			return fmt.Errorf("renewal manager unhealthy")
		}
		
		// Check if in recovery mode
		if recoveryMode, ok := health["recovery_mode"].(bool); ok && recoveryMode {
			return fmt.Errorf("renewal manager in recovery mode")
		}
		
		// Check failure count
		if failureCount, ok := health["failure_count"].(int); ok && failureCount > 5 {
			return fmt.Errorf("high renewal failure count: %d", failureCount)
		}
		
		return nil
	}
}

// CertificateExpiryCheck checks for certificates expiring soon
func CertificateExpiryCheck(getRenewalStatus func() map[string]interface{}, warningDays int) CheckFunc {
	return func(ctx context.Context) error {
		if getRenewalStatus == nil {
			return fmt.Errorf("renewal status function not provided")
		}
		
		statuses, ok := getRenewalStatus().(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid renewal status format")
		}
		
		var expiringDomains []string
		var criticalDomains []string
		
		for domain, statusInterface := range statuses {
			if status, ok := statusInterface.(map[string]interface{}); ok {
				if expiryDateStr, ok := status["expiry_date"].(string); ok {
					expiryDate, err := time.Parse(time.RFC3339, expiryDateStr)
					if err == nil {
						daysUntilExpiry := int(time.Until(expiryDate).Hours() / 24)
						if daysUntilExpiry <= 3 {
							criticalDomains = append(criticalDomains, domain)
						} else if daysUntilExpiry <= warningDays {
							expiringDomains = append(expiringDomains, domain)
						}
					}
				}
			}
		}
		
		if len(criticalDomains) > 0 {
			return fmt.Errorf("critical: certificates expiring within 3 days: %v", criticalDomains)
		}
		
		if len(expiringDomains) > 0 {
			return fmt.Errorf("warning: certificates expiring within %d days: %v", warningDays, expiringDomains)
		}
		
		return nil
	}
}

// Helper functions for certificate checking

func checkCertificatesInDirectory(dirPath string, warningDays int) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate directory: %w", err)
	}
	
	var errors []string
	for _, entry := range entries {
		if !entry.IsDir() {
			filePath := filepath.Join(dirPath, entry.Name())
			if err := checkCertificateFile(filePath, warningDays); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", entry.Name(), err))
			}
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("certificate issues found: %s", strings.Join(errors, "; "))
	}
	
	return nil
}

func checkCertificateFile(filePath string, warningDays int) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}
	
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}
	
	if block.Type != "CERTIFICATE" {
		// Not a certificate file, skip
		return nil
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	// Check expiry
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysUntilExpiry < 0 {
		return fmt.Errorf("certificate expired %d days ago", -daysUntilExpiry)
	}
	
	if daysUntilExpiry <= warningDays {
		return fmt.Errorf("certificate expires in %d days", daysUntilExpiry)
	}
	
	return nil
}

func DiskSpaceCheck(path string, minPercent float64) CheckFunc {
	return func(ctx context.Context) error {
		return nil
	}
}