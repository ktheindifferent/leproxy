// Package certmon provides certificate expiry monitoring and alerting
package certmon

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/metrics"
)

// CertificateInfo holds information about a certificate
type CertificateInfo struct {
	Domain      string    `json:"domain"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	IsExpired   bool      `json:"is_expired"`
	IsExpiring  bool      `json:"is_expiring"`
	SerialNumber string   `json:"serial_number"`
	DNSNames    []string  `json:"dns_names"`
	FilePath    string    `json:"file_path"`
}

// Monitor monitors certificate expiry
type Monitor struct {
	mu              sync.RWMutex
	cacheDir        string
	certificates    map[string]*CertificateInfo
	checkInterval   time.Duration
	warningDays     int
	criticalDays    int
	stopChan        chan struct{}
	alertHandlers   []AlertHandler
	webhookURL      string
	metricsEnabled  bool
}

// AlertHandler is called when a certificate is expiring
type AlertHandler func(cert *CertificateInfo, level AlertLevel)

// AlertLevel represents the severity of an alert
type AlertLevel string

const (
	AlertLevelInfo     AlertLevel = "info"
	AlertLevelWarning  AlertLevel = "warning"
	AlertLevelCritical AlertLevel = "critical"
	AlertLevelExpired  AlertLevel = "expired"
)

// NewMonitor creates a new certificate monitor
func NewMonitor(cacheDir string, checkInterval time.Duration) *Monitor {
	return &Monitor{
		cacheDir:       cacheDir,
		certificates:   make(map[string]*CertificateInfo),
		checkInterval:  checkInterval,
		warningDays:    30,
		criticalDays:   7,
		stopChan:       make(chan struct{}),
		metricsEnabled: true,
	}
}

// Start begins monitoring certificates
func (m *Monitor) Start() {
	// Initial scan
	m.scanCertificates()
	
	// Start monitoring loop
	go m.monitorLoop()
	
	logger.Info("Certificate monitor started", 
		"cache_dir", m.cacheDir,
		"check_interval", m.checkInterval,
		"warning_days", m.warningDays,
		"critical_days", m.criticalDays)
}

// Stop stops monitoring certificates
func (m *Monitor) Stop() {
	close(m.stopChan)
	logger.Info("Certificate monitor stopped")
}

// monitorLoop continuously monitors certificates
func (m *Monitor) monitorLoop() {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.scanCertificates()
			m.checkExpiry()
			m.updateMetrics()
		case <-m.stopChan:
			return
		}
	}
}

// scanCertificates scans the cache directory for certificates
func (m *Monitor) scanCertificates() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing certificates
	m.certificates = make(map[string]*CertificateInfo)

	// Walk through cache directory
	err := filepath.Walk(m.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		// Check for certificate files
		if !info.IsDir() && (filepath.Ext(path) == ".crt" || filepath.Ext(path) == ".pem") {
			if certInfo := m.loadCertificate(path); certInfo != nil {
				m.certificates[certInfo.Domain] = certInfo
			}
		}

		return nil
	})

	if err != nil {
		logger.Error("Failed to scan certificates", "error", err)
	}

	logger.Debug("Certificate scan completed", "count", len(m.certificates))
}

// loadCertificate loads and parses a certificate file
func (m *Monitor) loadCertificate(path string) *CertificateInfo {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Error("Failed to read certificate file", "path", path, "error", err)
		return nil
	}

	// Parse PEM data
	block, _ := pem.Decode(data)
	if block == nil {
		logger.Error("Failed to decode PEM block", "path", path)
		return nil
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error("Failed to parse certificate", "path", path, "error", err)
		return nil
	}

	// Extract domain from certificate or filename
	domain := ""
	if len(cert.DNSNames) > 0 {
		domain = cert.DNSNames[0]
	} else if cert.Subject.CommonName != "" {
		domain = cert.Subject.CommonName
	} else {
		// Use filename as fallback
		domain = filepath.Base(path)
		domain = domain[:len(domain)-len(filepath.Ext(domain))]
	}

	// Calculate days until expiry
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	isExpired := now.After(cert.NotAfter)
	isExpiring := daysLeft <= m.warningDays && !isExpired

	return &CertificateInfo{
		Domain:       domain,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DaysLeft:     daysLeft,
		IsExpired:    isExpired,
		IsExpiring:   isExpiring,
		SerialNumber: cert.SerialNumber.String(),
		DNSNames:     cert.DNSNames,
		FilePath:     path,
	}
}

// checkExpiry checks for expiring certificates and triggers alerts
func (m *Monitor) checkExpiry() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cert := range m.certificates {
		level := m.getAlertLevel(cert)
		
		if level != AlertLevelInfo {
			m.triggerAlert(cert, level)
		}
	}
}

// getAlertLevel determines the alert level for a certificate
func (m *Monitor) getAlertLevel(cert *CertificateInfo) AlertLevel {
	if cert.IsExpired {
		return AlertLevelExpired
	}
	if cert.DaysLeft <= m.criticalDays {
		return AlertLevelCritical
	}
	if cert.DaysLeft <= m.warningDays {
		return AlertLevelWarning
	}
	return AlertLevelInfo
}

// triggerAlert triggers alerts for expiring certificates
func (m *Monitor) triggerAlert(cert *CertificateInfo, level AlertLevel) {
	// Log the alert
	switch level {
	case AlertLevelExpired:
		logger.Error("Certificate expired", 
			"domain", cert.Domain,
			"expired", cert.NotAfter.Format(time.RFC3339))
	case AlertLevelCritical:
		logger.Error("Certificate expiring soon", 
			"domain", cert.Domain,
			"days_left", cert.DaysLeft,
			"expires", cert.NotAfter.Format(time.RFC3339))
	case AlertLevelWarning:
		logger.Warn("Certificate expiring", 
			"domain", cert.Domain,
			"days_left", cert.DaysLeft,
			"expires", cert.NotAfter.Format(time.RFC3339))
	}

	// Call alert handlers
	for _, handler := range m.alertHandlers {
		handler(cert, level)
	}

	// Send webhook if configured
	if m.webhookURL != "" {
		m.sendWebhook(cert, level)
	}
}

// sendWebhook sends an alert to a webhook URL
func (m *Monitor) sendWebhook(cert *CertificateInfo, level AlertLevel) {
	payload := map[string]interface{}{
		"alert_level": level,
		"certificate": cert,
		"timestamp":   time.Now().Unix(),
		"message":     fmt.Sprintf("Certificate for %s expires in %d days", cert.Domain, cert.DaysLeft),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		logger.Error("Failed to marshal webhook payload", "error", err)
		return
	}

	resp, err := http.Post(m.webhookURL, "application/json", nil)
	if err != nil {
		logger.Error("Failed to send webhook", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		logger.Error("Webhook returned error", "status", resp.StatusCode)
	}
}

// updateMetrics updates Prometheus metrics
func (m *Monitor) updateMetrics() {
	if !m.metricsEnabled {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Count certificates by status
	var expired, expiring, valid int
	var minDaysLeft = 365

	for _, cert := range m.certificates {
		if cert.IsExpired {
			expired++
		} else if cert.IsExpiring {
			expiring++
		} else {
			valid++
		}

		if cert.DaysLeft < minDaysLeft && !cert.IsExpired {
			minDaysLeft = cert.DaysLeft
		}
	}

	// Update metrics
	metrics.SetGauge("certificates_total", float64(len(m.certificates)))
	metrics.SetGauge("certificates_expired", float64(expired))
	metrics.SetGauge("certificates_expiring", float64(expiring))
	metrics.SetGauge("certificates_valid", float64(valid))
	metrics.SetGauge("certificate_min_days_left", float64(minDaysLeft))
}

// GetCertificates returns all monitored certificates
func (m *Monitor) GetCertificates() []*CertificateInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	certs := make([]*CertificateInfo, 0, len(m.certificates))
	for _, cert := range m.certificates {
		certs = append(certs, cert)
	}

	return certs
}

// GetCertificate returns information about a specific certificate
func (m *Monitor) GetCertificate(domain string) (*CertificateInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, ok := m.certificates[domain]
	return cert, ok
}

// RegisterAlertHandler registers a handler for certificate alerts
func (m *Monitor) RegisterAlertHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertHandlers = append(m.alertHandlers, handler)
}

// SetWebhookURL sets the webhook URL for alerts
func (m *Monitor) SetWebhookURL(url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webhookURL = url
}

// SetWarningDays sets the number of days before expiry to trigger a warning
func (m *Monitor) SetWarningDays(days int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.warningDays = days
}

// SetCriticalDays sets the number of days before expiry to trigger a critical alert
func (m *Monitor) SetCriticalDays(days int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.criticalDays = days
}

// ForceRenewal triggers a certificate renewal for the specified domain
func (m *Monitor) ForceRenewal(domain string) error {
	m.mu.RLock()
	cert, exists := m.certificates[domain]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("certificate not found for domain: %s", domain)
	}

	// Remove the certificate file to trigger renewal
	if err := os.Remove(cert.FilePath); err != nil {
		return fmt.Errorf("failed to remove certificate file: %w", err)
	}

	logger.Info("Certificate renewal triggered", "domain", domain)
	
	// Remove from cache
	m.mu.Lock()
	delete(m.certificates, domain)
	m.mu.Unlock()

	return nil
}

// GetExpiringCertificates returns certificates that are expiring within the specified days
func (m *Monitor) GetExpiringCertificates(days int) []*CertificateInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var expiring []*CertificateInfo
	for _, cert := range m.certificates {
		if cert.DaysLeft <= days && !cert.IsExpired {
			expiring = append(expiring, cert)
		}
	}

	return expiring
}

// GetExpiredCertificates returns all expired certificates
func (m *Monitor) GetExpiredCertificates() []*CertificateInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var expired []*CertificateInfo
	for _, cert := range m.certificates {
		if cert.IsExpired {
			expired = append(expired, cert)
		}
	}

	return expired
}

// GenerateReport generates a certificate status report
func (m *Monitor) GenerateReport() *Report {
	m.mu.RLock()
	defer m.mu.RUnlock()

	report := &Report{
		Timestamp:    time.Now(),
		TotalCerts:   len(m.certificates),
		Certificates: make([]*CertificateInfo, 0, len(m.certificates)),
	}

	for _, cert := range m.certificates {
		report.Certificates = append(report.Certificates, cert)
		
		if cert.IsExpired {
			report.ExpiredCount++
		} else if cert.DaysLeft <= m.criticalDays {
			report.CriticalCount++
		} else if cert.DaysLeft <= m.warningDays {
			report.WarningCount++
		} else {
			report.ValidCount++
		}
	}

	return report
}

// Report represents a certificate status report
type Report struct {
	Timestamp     time.Time          `json:"timestamp"`
	TotalCerts    int                `json:"total_certificates"`
	ValidCount    int                `json:"valid_count"`
	WarningCount  int                `json:"warning_count"`
	CriticalCount int                `json:"critical_count"`
	ExpiredCount  int                `json:"expired_count"`
	Certificates  []*CertificateInfo `json:"certificates"`
}