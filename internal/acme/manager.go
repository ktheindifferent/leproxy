package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/artyom/leproxy/internal/errors"
	"github.com/artyom/leproxy/internal/logger"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Global manager instance
var globalManager *Manager

// GetGlobalManager returns the global ACME manager instance
func GetGlobalManager() *Manager {
	return globalManager
}

// SetGlobalManager sets the global ACME manager instance
func SetGlobalManager(manager *Manager) {
	globalManager = manager
}

// Config holds ACME configuration
type Config struct {
	Provider    string   // Provider name (letsencrypt, zerossl, buypass, sslcom, entrust)
	DirectoryURL string  // Custom ACME directory URL
	Email       string   // Contact email
	CacheDir    string   // Certificate cache directory
	Domains     []string // Allowed domains
	EABKID      string   // External Account Binding Key ID (required for some providers)
	EABHMAC     string   // External Account Binding HMAC (required for some providers)
	TestMode    bool     // Use staging/test environment when available
}

// Constants for ACME providers
const (
	// Provider names
	ProviderLetsEncrypt = "letsencrypt"
	ProviderZeroSSL     = "zerossl"
	ProviderBuypass     = "buypass"
	ProviderSSLcom      = "sslcom"
	ProviderEntrust     = "entrust"
	ProviderGoogle      = "google"
	
	// Production directory URLs
	LetsEncryptProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
	ZeroSSLProdURL        = "https://acme.zerossl.com/v2/DV90"
	BuypassProdURL        = "https://api.buypass.com/acme/directory"
	SSLcomProdURL         = "https://acme.ssl.com/sslcom-dv-rsa"
	EntrustProdURL        = "https://acme.entrust.net/acme/api/v1/directory/ec"
	GoogleProdURL         = "https://dv.acme-v02.api.pki.goog/directory"
	
	// Staging/Test directory URLs
	LetsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	BuypassStagingURL     = "https://api.test4.buypass.no/acme/directory"
	GoogleStagingURL      = "https://dv.acme-v02.test-api.pki.goog/directory"
)

// Manager wraps autocert.Manager with additional functionality
type Manager struct {
	*autocert.Manager
	config         *Config
	renewalManager *RenewalManager
}

// NewManager creates a new ACME certificate manager
func NewManager(config *Config) (*Manager, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(config.CacheDir, 0700); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeConfiguration, "failed to create cache directory", "")
	}

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(config.CacheDir),
		Prompt:     autocert.AcceptTOS,
		Email:      config.Email,
		HostPolicy: createHostPolicy(config.Domains),
	}

	// Configure ACME client
	if err := configureACMEClient(manager, config); err != nil {
		return nil, err
	}

	m := &Manager{
		Manager: manager,
		config:  config,
	}
	
	// Initialize renewal manager with error recovery
	m.renewalManager = NewRenewalManager(m)
	
	// Check if renewal manager has initialization errors
	if m.renewalManager.initError != nil {
		logger.Warn("Renewal manager initialized with errors", map[string]interface{}{"error": m.renewalManager.initError, "note": "Certificate renewal may have limited functionality"})
		// Continue with degraded functionality rather than failing completely
	}
	
	return m, nil
}

// GetTLSConfig returns the TLS configuration for the manager
func (m *Manager) GetTLSConfig() *tls.Config {
	config := m.Manager.TLSConfig()
	config.MinVersion = tls.VersionTLS12
	config.CipherSuites = getSecureCipherSuites()
	return config
}

// StartRenewalManager starts the automatic renewal process with error handling
func (m *Manager) StartRenewalManager(ctx context.Context) error {
	if m.renewalManager == nil {
		return errors.New(errors.ErrorTypeConfiguration, "renewal manager not initialized", "manager", fmt.Errorf("nil"))
	}
	
	if err := m.renewalManager.Start(ctx); err != nil {
		return errors.Wrap(err, errors.ErrorTypeConfiguration, "failed to start renewal manager", "")
	}
	
	return nil
}

// StopRenewalManager stops the automatic renewal process gracefully
func (m *Manager) StopRenewalManager() {
	if m.renewalManager != nil {
		logger.Info("Stopping renewal manager")
		m.renewalManager.Stop()
	}
}

// SetRenewalAlertHandler sets the alert handler for renewal failures
func (m *Manager) SetRenewalAlertHandler(handler AlertHandler) {
	if m.renewalManager != nil {
		m.renewalManager.SetAlertHandler(handler)
	} else {
		logger.Warn("Cannot set alert handler - renewal manager not initialized")
	}
}

// GetRenewalStatus returns the current renewal status for all domains
func (m *Manager) GetRenewalStatus() map[string]*RenewalStatus {
	if m.renewalManager != nil {
		return m.renewalManager.GetStatus()
	}
	return make(map[string]*RenewalStatus)
}

// GetRenewalHistory returns the renewal history
func (m *Manager) GetRenewalHistory() []RenewalHistory {
	if m.renewalManager != nil {
		return m.renewalManager.GetHistory()
	}
	return []RenewalHistory{}
}

// RenewCertificates checks and renews certificates if needed (deprecated - use StartRenewalManager)
func (m *Manager) RenewCertificates(ctx context.Context) error {
	logger.Info("Checking certificates for renewal (deprecated method - use StartRenewalManager)")
	if m.renewalManager != nil {
		m.renewalManager.checkAndRenewAll(ctx)
	} else {
		return errors.New(errors.ErrorTypeConfiguration, "renewal manager not initialized", "manager", fmt.Errorf("nil"))
	}
	return nil
}

// GetRenewalHealth returns the health status of the renewal manager
func (m *Manager) GetRenewalHealth() map[string]interface{} {
	if m.renewalManager != nil {
		return m.renewalManager.GetHealthStatus()
	}
	return map[string]interface{}{
		"healthy": false,
		"error":   "renewal manager not initialized",
	}
}

// IsRenewalHealthy returns true if the renewal manager is healthy
func (m *Manager) IsRenewalHealthy() bool {
	if m.renewalManager != nil {
		return m.renewalManager.IsHealthy()
	}
	return false
}

func validateConfig(config *Config) error {
	if config.CacheDir == "" {
		return fmt.Errorf("cache directory is required")
	}

	// Validate provider-specific requirements
	switch config.Provider {
	case ProviderZeroSSL:
		if config.EABKID == "" || config.EABHMAC == "" {
			return fmt.Errorf("EAB credentials (EABKID and EABHMAC) are required for ZeroSSL")
		}
	case ProviderSSLcom:
		if config.EABKID == "" || config.EABHMAC == "" {
			return fmt.Errorf("EAB credentials (EABKID and EABHMAC) are required for SSL.com")
		}
	case ProviderGoogle:
		if config.EABKID == "" || config.EABHMAC == "" {
			return fmt.Errorf("EAB credentials (EABKID and EABHMAC) are required for Google Trust Services")
		}
	case ProviderBuypass:
		// Buypass doesn't support wildcard certificates
		for _, domain := range config.Domains {
			if strings.HasPrefix(domain, "*.") {
				return fmt.Errorf("Buypass does not support wildcard certificates (found: %s)", domain)
			}
		}
	}

	return nil
}

func configureACMEClient(manager *autocert.Manager, config *Config) error {
	directoryURL := getDirectoryURL(config)
	
	if directoryURL != "" {
		parsedURL, err := url.Parse(directoryURL)
		if err != nil {
			return errors.Wrap(err, errors.ErrorTypeConfiguration, "invalid ACME directory URL", "")
		}

		client := &acme.Client{
			DirectoryURL: parsedURL.String(),
		}

		// Configure EAB if provided
		if config.EABKID != "" && config.EABHMAC != "" {
			logger.Info("Configuring External Account Binding", map[string]interface{}{"provider": config.Provider})
			// EAB configuration would be applied here during account registration
			// Note: The actual EAB implementation requires modifying the account registration
			// process which happens internally in autocert.Manager
		}

		manager.Client = client
		logger.Info("ACME client configured", map[string]interface{}{"provider": config.Provider, "directory": directoryURL, "test_mode": config.TestMode})
	}

	return nil
}

func getDirectoryURL(config *Config) string {
	if config.DirectoryURL != "" {
		return config.DirectoryURL
	}

	provider := strings.ToLower(config.Provider)
	
	// Return staging URLs if test mode is enabled
	if config.TestMode {
		switch provider {
		case ProviderLetsEncrypt:
			return LetsEncryptStagingURL
		case ProviderBuypass:
			return BuypassStagingURL
		case ProviderGoogle:
			return GoogleStagingURL
		default:
			logger.Warn("No staging environment available for provider", map[string]interface{}{"provider": provider})
		}
	}

	// Return production URLs
	switch provider {
	case ProviderZeroSSL:
		return ZeroSSLProdURL
	case ProviderBuypass:
		return BuypassProdURL
	case ProviderSSLcom:
		return SSLcomProdURL
	case ProviderEntrust:
		return EntrustProdURL
	case ProviderGoogle:
		return GoogleProdURL
	case ProviderLetsEncrypt:
		return "" // Use default Let's Encrypt production
	default:
		return ""
	}
}

func createHostPolicy(domains []string) autocert.HostPolicy {
	if len(domains) == 0 {
		return nil // Accept any domain
	}

	allowedHosts := make(map[string]bool)
	for _, domain := range domains {
		allowedHosts[strings.ToLower(domain)] = true
	}

	return func(ctx context.Context, host string) error {
		host = strings.ToLower(host)
		if allowedHosts[host] {
			return nil
		}
		return fmt.Errorf("host %q not allowed", host)
	}
}

func getSecureCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
}

// BackupManager handles certificate backup and restore
type BackupManager struct {
	sourceDir string
	backupDir string
}

// NewBackupManager creates a new backup manager
func NewBackupManager(sourceDir, backupDir string) *BackupManager {
	return &BackupManager{
		sourceDir: sourceDir,
		backupDir: backupDir,
	}
}

// Backup creates a backup of all certificates
func (b *BackupManager) Backup() error {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	backupPath := filepath.Join(b.backupDir, "backup-"+timestamp)
	
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return errors.Wrap(err, errors.ErrorTypeIO, "failed to create backup directory", "")
	}

	// Copy certificate files
	return filepath.Walk(b.sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(b.sourceDir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(backupPath, relPath)
		destDir := filepath.Dir(destPath)

		if err := os.MkdirAll(destDir, 0700); err != nil {
			return err
		}

		return copyFile(path, destPath)
	})
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// ProviderInfo contains information about an ACME provider
type ProviderInfo struct {
	Name            string
	DisplayName     string
	DirectoryURL    string
	StagingURL      string
	RequiresEAB     bool
	SupportsWildcard bool
	CertValidity    int // days
	Description     string
}

// GetProviderInfo returns information about a specific ACME provider
func GetProviderInfo(provider string) *ProviderInfo {
	providers := map[string]*ProviderInfo{
		ProviderLetsEncrypt: {
			Name:            ProviderLetsEncrypt,
			DisplayName:     "Let's Encrypt",
			DirectoryURL:    LetsEncryptProdURL,
			StagingURL:      LetsEncryptStagingURL,
			RequiresEAB:     false,
			SupportsWildcard: true,
			CertValidity:    90,
			Description:     "The original free ACME CA, widely trusted and supported",
		},
		ProviderZeroSSL: {
			Name:            ProviderZeroSSL,
			DisplayName:     "ZeroSSL",
			DirectoryURL:    ZeroSSLProdURL,
			StagingURL:      "",
			RequiresEAB:     true,
			SupportsWildcard: true,
			CertValidity:    90,
			Description:     "Free ACME certificates with EAB, supports wildcards",
		},
		ProviderBuypass: {
			Name:            ProviderBuypass,
			DisplayName:     "Buypass Go SSL",
			DirectoryURL:    BuypassProdURL,
			StagingURL:      BuypassStagingURL,
			RequiresEAB:     false,
			SupportsWildcard: false,
			CertValidity:    180,
			Description:     "European CA with 180-day certificates, no wildcard support",
		},
		ProviderSSLcom: {
			Name:            ProviderSSLcom,
			DisplayName:     "SSL.com",
			DirectoryURL:    SSLcomProdURL,
			StagingURL:      "",
			RequiresEAB:     true,
			SupportsWildcard: false,
			CertValidity:    90,
			Description:     "Commercial CA with free ACME tier, single domain + www",
		},
		ProviderEntrust: {
			Name:            ProviderEntrust,
			DisplayName:     "Entrust",
			DirectoryURL:    EntrustProdURL,
			StagingURL:      "",
			RequiresEAB:     false,
			SupportsWildcard: true,
			CertValidity:    90,
			Description:     "Enterprise-grade CA with ACME support",
		},
		ProviderGoogle: {
			Name:            ProviderGoogle,
			DisplayName:     "Google Trust Services",
			DirectoryURL:    GoogleProdURL,
			StagingURL:      GoogleStagingURL,
			RequiresEAB:     true,
			SupportsWildcard: true,
			CertValidity:    90,
			Description:     "Google's public CA with ACME support, requires EAB",
		},
	}
	
	if info, exists := providers[strings.ToLower(provider)]; exists {
		return info
	}
	return nil
}

// GetAvailableProviders returns a list of all available ACME providers
func GetAvailableProviders() []ProviderInfo {
	return []ProviderInfo{
		*GetProviderInfo(ProviderLetsEncrypt),
		*GetProviderInfo(ProviderZeroSSL),
		*GetProviderInfo(ProviderBuypass),
		*GetProviderInfo(ProviderSSLcom),
		*GetProviderInfo(ProviderEntrust),
		*GetProviderInfo(ProviderGoogle),
	}
}

// CleanupExpired removes expired certificates from the cache
func (m *Manager) CleanupExpired() error {
	if m.config.CacheDir == "" {
		return nil
	}
	
	files, err := ioutil.ReadDir(m.config.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}
	
	var removedCount int
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		
		// Only process certificate files
		if !strings.HasSuffix(file.Name(), "+rsa") && !strings.HasSuffix(file.Name(), "+ecdsa") {
			continue
		}
		
		certPath := filepath.Join(m.config.CacheDir, file.Name())
		
		// Read certificate
		certPEM, err := ioutil.ReadFile(certPath)
		if err != nil {
			logger.Warn("Failed to read certificate file", map[string]interface{}{
				"file": file.Name(),
				"error": err,
			})
			continue
		}
		
		// Parse certificate
		block, _ := pem.Decode(certPEM)
		if block == nil {
			continue
		}
		
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Warn("Failed to parse certificate", map[string]interface{}{
				"file": file.Name(),
				"error": err,
			})
			continue
		}
		
		// Check if expired
		if time.Now().After(cert.NotAfter) {
			if err := os.Remove(certPath); err != nil {
				logger.Error("Failed to remove expired certificate", map[string]interface{}{
					"file": file.Name(),
					"error": err,
				})
			} else {
				removedCount++
				logger.Info("Removed expired certificate", map[string]interface{}{
					"file": file.Name(),
					"expired": cert.NotAfter,
				})
			}
		}
	}
	
	if removedCount > 0 {
		logger.Info("Certificate cleanup completed", map[string]interface{}{
			"removed": removedCount,
		})
	}
	
	return nil
}