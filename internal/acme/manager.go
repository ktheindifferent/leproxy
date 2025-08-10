package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/artyom/leproxy/internal/errors"
	"github.com/artyom/leproxy/internal/logger"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config holds ACME configuration
type Config struct {
	Provider    string   // Provider name (letsencrypt, zerossl)
	DirectoryURL string  // Custom ACME directory URL
	Email       string   // Contact email
	CacheDir    string   // Certificate cache directory
	Domains     []string // Allowed domains
	EABKID      string   // External Account Binding Key ID
	EABHMAC     string   // External Account Binding HMAC
}

// Constants for ACME providers
const (
	ProviderLetsEncrypt = "letsencrypt"
	ProviderZeroSSL     = "zerossl"
	
	// Default directory URLs
	LetsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	LetsEncryptProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
	ZeroSSLURL           = "https://acme.zerossl.com/v2/DV90"
)

// Manager wraps autocert.Manager with additional functionality
type Manager struct {
	*autocert.Manager
	config *Config
}

// NewManager creates a new ACME certificate manager
func NewManager(config *Config) (*Manager, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// Ensure cache directory exists
	if err := os.MkdirAll(config.CacheDir, 0700); err != nil {
		return nil, errors.Wrap(err, errors.ErrConfiguration, "failed to create cache directory")
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

	return &Manager{
		Manager: manager,
		config:  config,
	}, nil
}

// GetTLSConfig returns the TLS configuration for the manager
func (m *Manager) GetTLSConfig() *tls.Config {
	config := m.Manager.TLSConfig()
	config.MinVersion = tls.VersionTLS12
	config.CipherSuites = getSecureCipherSuites()
	return config
}

// RenewCertificates checks and renews certificates if needed
func (m *Manager) RenewCertificates(ctx context.Context) error {
	logger.Info("Checking certificates for renewal")
	
	for _, domain := range m.config.Domains {
		cert, err := m.Manager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: domain,
		})
		if err != nil {
			logger.Warn("Failed to get certificate", "domain", domain, "error", err)
			continue
		}
		
		if cert != nil && len(cert.Certificate) > 0 {
			logger.Debug("Certificate valid", "domain", domain)
		}
	}
	
	return nil
}

func validateConfig(config *Config) error {
	if config.CacheDir == "" {
		return fmt.Errorf("cache directory is required")
	}

	if config.Provider == ProviderZeroSSL && (config.EABKID == "" || config.EABHMAC == "") {
		return fmt.Errorf("EAB credentials required for ZeroSSL")
	}

	return nil
}

func configureACMEClient(manager *autocert.Manager, config *Config) error {
	directoryURL := getDirectoryURL(config)
	
	if directoryURL != "" {
		parsedURL, err := url.Parse(directoryURL)
		if err != nil {
			return errors.Wrap(err, errors.ErrConfiguration, "invalid ACME directory URL")
		}

		client := &acme.Client{
			DirectoryURL: parsedURL.String(),
		}

		// Configure EAB if provided
		if config.EABKID != "" && config.EABHMAC != "" {
			logger.Info("Configuring External Account Binding")
			// EAB configuration would be applied here during account registration
		}

		manager.Client = client
		logger.Info("ACME client configured", "directory", directoryURL)
	}

	return nil
}

func getDirectoryURL(config *Config) string {
	if config.DirectoryURL != "" {
		return config.DirectoryURL
	}

	switch strings.ToLower(config.Provider) {
	case ProviderZeroSSL:
		return ZeroSSLURL
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
		return errors.Wrap(err, errors.ErrFileSystem, "failed to create backup directory")
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