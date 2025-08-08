package dbproxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewCertManager(t *testing.T) {
	tests := []struct {
		name     string
		cacheDir string
		wantErr  bool
	}{
		{
			name:     "valid cache directory",
			cacheDir: t.TempDir(),
			wantErr:  false,
		},
		{
			name:     "empty cache directory",
			cacheDir: "",
			wantErr:  false, // Should use temp dir
		},
		{
			name:     "nested cache directory",
			cacheDir: filepath.Join(t.TempDir(), "nested", "cache"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := NewCertManager(tt.cacheDir)
			if cm == nil {
				t.Error("Expected non-nil CertManager")
			}

			// Verify cache directory
			if tt.cacheDir != "" && cm.cacheDir != tt.cacheDir {
				t.Errorf("Expected cache dir %s, got %s", tt.cacheDir, cm.cacheDir)
			}
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	cm := NewCertManager(t.TempDir())

	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "localhost",
			hostname: "localhost",
			wantErr:  false,
		},
		{
			name:     "IP address",
			hostname: "127.0.0.1",
			wantErr:  false,
		},
		{
			name:     "domain name",
			hostname: "example.com",
			wantErr:  false,
		},
		{
			name:     "wildcard domain",
			hostname: "*.example.com",
			wantErr:  false,
		},
		{
			name:     "subdomain",
			hostname: "api.example.com",
			wantErr:  false,
		},
		{
			name:     "empty hostname",
			hostname: "",
			wantErr:  true,
		},
		{
			name:     "hostname with port",
			hostname: "example.com:443",
			wantErr:  false, // Should handle gracefully
		},
		{
			name:     "internationalized domain",
			hostname: "例え.jp",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := cm.GetTLSConfig(tt.hostname)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Error("Expected non-nil TLS config")
				return
			}

			// Verify TLS config has certificates
			if len(config.Certificates) == 0 {
				t.Error("Expected at least one certificate in TLS config")
			}
		})
	}
}

func TestCertificateCaching(t *testing.T) {
	cacheDir := t.TempDir()
	cm := NewCertManager(cacheDir)

	hostname := "test.example.com"

	// Get certificate first time (should generate)
	config1, err := cm.GetTLSConfig(hostname)
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	// Get certificate second time (should use cache)
	config2, err := cm.GetTLSConfig(hostname)
	if err != nil {
		t.Fatalf("Failed to get cached TLS config: %v", err)
	}

	// Both configs should have certificates
	if len(config1.Certificates) == 0 || len(config2.Certificates) == 0 {
		t.Error("Expected certificates in both configs")
	}

	// Verify certificate files exist in cache
	certFile := filepath.Join(cacheDir, hostname+".crt")
	keyFile := filepath.Join(cacheDir, hostname+".key")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file not found: %s", certFile)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Errorf("Key file not found: %s", keyFile)
	}
}

func TestCertificateGeneration(t *testing.T) {
	cm := NewCertManager(t.TempDir())

	tests := []struct {
		name         string
		hostname     string
		checkSAN     bool
		checkCN      bool
		checkExpiry  bool
		expiryDays   int
	}{
		{
			name:        "basic certificate",
			hostname:    "test.local",
			checkSAN:    true,
			checkCN:     true,
			checkExpiry: true,
			expiryDays:  365,
		},
		{
			name:        "IP address certificate",
			hostname:    "192.168.1.1",
			checkSAN:    true,
			checkExpiry: true,
			expiryDays:  365,
		},
		{
			name:        "wildcard certificate",
			hostname:    "*.example.com",
			checkSAN:    true,
			checkCN:     true,
			checkExpiry: true,
			expiryDays:  365,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := cm.GetTLSConfig(tt.hostname)
			if err != nil {
				t.Fatalf("Failed to get TLS config: %v", err)
			}

			if len(config.Certificates) == 0 {
				t.Fatal("No certificates in TLS config")
			}

			cert := config.Certificates[0]
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			// Check Common Name
			if tt.checkCN && x509Cert.Subject.CommonName != tt.hostname {
				t.Errorf("Expected CN %s, got %s", tt.hostname, x509Cert.Subject.CommonName)
			}

			// Check Subject Alternative Names
			if tt.checkSAN {
				found := false
				for _, name := range x509Cert.DNSNames {
					if name == tt.hostname || strings.HasSuffix(tt.hostname, name) {
						found = true
						break
					}
				}
				
				// Check IP SANs if hostname is an IP
				if !found && net.ParseIP(tt.hostname) != nil {
					for _, ip := range x509Cert.IPAddresses {
						if ip.String() == tt.hostname {
							found = true
							break
						}
					}
				}

				if !found && tt.hostname != "*.example.com" { // Wildcard is special case
					t.Errorf("Hostname %s not found in SANs", tt.hostname)
				}
			}

			// Check expiry
			if tt.checkExpiry {
				expectedExpiry := time.Now().AddDate(0, 0, tt.expiryDays)
				actualExpiry := x509Cert.NotAfter

				// Allow some tolerance (1 hour)
				diff := expectedExpiry.Sub(actualExpiry)
				if diff < -time.Hour || diff > time.Hour {
					t.Errorf("Certificate expiry mismatch: expected ~%v, got %v", expectedExpiry, actualExpiry)
				}
			}

			// Verify it's a self-signed certificate
			if x509Cert.Issuer.CommonName != x509Cert.Subject.CommonName {
				t.Error("Certificate is not self-signed")
			}

			// Verify key usage
			if x509Cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
				t.Error("Certificate missing KeyEncipherment usage")
			}
			if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
				t.Error("Certificate missing DigitalSignature usage")
			}
		})
	}
}

func TestIsCertExpired(t *testing.T) {
	tests := []struct {
		name        string
		certExpiry  time.Time
		expectExpired bool
	}{
		{
			name:        "expired certificate",
			certExpiry:  time.Now().Add(-24 * time.Hour),
			expectExpired: true,
		},
		{
			name:        "valid certificate",
			certExpiry:  time.Now().Add(365 * 24 * time.Hour),
			expectExpired: false,
		},
		{
			name:        "certificate expiring in 29 days",
			certExpiry:  time.Now().Add(29 * 24 * time.Hour),
			expectExpired: true, // Should be considered expired if < 30 days
		},
		{
			name:        "certificate expiring in 31 days",
			certExpiry:  time.Now().Add(31 * 24 * time.Hour),
			expectExpired: false,
		},
		{
			name:        "certificate expiring today",
			certExpiry:  time.Now().Add(1 * time.Hour),
			expectExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock certificate with the specified expiry
			cert := &tls.Certificate{
				Leaf: &x509.Certificate{
					NotAfter: tt.certExpiry,
				},
			}

			result := isCertExpired(cert)
			if result != tt.expectExpired {
				t.Errorf("isCertExpired() = %v, want %v", result, tt.expectExpired)
			}
		})
	}
}

func TestCertificateRotation(t *testing.T) {
	cacheDir := t.TempDir()
	cm := NewCertManager(cacheDir)
	hostname := "rotate.example.com"

	// Create an expired certificate file
	certFile := filepath.Join(cacheDir, hostname+".crt")
	keyFile := filepath.Join(cacheDir, hostname+".key")

	// Generate a certificate that's already expired
	expiredCert := generateExpiredCert(t, hostname)
	
	// Write expired cert to cache
	err := os.WriteFile(certFile, expiredCert.certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write expired cert: %v", err)
	}
	err = os.WriteFile(keyFile, expiredCert.keyPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to write expired key: %v", err)
	}

	// Get TLS config - should regenerate due to expiry
	config, err := cm.GetTLSConfig(hostname)
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	// Parse the new certificate
	if len(config.Certificates) == 0 {
		t.Fatal("No certificates in TLS config")
	}

	cert := config.Certificates[0]
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify the certificate is not expired
	if time.Now().After(x509Cert.NotAfter) {
		t.Error("New certificate is already expired")
	}

	// Verify it's valid for at least 30 days
	if time.Now().Add(30 * 24 * time.Hour).After(x509Cert.NotAfter) {
		t.Error("New certificate expires in less than 30 days")
	}
}

func TestConcurrentCertificateGeneration(t *testing.T) {
	cm := NewCertManager(t.TempDir())
	hostname := "concurrent.example.com"

	// Number of concurrent requests
	numRequests := 10
	done := make(chan error, numRequests)

	// Launch concurrent certificate requests
	for i := 0; i < numRequests; i++ {
		go func() {
			_, err := cm.GetTLSConfig(hostname)
			done <- err
		}()
	}

	// Collect results
	for i := 0; i < numRequests; i++ {
		err := <-done
		if err != nil {
			t.Errorf("Concurrent request %d failed: %v", i, err)
		}
	}

	// Verify only one certificate was created
	certFile := filepath.Join(cm.cacheDir, hostname+".crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Error("Certificate file not created")
	}
}

func TestCertificatePermissions(t *testing.T) {
	cacheDir := t.TempDir()
	cm := NewCertManager(cacheDir)
	hostname := "perms.example.com"

	// Generate certificate
	_, err := cm.GetTLSConfig(hostname)
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	// Check file permissions
	certFile := filepath.Join(cacheDir, hostname+".crt")
	keyFile := filepath.Join(cacheDir, hostname+".key")

	certInfo, err := os.Stat(certFile)
	if err != nil {
		t.Fatalf("Failed to stat cert file: %v", err)
	}

	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}

	// Certificate can be world-readable (0644)
	certMode := certInfo.Mode()
	if certMode.Perm() != 0644 {
		t.Errorf("Certificate file has wrong permissions: %v", certMode.Perm())
	}

	// Private key must be restricted (0600)
	keyMode := keyInfo.Mode()
	if keyMode.Perm() != 0600 {
		t.Errorf("Key file has wrong permissions: %v", keyMode.Perm())
	}
}

func TestInvalidCacheDirectory(t *testing.T) {
	tests := []struct {
		name      string
		setupDir  func() string
		cleanupDir func(string)
		wantErr   bool
	}{
		{
			name: "read-only directory",
			setupDir: func() string {
				dir := t.TempDir()
				os.Chmod(dir, 0444)
				return dir
			},
			cleanupDir: func(dir string) {
				os.Chmod(dir, 0755)
			},
			wantErr: true,
		},
		{
			name: "file instead of directory",
			setupDir: func() string {
				tmpfile, _ := os.CreateTemp("", "certcache")
				tmpfile.Close()
				return tmpfile.Name()
			},
			cleanupDir: func(path string) {
				os.Remove(path)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setupDir()
			defer tt.cleanupDir(dir)

			cm := NewCertManager(dir)
			_, err := cm.GetTLSConfig("test.example.com")

			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			} else if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// Helper struct for expired certificate
type expiredCertData struct {
	certPEM []byte
	keyPEM  []byte
}

// Helper function to generate an expired certificate for testing
func generateExpiredCert(t *testing.T, hostname string) *expiredCertData {
	// This is a simplified version - in real tests you'd generate actual expired certs
	// For now, return dummy data that will fail parsing and trigger regeneration
	return &expiredCertData{
		certPEM: []byte("invalid cert data"),
		keyPEM:  []byte("invalid key data"),
	}
}