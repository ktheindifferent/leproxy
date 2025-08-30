package dbproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CertManager struct {
	CacheDir string
}

func NewCertManager(cacheDir string) *CertManager {
	return &CertManager{
		CacheDir: cacheDir,
	}
}

func (cm *CertManager) GetOrCreateCert(hostname string) (*tls.Certificate, error) {
	certPath := filepath.Join(cm.CacheDir, fmt.Sprintf("%s.crt", hostname))
	keyPath := filepath.Join(cm.CacheDir, fmt.Sprintf("%s.key", hostname))

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				if !isCertExpired(&cert) {
					return &cert, nil
				}
			}
		}
	}

	return cm.generateCert(hostname, certPath, keyPath)
}

func (cm *CertManager) generateCert(hostname, certPath, keyPath string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"DB Proxy Auto-Generated"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	if err := os.MkdirAll(cm.CacheDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Use atomic file operations with temporary files
	tempCertPath := certPath + ".tmp"
	tempKeyPath := keyPath + ".tmp"
	
	// Cleanup function for error cases
	cleanup := func() {
		os.Remove(tempCertPath)
		os.Remove(tempKeyPath)
	}

	// Write certificate to temporary file
	certOut, err := os.OpenFile(tempCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp cert file: %w", err)
	}
	
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		certOut.Close()
		cleanup()
		return nil, fmt.Errorf("failed to write certificate: %w", err)
	}
	
	// Ensure data is written to disk
	if err := certOut.Sync(); err != nil {
		certOut.Close()
		cleanup()
		return nil, fmt.Errorf("failed to sync cert file: %w", err)
	}
	
	if err := certOut.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to close cert file: %w", err)
	}

	// Write private key to temporary file
	keyOut, err := os.OpenFile(tempKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create temp key file: %w", err)
	}

	privKeyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		keyOut.Close()
		cleanup()
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyDER}); err != nil {
		keyOut.Close()
		cleanup()
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}
	
	// Ensure data is written to disk
	if err := keyOut.Sync(); err != nil {
		keyOut.Close()
		cleanup()
		return nil, fmt.Errorf("failed to sync key file: %w", err)
	}
	
	if err := keyOut.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to close key file: %w", err)
	}

	// Atomic rename operations
	if err := os.Rename(tempCertPath, certPath); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to rename cert file: %w", err)
	}
	
	if err := os.Rename(tempKeyPath, keyPath); err != nil {
		// Try to restore cert file since key rename failed
		os.Remove(certPath)
		cleanup()
		return nil, fmt.Errorf("failed to rename key file: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load generated certificate: %w", err)
	}

	return &cert, nil
}

func isCertExpired(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return true
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}

	return time.Now().After(x509Cert.NotAfter) || time.Now().Before(x509Cert.NotBefore)
}

func (cm *CertManager) GetTLSConfig(hostname string) (*tls.Config, error) {
	cert, err := cm.GetOrCreateCert(hostname)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}