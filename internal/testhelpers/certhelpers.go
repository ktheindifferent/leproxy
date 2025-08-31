package testhelpers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// CreateTestCertificate creates a self-signed certificate for testing
func CreateTestCertificate(t *testing.T, hostname string, validDays int) (certPEM, keyPEM []byte) {
	t.Helper()
	
	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	
	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}
	
	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	
	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	
	// Encode private key to PEM
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	
	return certPEM, keyPEM
}

// WriteCorruptedCertFiles writes corrupted certificate and key files for testing error handling
func WriteCorruptedCertFiles(t *testing.T, certPath, keyPath string) {
	t.Helper()
	
	corruptedCert := []byte("-----BEGIN CERTIFICATE-----\nincomplete and corrupted data\n")
	corruptedKey := []byte("-----BEGIN RSA PRIVATE KEY-----\nincomplete and corrupted data\n")
	
	WriteFile(t, certPath, corruptedCert, 0644)
	WriteFile(t, keyPath, corruptedKey, 0600)
}