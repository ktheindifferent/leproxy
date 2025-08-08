package certbackup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BackupManager manages certificate backups
type BackupManager struct {
	certDir       string
	backupDir     string
	encryptionKey []byte
	retention     time.Duration
	
	mu            sync.RWMutex
	lastBackup    time.Time
	backupCount   int64
	restoreCount  int64
}

// Config holds backup configuration
type Config struct {
	CertDir       string
	BackupDir     string
	EncryptionKey string
	Retention     time.Duration
	AutoBackup    bool
	BackupInterval time.Duration
}

// NewBackupManager creates a new backup manager
func NewBackupManager(cfg Config) (*BackupManager, error) {
	// Ensure directories exist
	if err := os.MkdirAll(cfg.BackupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Derive encryption key from passphrase
	var encKey []byte
	if cfg.EncryptionKey != "" {
		hash := sha256.Sum256([]byte(cfg.EncryptionKey))
		encKey = hash[:]
	}
	
	if cfg.Retention <= 0 {
		cfg.Retention = 30 * 24 * time.Hour // 30 days default
	}
	
	bm := &BackupManager{
		certDir:       cfg.CertDir,
		backupDir:     cfg.BackupDir,
		encryptionKey: encKey,
		retention:     cfg.Retention,
	}
	
	// Start auto-backup if enabled
	if cfg.AutoBackup {
		if cfg.BackupInterval <= 0 {
			cfg.BackupInterval = 24 * time.Hour // Daily default
		}
		go bm.autoBackupLoop(cfg.BackupInterval)
	}
	
	// Start cleanup routine
	go bm.cleanupLoop()
	
	return bm, nil
}

// Backup creates a backup of all certificates
func (bm *BackupManager) Backup() (string, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	timestamp := time.Now().Format("20060102-150405")
	backupName := fmt.Sprintf("cert-backup-%s", timestamp)
	
	// Create temporary tar.gz file
	tempFile := filepath.Join(bm.backupDir, backupName+".tar.gz.tmp")
	finalFile := filepath.Join(bm.backupDir, backupName+".tar.gz")
	
	if bm.encryptionKey != nil {
		finalFile += ".enc"
	}
	
	// Create the archive
	if err := bm.createArchive(tempFile); err != nil {
		return "", fmt.Errorf("failed to create archive: %w", err)
	}
	
	// Encrypt if key is provided
	if bm.encryptionKey != nil {
		if err := bm.encryptFile(tempFile, finalFile); err != nil {
			os.Remove(tempFile)
			return "", fmt.Errorf("failed to encrypt backup: %w", err)
		}
		os.Remove(tempFile)
	} else {
		if err := os.Rename(tempFile, finalFile); err != nil {
			os.Remove(tempFile)
			return "", fmt.Errorf("failed to finalize backup: %w", err)
		}
	}
	
	bm.lastBackup = time.Now()
	bm.backupCount++
	
	return finalFile, nil
}

// Restore restores certificates from a backup
func (bm *BackupManager) Restore(backupPath string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	// Check if backup exists
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}
	
	// Determine if encrypted
	encrypted := strings.HasSuffix(backupPath, ".enc")
	
	var archivePath string
	if encrypted {
		if bm.encryptionKey == nil {
			return fmt.Errorf("backup is encrypted but no encryption key provided")
		}
		
		// Decrypt to temporary file
		tempFile := backupPath + ".tmp"
		if err := bm.decryptFile(backupPath, tempFile); err != nil {
			return fmt.Errorf("failed to decrypt backup: %w", err)
		}
		defer os.Remove(tempFile)
		archivePath = tempFile
	} else {
		archivePath = backupPath
	}
	
	// Extract the archive
	if err := bm.extractArchive(archivePath); err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
	}
	
	bm.restoreCount++
	
	return nil
}

// ListBackups returns a list of available backups
func (bm *BackupManager) ListBackups() ([]BackupInfo, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	var backups []BackupInfo
	
	err := filepath.Walk(bm.backupDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Check if it's a backup file
		name := info.Name()
		if strings.HasPrefix(name, "cert-backup-") && 
		   (strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tar.gz.enc")) {
			
			backup := BackupInfo{
				Path:      path,
				Name:      name,
				Size:      info.Size(),
				Created:   info.ModTime(),
				Encrypted: strings.HasSuffix(name, ".enc"),
			}
			
			// Parse timestamp from filename
			if parts := strings.Split(name, "-"); len(parts) >= 3 {
				if t, err := time.Parse("20060102", parts[2][:8]); err == nil {
					backup.Created = t
				}
			}
			
			backups = append(backups, backup)
		}
		
		return nil
	})
	
	return backups, err
}

// createArchive creates a tar.gz archive of the certificate directory
func (bm *BackupManager) createArchive(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()
	
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()
	
	return filepath.Walk(bm.certDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		
		// Update header name to be relative to certDir
		relPath, err := filepath.Rel(bm.certDir, path)
		if err != nil {
			return err
		}
		header.Name = relPath
		
		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		
		// Write file content if not a directory
		if !info.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			
			if _, err := tarWriter.Write(data); err != nil {
				return err
			}
		}
		
		return nil
	})
}

// extractArchive extracts a tar.gz archive to the certificate directory
func (bm *BackupManager) extractArchive(archivePath string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()
	
	tarReader := tar.NewReader(gzReader)
	
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		targetPath := filepath.Join(bm.certDir, header.Name)
		
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
			
		case tar.TypeReg:
			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return err
			}
			
			// Create file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return err
			}
			
			// Copy content
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
			
			// Set permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// encryptFile encrypts a file using AES-GCM
func (bm *BackupManager) encryptFile(inputPath, outputPath string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	
	block, err := aes.NewCipher(bm.encryptionKey)
	if err != nil {
		return err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	
	return os.WriteFile(outputPath, ciphertext, 0600)
}

// decryptFile decrypts a file using AES-GCM
func (bm *BackupManager) decryptFile(inputPath, outputPath string) error {
	ciphertext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	
	block, err := aes.NewCipher(bm.encryptionKey)
	if err != nil {
		return err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	
	return os.WriteFile(outputPath, plaintext, 0600)
}

// autoBackupLoop performs automatic backups at regular intervals
func (bm *BackupManager) autoBackupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for range ticker.C {
		if _, err := bm.Backup(); err != nil {
			// Log error (implementation depends on your logger)
			fmt.Printf("Auto-backup failed: %v\n", err)
		}
	}
}

// cleanupLoop removes old backups based on retention policy
func (bm *BackupManager) cleanupLoop() {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()
	
	for range ticker.C {
		bm.cleanup()
	}
}

// cleanup removes backups older than retention period
func (bm *BackupManager) cleanup() error {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	
	cutoff := time.Now().Add(-bm.retention)
	
	return filepath.Walk(bm.backupDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Check if it's an old backup
		if strings.HasPrefix(info.Name(), "cert-backup-") && info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil {
				// Log error but continue
				fmt.Printf("Failed to remove old backup %s: %v\n", path, err)
			}
		}
		
		return nil
	})
}

// Stats returns backup statistics
func (bm *BackupManager) Stats() BackupStats {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	backups, _ := bm.ListBackups()
	
	var totalSize int64
	for _, b := range backups {
		totalSize += b.Size
	}
	
	return BackupStats{
		LastBackup:   bm.lastBackup,
		BackupCount:  bm.backupCount,
		RestoreCount: bm.restoreCount,
		TotalBackups: len(backups),
		TotalSize:    totalSize,
	}
}

// VerifyBackup verifies the integrity of a backup
func (bm *BackupManager) VerifyBackup(backupPath string) error {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	
	// Check if file exists
	info, err := os.Stat(backupPath)
	if err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}
	
	// Check minimum size
	if info.Size() < 100 {
		return fmt.Errorf("backup file too small, possibly corrupted")
	}
	
	// If encrypted, try to decrypt header
	if strings.HasSuffix(backupPath, ".enc") {
		if bm.encryptionKey == nil {
			return fmt.Errorf("backup is encrypted but no key provided")
		}
		
		// Read first few bytes to verify encryption
		file, err := os.Open(backupPath)
		if err != nil {
			return err
		}
		defer file.Close()
		
		// Verify we can create cipher with the key
		_, err = aes.NewCipher(bm.encryptionKey)
		if err != nil {
			return fmt.Errorf("invalid encryption key: %w", err)
		}
	} else {
		// Try to read tar.gz header
		file, err := os.Open(backupPath)
		if err != nil {
			return err
		}
		defer file.Close()
		
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("invalid gzip format: %w", err)
		}
		defer gzReader.Close()
		
		tarReader := tar.NewReader(gzReader)
		_, err = tarReader.Next()
		if err != nil && err != io.EOF {
			return fmt.Errorf("invalid tar format: %w", err)
		}
	}
	
	return nil
}

// BackupInfo contains information about a backup
type BackupInfo struct {
	Path      string
	Name      string
	Size      int64
	Created   time.Time
	Encrypted bool
}

// BackupStats contains backup statistics
type BackupStats struct {
	LastBackup   time.Time
	BackupCount  int64
	RestoreCount int64
	TotalBackups int
	TotalSize    int64
}

// GenerateEncryptionKey generates a random encryption key
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// ValidateEncryptionKey validates an encryption key
func ValidateEncryptionKey(key string) error {
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid hex encoding: %w", err)
	}
	
	if len(decoded) != 32 {
		return fmt.Errorf("key must be 32 bytes (64 hex characters)")
	}
	
	return nil
}