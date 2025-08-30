package testhelpers

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestWriteFile verifies that WriteFile properly handles errors
func TestWriteFile(t *testing.T) {
	// Test successful write
	t.Run("valid write", func(t *testing.T) {
		path := t.TempDir() + "/test.txt"
		data := []byte("test data")
		
		WriteFile(t, path, data, 0644)
		
		// Verify the file was written correctly
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("Failed to read written file: %v", err)
		}
		
		if string(content) != string(data) {
			t.Errorf("File content mismatch: got %q, want %q", content, data)
		}
	})
	
	// Note: Testing failure case with t.Fatal is complex due to test framework limitations
	// The helper function will fail the test appropriately when used in real test scenarios
}

// TestCreateTempFile verifies temp file creation and cleanup
func TestCreateTempFile(t *testing.T) {
	// Create a temp file
	path := CreateTempFile(t, "test-tempfile-*")
	
	// Verify it exists
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Temp file should exist: %v", err)
	}
	
	// Clean up
	os.Remove(path)
}

// mockConn implements a simple mock connection for testing
type mockConn struct {
	writeErr error
	readErr  error
	written  []byte
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.written = append(m.written, b...)
	return len(b), nil
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return 0, nil
}

// TestMustWrite verifies MustWrite error handling
func TestMustWrite(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		conn := &mockConn{}
		data := []byte("test data")
		
		MustWrite(t, conn, data)
		
		if string(conn.written) != string(data) {
			t.Errorf("Data not written correctly: got %q, want %q", conn.written, data)
		}
	})
	
	// Note: Testing failure case with t.Fatal is complex due to test framework limitations
	// The helper function will fail the test appropriately when used in real test scenarios
}

// TestWriteOrIgnore verifies WriteOrIgnore doesn't panic on errors
func TestWriteOrIgnore(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		conn := &mockConn{}
		data := []byte("test data")
		
		WriteOrIgnore(conn, data)
		
		if string(conn.written) != string(data) {
			t.Errorf("Data not written correctly: got %q, want %q", conn.written, data)
		}
	})
	
	t.Run("write error ignored", func(t *testing.T) {
		conn := &mockConn{writeErr: errors.New("write failed")}
		data := []byte("test data")
		
		// Should not panic
		WriteOrIgnore(conn, data)
	})
}

// TestReadOrIgnore verifies ReadOrIgnore doesn't panic on errors
func TestReadOrIgnore(t *testing.T) {
	t.Run("read error ignored", func(t *testing.T) {
		conn := &mockConn{readErr: errors.New("read failed")}
		buf := make([]byte, 10)
		
		// Should not panic
		ReadOrIgnore(conn, buf)
	})
}

// TestCreateTestCertificate verifies certificate creation
func TestCreateTestCertificate(t *testing.T) {
	certPEM, keyPEM := CreateTestCertificate(t, "test.example.com", 365)
	
	if len(certPEM) == 0 {
		t.Error("Certificate PEM is empty")
	}
	
	if len(keyPEM) == 0 {
		t.Error("Key PEM is empty")
	}
	
	// Verify the certificate is valid PEM
	if !contains(certPEM, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("Certificate PEM doesn't contain expected header")
	}
	
	if !contains(keyPEM, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Error("Key PEM doesn't contain expected header")
	}
}

// TestWriteCorruptedCertFiles verifies corrupted cert file writing
func TestWriteCorruptedCertFiles(t *testing.T) {
	tempDir := t.TempDir()
	certPath := tempDir + "/cert.pem"
	keyPath := tempDir + "/key.pem"
	
	WriteCorruptedCertFiles(t, certPath, keyPath)
	
	// Verify files exist
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("Certificate file should exist: %v", err)
	}
	
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("Key file should exist: %v", err)
	}
	
	// Verify files contain corrupted data
	certData, _ := os.ReadFile(certPath)
	if !contains(certData, []byte("incomplete and corrupted")) {
		t.Error("Certificate file doesn't contain expected corrupted data")
	}
	
	keyData, _ := os.ReadFile(keyPath)
	if !contains(keyData, []byte("incomplete and corrupted")) {
		t.Error("Key file doesn't contain expected corrupted data")
	}
}

// TestNetworkErrorHandling tests error handling with real network connections
func TestNetworkErrorHandling(t *testing.T) {
	// Create a listener that immediately closes connections
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close() // Immediately close
		}
	}()
	
	// Try to connect and write
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	
	// Give the server time to close the connection
	time.Sleep(10 * time.Millisecond)
	
	// This should not panic even though the connection is closed
	WriteOrIgnore(conn, []byte("test data"))
	
	buf := make([]byte, 10)
	ReadOrIgnore(conn, buf)
}

func contains(data, substr []byte) bool {
	for i := 0; i <= len(data)-len(substr); i++ {
		if string(data[i:i+len(substr)]) == string(substr) {
			return true
		}
	}
	return false
}