// Package testhelpers provides common helper functions for tests
package testhelpers

import (
	"os"
	"testing"
)

// WriteFile writes data to a file and fails the test on error
func WriteFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("Failed to write file %s: %v", path, err)
	}
}

// CreateTempFile creates a temporary file and returns its path
func CreateTempFile(t *testing.T, pattern string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}
	return tmpfile.Name()
}

// MustWrite writes data to a connection and fails the test on error
func MustWrite(t *testing.T, conn interface{ Write([]byte) (int, error) }, data []byte) {
	t.Helper()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}
}

// WriteOrIgnore writes data to a connection and ignores errors
// Use this when testing connection failures or shutdowns
func WriteOrIgnore(conn interface{ Write([]byte) (int, error) }, data []byte) {
	_, _ = conn.Write(data)
}

// ReadOrIgnore reads data from a connection and ignores errors
// Use this when testing connection failures or shutdowns
func ReadOrIgnore(conn interface{ Read([]byte) (int, error) }, buf []byte) {
	_, _ = conn.Read(buf)
}