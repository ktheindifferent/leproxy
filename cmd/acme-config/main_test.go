package main

import (
	"os"
	"testing"
)

func TestShowProviderDetails_UnknownProvider(t *testing.T) {
	err := showProviderDetails("nonexistent-provider")
	if err == nil {
		t.Error("Expected error for unknown provider, got nil")
	}
	if err.Error() != "unknown provider: nonexistent-provider" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestGenerateConfiguration_MissingEmail(t *testing.T) {
	// Test with missing email
	err := generateConfiguration("test.yaml", "letsencrypt", "", "", "", false, "yaml")
	if err == nil {
		t.Error("Expected error for missing email, got nil")
	}
	if err.Error() != "email is required for configuration generation" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestGenerateConfiguration_UnknownProvider(t *testing.T) {
	err := generateConfiguration("test.yaml", "nonexistent", "test@example.com", "", "", false, "yaml")
	if err == nil {
		t.Error("Expected error for unknown provider, got nil")
	}
	if err.Error() != "unknown provider: nonexistent" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestGenerateConfiguration_MissingEAB(t *testing.T) {
	// Test with a provider that requires EAB but without EAB credentials
	// This test assumes zerossl requires EAB
	err := generateConfiguration("test.yaml", "zerossl", "test@example.com", "", "", false, "yaml")
	if err == nil {
		t.Error("Expected error for missing EAB credentials, got nil")
	}
}

func TestGenerateConfiguration_InvalidFile(t *testing.T) {
	// Try to create a file in a non-existent directory
	err := generateConfiguration("/nonexistent/dir/test.yaml", "letsencrypt", "test@example.com", "", "", false, "yaml")
	if err == nil {
		t.Error("Expected error for invalid file path, got nil")
	}
}

// Cleanup any test files created
func TestMain(m *testing.M) {
	code := m.Run()
	// Cleanup test files if any were created
	os.Remove("test.yaml")
	os.Exit(code)
}