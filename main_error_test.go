package main

import (
	"testing"
	
	"github.com/artyom/leproxy/internal/logger"
)

func TestLoggerInit_InvalidLevel(t *testing.T) {
	// Test that invalid log level returns an error
	err := logger.Init("INVALID_LEVEL", false)
	if err == nil {
		t.Error("Expected error for invalid log level, got nil")
	}
	if err.Error() != "unknown log level: INVALID_LEVEL" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestLoggerInit_ValidLevels(t *testing.T) {
	validLevels := []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}
	
	for _, level := range validLevels {
		err := logger.Init(level, false)
		if err != nil {
			t.Errorf("Unexpected error for valid level %s: %v", level, err)
		}
	}
	
	// Test with JSON mode
	err := logger.Init("INFO", true)
	if err != nil {
		t.Errorf("Unexpected error with JSON mode: %v", err)
	}
}

func TestLoggerFatal_NoExit(t *testing.T) {
	// This test verifies that logger.Fatal no longer calls os.Exit
	// We can call it without the test process exiting
	logger.Fatal("Test fatal message", map[string]interface{}{"test": true})
	// If we reach here, the test passes (Fatal didn't call os.Exit)
}