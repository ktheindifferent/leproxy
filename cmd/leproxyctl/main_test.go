package main

import (
	"flag"
	"os"
	"testing"
)

func TestRun_NoCommand(t *testing.T) {
	// Reset flags for testing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	
	// Save original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	
	// Set test args with no command
	os.Args = []string{"leproxyctl"}
	
	err := run()
	if err == nil {
		t.Error("Expected error for no command, got nil")
	}
	if err.Error() != "no command specified" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	// Reset flags for testing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	
	// Save original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()
	
	// Set test args with unknown command
	os.Args = []string{"leproxyctl", "nonexistent"}
	
	err := run()
	if err == nil {
		t.Error("Expected error for unknown command, got nil")
	}
	if err.Error() != "unknown command: nonexistent" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestCommandExecution(t *testing.T) {
	// Test that valid commands are recognized
	validCommands := []string{
		"status",
		"mappings",
		"certs",
		"blacklist",
		"reload",
		"health",
		"metrics",
		"logs",
		"test",
		"version",
	}
	
	for _, cmdName := range validCommands {
		found := false
		for _, cmd := range commands {
			if cmd.Name == cmdName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Command %s not found in commands list", cmdName)
		}
	}
}

func TestGetEnv(t *testing.T) {
	// Test with environment variable set
	os.Setenv("TEST_ENV_VAR", "test_value")
	defer os.Unsetenv("TEST_ENV_VAR")
	
	result := getEnv("TEST_ENV_VAR", "default")
	if result != "test_value" {
		t.Errorf("Expected 'test_value', got '%s'", result)
	}
	
	// Test with environment variable not set
	result = getEnv("NONEXISTENT_VAR", "default")
	if result != "default" {
		t.Errorf("Expected 'default', got '%s'", result)
	}
}