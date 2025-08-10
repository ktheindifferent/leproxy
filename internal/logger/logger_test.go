package logger

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name      string
		level     Level
		format    Format
		wantLevel Level
	}{
		{
			name:      "debug level text format",
			level:     LevelDebug,
			format:    FormatText,
			wantLevel: LevelDebug,
		},
		{
			name:      "info level json format",
			level:     LevelInfo,
			format:    FormatJSON,
			wantLevel: LevelInfo,
		},
		{
			name:      "error level text format",
			level:     LevelError,
			format:    FormatText,
			wantLevel: LevelError,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.level, tt.format)
			if logger == nil {
				t.Fatal("New() returned nil")
			}
			if logger.level != tt.wantLevel {
				t.Errorf("logger.level = %v, want %v", logger.level, tt.wantLevel)
			}
			if logger.format != tt.format {
				t.Errorf("logger.format = %v, want %v", logger.format, tt.format)
			}
		})
	}
}

func TestSetLevel(t *testing.T) {
	logger := New(LevelInfo, FormatText)
	
	tests := []struct {
		name     string
		newLevel Level
	}{
		{"set to debug", LevelDebug},
		{"set to warn", LevelWarn},
		{"set to error", LevelError},
		{"set to fatal", LevelFatal},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.SetLevel(tt.newLevel)
			if logger.level != tt.newLevel {
				t.Errorf("After SetLevel(%v), level = %v", tt.newLevel, logger.level)
			}
		})
	}
}

func TestLoggerTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelDebug, FormatText)
	logger.output = &buf
	
	tests := []struct {
		name     string
		logFunc  func(string, map[string]interface{})
		message  string
		fields   map[string]interface{}
		contains []string
	}{
		{
			name:     "debug message",
			logFunc:  logger.Debug,
			message:  "debug test",
			fields:   map[string]interface{}{"key": "value"},
			contains: []string{"DEBUG", "debug test", "key=value"},
		},
		{
			name:     "info message",
			logFunc:  logger.Info,
			message:  "info test",
			fields:   map[string]interface{}{"count": 42},
			contains: []string{"INFO", "info test", "count=42"},
		},
		{
			name:     "warn message",
			logFunc:  logger.Warn,
			message:  "warning test",
			fields:   nil,
			contains: []string{"WARN", "warning test"},
		},
		{
			name:     "error message",
			logFunc:  logger.Error,
			message:  "error test",
			fields:   map[string]interface{}{"error": "failed"},
			contains: []string{"ERROR", "error test", "error=failed"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message, tt.fields)
			output := buf.String()
			
			for _, want := range tt.contains {
				if !strings.Contains(output, want) {
					t.Errorf("Log output %q should contain %q", output, want)
				}
			}
		})
	}
}

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelDebug, FormatJSON)
	logger.output = &buf
	
	tests := []struct {
		name    string
		logFunc func(string, map[string]interface{})
		message string
		fields  map[string]interface{}
		level   string
	}{
		{
			name:    "debug json",
			logFunc: logger.Debug,
			message: "debug message",
			fields:  map[string]interface{}{"key": "value", "number": 123},
			level:   "DEBUG",
		},
		{
			name:    "info json",
			logFunc: logger.Info,
			message: "info message",
			fields:  map[string]interface{}{"status": "ok"},
			level:   "INFO",
		},
		{
			name:    "error json",
			logFunc: logger.Error,
			message: "error message",
			fields:  map[string]interface{}{"code": 500},
			level:   "ERROR",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message, tt.fields)
			
			var result map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to parse JSON output: %v", err)
			}
			
			if result["level"] != tt.level {
				t.Errorf("JSON level = %v, want %v", result["level"], tt.level)
			}
			
			if result["message"] != tt.message {
				t.Errorf("JSON message = %v, want %v", result["message"], tt.message)
			}
			
			if _, ok := result["timestamp"]; !ok {
				t.Error("JSON output should contain timestamp")
			}
			
			// Check fields
			if tt.fields != nil {
				for key, value := range tt.fields {
					if result[key] != value {
						t.Errorf("JSON field %s = %v, want %v", key, result[key], value)
					}
				}
			}
		})
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	tests := []struct {
		name         string
		loggerLevel  Level
		debugLogged  bool
		infoLogged   bool
		warnLogged   bool
		errorLogged  bool
	}{
		{
			name:        "debug level logs all",
			loggerLevel: LevelDebug,
			debugLogged: true,
			infoLogged:  true,
			warnLogged:  true,
			errorLogged: true,
		},
		{
			name:        "info level skips debug",
			loggerLevel: LevelInfo,
			debugLogged: false,
			infoLogged:  true,
			warnLogged:  true,
			errorLogged: true,
		},
		{
			name:        "warn level skips debug and info",
			loggerLevel: LevelWarn,
			debugLogged: false,
			infoLogged:  false,
			warnLogged:  true,
			errorLogged: true,
		},
		{
			name:        "error level only logs errors",
			loggerLevel: LevelError,
			debugLogged: false,
			infoLogged:  false,
			warnLogged:  false,
			errorLogged: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(tt.loggerLevel, FormatText)
			logger.output = &buf
			
			logger.Debug("debug", nil)
			debugOutput := buf.String()
			buf.Reset()
			
			logger.Info("info", nil)
			infoOutput := buf.String()
			buf.Reset()
			
			logger.Warn("warn", nil)
			warnOutput := buf.String()
			buf.Reset()
			
			logger.Error("error", nil)
			errorOutput := buf.String()
			
			if tt.debugLogged && debugOutput == "" {
				t.Error("Debug should be logged but wasn't")
			}
			if !tt.debugLogged && debugOutput != "" {
				t.Error("Debug should not be logged but was")
			}
			
			if tt.infoLogged && infoOutput == "" {
				t.Error("Info should be logged but wasn't")
			}
			if !tt.infoLogged && infoOutput != "" {
				t.Error("Info should not be logged but was")
			}
			
			if tt.warnLogged && warnOutput == "" {
				t.Error("Warn should be logged but wasn't")
			}
			if !tt.warnLogged && warnOutput != "" {
				t.Error("Warn should not be logged but was")
			}
			
			if tt.errorLogged && errorOutput == "" {
				t.Error("Error should be logged but wasn't")
			}
			if !tt.errorLogged && errorOutput != "" {
				t.Error("Error should not be logged but was")
			}
		})
	}
}

func TestWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelDebug, FormatText)
	logger.output = &buf
	
	// Create logger with default fields
	contextLogger := logger.WithFields(map[string]interface{}{
		"service": "test",
		"version": "1.0",
	})
	
	// Log with additional fields
	contextLogger.Info("test message", map[string]interface{}{
		"extra": "field",
	})
	
	output := buf.String()
	
	// Check all fields are present
	expectedFields := []string{"service=test", "version=1.0", "extra=field"}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("Output should contain field %q", field)
		}
	}
}

func TestLoggerErrorWithCaller(t *testing.T) {
	var buf bytes.Buffer
	logger := New(LevelDebug, FormatText)
	logger.output = &buf
	
	logger.Error("test error", nil)
	output := buf.String()
	
	// Error logs should contain caller information
	if !strings.Contains(output, "logger_test.go") {
		t.Error("Error log should contain file name")
	}
}

func TestDefaultLogger(t *testing.T) {
	// Test that Default returns a non-nil logger
	defaultLogger := Default()
	if defaultLogger == nil {
		t.Fatal("Default() should return non-nil logger")
	}
	
	// Test that it's actually usable
	var buf bytes.Buffer
	defaultLogger.output = &buf
	
	defaultLogger.Info("test", nil)
	if buf.String() == "" {
		t.Error("Default logger should be able to log")
	}
}