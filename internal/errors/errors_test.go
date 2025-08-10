package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	baseErr := errors.New("base error")
	
	tests := []struct {
		name      string
		errType   ErrorType
		operation string
		service   string
		err       error
		wantType  ErrorType
		wantInMsg []string
	}{
		{
			name:      "connection error",
			errType:   ErrorTypeConnection,
			operation: "connect",
			service:   "postgres",
			err:       baseErr,
			wantType:  ErrorTypeConnection,
			wantInMsg: []string{"CONNECTION", "connect", "postgres", "base error"},
		},
		{
			name:      "configuration error",
			errType:   ErrorTypeConfiguration,
			operation: "parse config",
			service:   "main",
			err:       baseErr,
			wantType:  ErrorTypeConfiguration,
			wantInMsg: []string{"CONFIGURATION", "parse config", "main"},
		},
		{
			name:      "certificate error without service",
			errType:   ErrorTypeCertificate,
			operation: "generate cert",
			service:   "",
			err:       baseErr,
			wantType:  ErrorTypeCertificate,
			wantInMsg: []string{"CERTIFICATE", "generate cert"},
		},
		{
			name:      "timeout error",
			errType:   ErrorTypeTimeout,
			operation: "read",
			service:   "redis",
			err:       nil,
			wantType:  ErrorTypeTimeout,
			wantInMsg: []string{"TIMEOUT", "read", "redis"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyErr := New(tt.errType, tt.operation, tt.service, tt.err)
			
			if proxyErr.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", proxyErr.Type, tt.wantType)
			}
			
			if proxyErr.Operation != tt.operation {
				t.Errorf("Operation = %v, want %v", proxyErr.Operation, tt.operation)
			}
			
			if proxyErr.Service != tt.service {
				t.Errorf("Service = %v, want %v", proxyErr.Service, tt.service)
			}
			
			if proxyErr.Err != tt.err {
				t.Errorf("Err = %v, want %v", proxyErr.Err, tt.err)
			}
			
			if proxyErr.Details == nil {
				t.Error("Details map should be initialized")
			}
			
			if proxyErr.Stack == "" {
				t.Error("Stack trace should be captured")
			}
			
			// Check error message
			errMsg := proxyErr.Error()
			for _, want := range tt.wantInMsg {
				if want != "" && !strings.Contains(errMsg, want) {
					t.Errorf("Error message %q should contain %q", errMsg, want)
				}
			}
		})
	}
}

func TestWithDetail(t *testing.T) {
	proxyErr := New(ErrorTypeConnection, "connect", "postgres", nil)
	
	// Add single detail
	result := proxyErr.WithDetail("host", "localhost")
	if result != proxyErr {
		t.Error("WithDetail should return the same error instance")
	}
	
	if proxyErr.Details["host"] != "localhost" {
		t.Errorf("Detail host = %v, want localhost", proxyErr.Details["host"])
	}
	
	// Add multiple details
	proxyErr.WithDetail("port", 5432).WithDetail("database", "test")
	
	if proxyErr.Details["port"] != 5432 {
		t.Errorf("Detail port = %v, want 5432", proxyErr.Details["port"])
	}
	
	if proxyErr.Details["database"] != "test" {
		t.Errorf("Detail database = %v, want test", proxyErr.Details["database"])
	}
}

func TestWrap(t *testing.T) {
	baseErr := errors.New("base error")
	
	wrappedErr := Wrap(baseErr, ErrorTypeConnection, "connect", "postgres")
	
	// Type assert to *ProxyError
	wrapped, ok := wrappedErr.(*ProxyError)
	if !ok {
		t.Fatal("Wrap should return *ProxyError")
	}
	
	if wrapped.Type != ErrorTypeConnection {
		t.Errorf("Type = %v, want %v", wrapped.Type, ErrorTypeConnection)
	}
	
	if wrapped.Operation != "connect" {
		t.Errorf("Operation = %v, want %v", wrapped.Operation, "connect")
	}
	
	if wrapped.Service != "postgres" {
		t.Errorf("Service = %v, want %v", wrapped.Service, "postgres")
	}
	
	if wrapped.Err != baseErr {
		t.Errorf("Err = %v, want %v", wrapped.Err, baseErr)
	}
	
	// Check error message contains wrapped error
	if !strings.Contains(wrapped.Error(), "base error") {
		t.Error("Wrapped error message should contain base error")
	}
}

func TestIsType(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		errType  ErrorType
		expected bool
	}{
		{
			name:     "proxy error with matching type",
			err:      New(ErrorTypeConnection, "test", "", nil),
			errType:  ErrorTypeConnection,
			expected: true,
		},
		{
			name:     "proxy error with different type",
			err:      New(ErrorTypeConfiguration, "test", "", nil),
			errType:  ErrorTypeConnection,
			expected: false,
		},
		{
			name:     "non-proxy error",
			err:      errors.New("regular error"),
			errType:  ErrorTypeConnection,
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			errType:  ErrorTypeConnection,
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsType(tt.err, tt.errType)
			if result != tt.expected {
				t.Errorf("IsType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetDetails(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected map[string]interface{}
	}{
		{
			name: "proxy error with details",
			err: New(ErrorTypeConnection, "test", "", nil).
				WithDetail("host", "localhost").
				WithDetail("port", 5432),
			expected: map[string]interface{}{
				"host": "localhost",
				"port": 5432,
			},
		},
		{
			name:     "proxy error without details",
			err:      New(ErrorTypeConnection, "test", "", nil),
			expected: map[string]interface{}{},
		},
		{
			name:     "non-proxy error",
			err:      errors.New("regular error"),
			expected: nil,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: nil,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDetails(tt.err)
			
			if tt.expected == nil {
				if result != nil {
					t.Errorf("GetDetails() = %v, want nil", result)
				}
				return
			}
			
			if len(result) != len(tt.expected) {
				t.Errorf("GetDetails() returned %d items, want %d", len(result), len(tt.expected))
			}
			
			for key, want := range tt.expected {
				if got, ok := result[key]; !ok || got != want {
					t.Errorf("GetDetails()[%s] = %v, want %v", key, got, want)
				}
			}
		})
	}
}

func TestErrorFormatting(t *testing.T) {
	tests := []struct {
		name     string
		err      *ProxyError
		expected string
	}{
		{
			name: "with all fields",
			err: &ProxyError{
				Type:      ErrorTypeConnection,
				Operation: "connect",
				Service:   "postgres",
				Err:       errors.New("connection refused"),
			},
			expected: "[CONNECTION] connect for postgres: connection refused",
		},
		{
			name: "without service",
			err: &ProxyError{
				Type:      ErrorTypeConfiguration,
				Operation: "parse",
				Err:       errors.New("invalid format"),
			},
			expected: "[CONFIGURATION] parse: invalid format",
		},
		{
			name: "without base error",
			err: &ProxyError{
				Type:      ErrorTypeTimeout,
				Operation: "read",
				Service:   "redis",
			},
			expected: "[TIMEOUT] read for redis",
		},
		{
			name: "minimal error",
			err: &ProxyError{
				Type:      ErrorTypeInternal,
				Operation: "process",
			},
			expected: "[INTERNAL] process",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestCaptureStack(t *testing.T) {
	stack := captureStack()
	
	if stack == "" {
		t.Error("captureStack() should return non-empty stack trace")
	}
	
	// Stack should contain this test function name
	if !strings.Contains(stack, "TestCaptureStack") {
		t.Error("Stack trace should contain current function name")
	}
	
	// Stack should contain file information
	if !strings.Contains(stack, "errors_test.go") {
		t.Error("Stack trace should contain file name")
	}
}