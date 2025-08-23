package safe

import (
	"errors"
	"net"
	"testing"
	"time"
)

// Mock types for testing
type mockListener struct{}

func (m *mockListener) Accept() (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (m *mockListener) Close() error {
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestAssertTCPListener(t *testing.T) {
	tests := []struct {
		name    string
		input   net.Listener
		wantErr bool
	}{
		{
			name: "valid TCP listener",
			input: func() net.Listener {
				ln, _ := net.Listen("tcp", "127.0.0.1:0")
				if ln != nil {
					defer ln.Close()
				}
				return ln
			}(),
			wantErr: false,
		},
		{
			name:    "non-TCP listener",
			input:   &mockListener{},
			wantErr: true,
		},
		{
			name:    "nil listener",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AssertTCPListener(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("AssertTCPListener() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && result == nil {
				t.Error("AssertTCPListener() returned nil for valid input")
			}
			// Clean up
			if result != nil {
				result.Close()
			} else if tt.input != nil && !tt.wantErr {
				tt.input.Close()
			}
		})
	}
}

func TestAssertTCPConn(t *testing.T) {
	tests := []struct {
		name    string
		input   net.Conn
		wantErr bool
	}{
		{
			name: "valid TCP connection",
			input: func() net.Conn {
				ln, _ := net.Listen("tcp", "127.0.0.1:0")
				if ln == nil {
					return nil
				}
				defer ln.Close()
				
				go func() {
					conn, _ := ln.Accept()
					if conn != nil {
						conn.Close()
					}
				}()
				
				conn, _ := net.Dial("tcp", ln.Addr().String())
				return conn
			}(),
			wantErr: false,
		},
		{
			name:    "non-TCP connection",
			input:   &mockConn{},
			wantErr: true,
		},
		{
			name:    "nil connection",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AssertTCPConn(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("AssertTCPConn() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && result == nil {
				t.Error("AssertTCPConn() returned nil for valid input")
			}
			// Clean up
			if result != nil {
				result.Close()
			} else if tt.input != nil && !tt.wantErr {
				tt.input.Close()
			}
		})
	}
}

func TestGetMapValue(t *testing.T) {
	testMap := map[string]int{
		"one":   1,
		"two":   2,
		"three": 3,
	}

	tests := []struct {
		name         string
		key          string
		defaultValue int
		expected     int
	}{
		{
			name:         "existing key",
			key:          "two",
			defaultValue: 0,
			expected:     2,
		},
		{
			name:         "non-existing key",
			key:          "four",
			defaultValue: 4,
			expected:     4,
		},
		{
			name:         "empty key",
			key:          "",
			defaultValue: -1,
			expected:     -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMapValue(testMap, tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("GetMapValue() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetMapValueOk(t *testing.T) {
	testMap := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	tests := []struct {
		name     string
		key      string
		wantVal  string
		wantOk   bool
	}{
		{
			name:    "existing key",
			key:     "key1",
			wantVal: "value1",
			wantOk:  true,
		},
		{
			name:    "non-existing key",
			key:     "key3",
			wantVal: "",
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := GetMapValueOk(testMap, tt.key)
			if val != tt.wantVal {
				t.Errorf("GetMapValueOk() val = %v, want %v", val, tt.wantVal)
			}
			if ok != tt.wantOk {
				t.Errorf("GetMapValueOk() ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}

func TestSafeInterfaceConversion(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
	}{
		{
			name:    "valid string conversion",
			input:   "test",
			wantErr: false,
		},
		{
			name:    "invalid conversion",
			input:   123,
			wantErr: true,
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SafeInterfaceConversion[string](tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeInterfaceConversion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && result == "" && tt.input != "" {
				t.Error("SafeInterfaceConversion() returned empty string for valid input")
			}
		})
	}
}

func TestSafeStringConversion(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
		ok       bool
	}{
		{
			name:     "valid string",
			input:    "hello",
			expected: "hello",
			ok:       true,
		},
		{
			name:     "integer input",
			input:    42,
			expected: "",
			ok:       false,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: "",
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := SafeStringConversion(tt.input)
			if result != tt.expected {
				t.Errorf("SafeStringConversion() result = %v, want %v", result, tt.expected)
			}
			if ok != tt.ok {
				t.Errorf("SafeStringConversion() ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}

func TestSafeIntConversion(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int
		ok       bool
	}{
		{
			name:     "int input",
			input:    42,
			expected: 42,
			ok:       true,
		},
		{
			name:     "int32 input",
			input:    int32(100),
			expected: 100,
			ok:       true,
		},
		{
			name:     "int64 input",
			input:    int64(200),
			expected: 200,
			ok:       true,
		},
		{
			name:     "float64 input",
			input:    float64(300.0),
			expected: 300,
			ok:       true,
		},
		{
			name:     "float32 input",
			input:    float32(400.0),
			expected: 400,
			ok:       true,
		},
		{
			name:     "string input",
			input:    "not a number",
			expected: 0,
			ok:       false,
		},
		{
			name:     "nil input",
			input:    nil,
			expected: 0,
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := SafeIntConversion(tt.input)
			if result != tt.expected {
				t.Errorf("SafeIntConversion() result = %v, want %v", result, tt.expected)
			}
			if ok != tt.ok {
				t.Errorf("SafeIntConversion() ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}

func TestRecoverWithError(t *testing.T) {
	tests := []struct {
		name      string
		panicVal  interface{}
		wantError bool
	}{
		{
			name: "panic with error",
			panicVal: errors.New("test error"),
			wantError: true,
		},
		{
			name: "panic with string",
			panicVal: "panic message",
			wantError: true,
		},
		{
			name: "panic with number",
			panicVal: 42,
			wantError: true,
		},
		{
			name: "no panic",
			panicVal: nil,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			func() {
				defer func() {
					err = RecoverWithError()
				}()
				if tt.panicVal != nil {
					panic(tt.panicVal)
				}
			}()

			if (err != nil) != tt.wantError {
				t.Errorf("RecoverWithError() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestRecoverWithHandler(t *testing.T) {
	tests := []struct {
		name            string
		panicVal        interface{}
		expectHandlerCall bool
	}{
		{
			name:            "panic triggers handler",
			panicVal:        "test panic",
			expectHandlerCall: true,
		},
		{
			name:            "no panic",
			panicVal:        nil,
			expectHandlerCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlerCalled := false
			handler := func(r interface{}) {
				handlerCalled = true
			}

			func() {
				defer RecoverWithHandler(handler)
				if tt.panicVal != nil {
					panic(tt.panicVal)
				}
			}()

			if handlerCalled != tt.expectHandlerCall {
				t.Errorf("RecoverWithHandler() handler called = %v, want %v", handlerCalled, tt.expectHandlerCall)
			}
		})
	}
}

type testCloser struct {
	closed     bool
	shouldPanic bool
	closeErr   error
}

func (tc *testCloser) Close() error {
	if tc.shouldPanic {
		panic("close panic")
	}
	tc.closed = true
	return tc.closeErr
}

func TestSafeClose(t *testing.T) {
	tests := []struct {
		name      string
		closer    *testCloser
		wantError bool
	}{
		{
			name:      "successful close",
			closer:    &testCloser{},
			wantError: false,
		},
		{
			name:      "close with error",
			closer:    &testCloser{closeErr: errors.New("close error")},
			wantError: true,
		},
		{
			name:      "close with panic",
			closer:    &testCloser{shouldPanic: true},
			wantError: false, // Panic is recovered, no error returned
		},
		{
			name:      "nil closer",
			closer:    nil,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var closer interface{ Close() error }
			if tt.closer != nil {
				closer = tt.closer
			}
			
			err := SafeClose(closer)
			if (err != nil) != tt.wantError {
				t.Errorf("SafeClose() error = %v, wantError %v", err, tt.wantError)
			}
			
			if tt.closer != nil && !tt.closer.shouldPanic && !tt.closer.closed {
				t.Error("SafeClose() did not close the closer")
			}
		})
	}
}

func TestSafeMapAccess(t *testing.T) {
	testMap := map[string]int{
		"key1": 100,
		"key2": 200,
	}

	tests := []struct {
		name     string
		m        map[string]int
		keys     []string
		wantVal  int
		wantOk   bool
	}{
		{
			name:    "existing key",
			m:       testMap,
			keys:    []string{"key1"},
			wantVal: 100,
			wantOk:  true,
		},
		{
			name:    "non-existing key",
			m:       testMap,
			keys:    []string{"key3"},
			wantVal: 0,
			wantOk:  false,
		},
		{
			name:    "nil map",
			m:       nil,
			keys:    []string{"key1"},
			wantVal: 0,
			wantOk:  false,
		},
		{
			name:    "no keys",
			m:       testMap,
			keys:    []string{},
			wantVal: 0,
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := SafeMapAccess(tt.m, tt.keys...)
			if val != tt.wantVal {
				t.Errorf("SafeMapAccess() val = %v, want %v", val, tt.wantVal)
			}
			if ok != tt.wantOk {
				t.Errorf("SafeMapAccess() ok = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}