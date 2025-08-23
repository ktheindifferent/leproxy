package safe

import (
	"fmt"
	"net"
	"net/http"
)

// AssertTCPListener safely asserts that a net.Listener is a *net.TCPListener
func AssertTCPListener(ln net.Listener) (*net.TCPListener, error) {
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("listener is not a TCP listener, got %T", ln)
	}
	return tcpLn, nil
}

// AssertTCPConn safely asserts that a net.Conn is a *net.TCPConn
func AssertTCPConn(conn net.Conn) (*net.TCPConn, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a TCP connection, got %T", conn)
	}
	return tcpConn, nil
}

// AssertResponseWriter safely asserts custom response writer types
func AssertResponseWriter(w http.ResponseWriter) (http.ResponseWriter, bool) {
	// This is a generic helper that can be extended for specific types
	if w == nil {
		return nil, false
	}
	return w, true
}

// GetMapValue safely gets a value from a map with a default value
func GetMapValue[K comparable, V any](m map[K]V, key K, defaultValue V) V {
	if val, ok := m[key]; ok {
		return val
	}
	return defaultValue
}

// GetMapValueOk safely gets a value from a map and returns if it exists
func GetMapValueOk[K comparable, V any](m map[K]V, key K) (V, bool) {
	val, ok := m[key]
	return val, ok
}

// SafeInterfaceConversion safely converts an interface to a specific type
func SafeInterfaceConversion[T any](value interface{}) (T, error) {
	var zero T
	converted, ok := value.(T)
	if !ok {
		return zero, fmt.Errorf("cannot convert %T to %T", value, zero)
	}
	return converted, nil
}

// SafeStringConversion safely converts an interface to string
func SafeStringConversion(value interface{}) (string, bool) {
	str, ok := value.(string)
	return str, ok
}

// SafeIntConversion safely converts an interface to int
func SafeIntConversion(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	default:
		return 0, false
	}
}

// SafeMapAccess provides safe access to nested maps
func SafeMapAccess[K comparable, V any](m map[K]V, keys ...K) (V, bool) {
	var zero V
	if len(keys) == 0 || m == nil {
		return zero, false
	}
	
	val, ok := m[keys[0]]
	return val, ok
}

// RecoverWithError recovers from panic and returns as error
func RecoverWithError() error {
	if r := recover(); r != nil {
		switch err := r.(type) {
		case error:
			return fmt.Errorf("recovered from panic: %w", err)
		default:
			return fmt.Errorf("recovered from panic: %v", r)
		}
	}
	return nil
}

// RecoverWithHandler recovers from panic and calls a handler function
func RecoverWithHandler(handler func(interface{})) {
	if r := recover(); r != nil {
		if handler != nil {
			handler(r)
		}
	}
}

// SafeClose safely closes a closer and handles any panic
func SafeClose(closer interface{ Close() error }) error {
	defer func() {
		if r := recover(); r != nil {
			// Ignore panic during close
		}
	}()
	
	if closer != nil {
		return closer.Close()
	}
	return nil
}