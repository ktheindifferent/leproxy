package errors

import (
	"fmt"
	"runtime"
	"strings"
)

type ErrorType string

const (
	ErrorTypeConnection   ErrorType = "CONNECTION"
	ErrorTypeConfiguration ErrorType = "CONFIGURATION"
	ErrorTypeCertificate  ErrorType = "CERTIFICATE"
	ErrorTypeProtocol     ErrorType = "PROTOCOL"
	ErrorTypeTimeout      ErrorType = "TIMEOUT"
	ErrorTypePermission   ErrorType = "PERMISSION"
	ErrorTypeIO           ErrorType = "IO"
	ErrorTypeInternal     ErrorType = "INTERNAL"
)

type ProxyError struct {
	Type      ErrorType
	Operation string
	Service   string
	Err       error
	Details   map[string]interface{}
	Stack     string
}

func New(errType ErrorType, operation, service string, err error) *ProxyError {
	return &ProxyError{
		Type:      errType,
		Operation: operation,
		Service:   service,
		Err:       err,
		Details:   make(map[string]interface{}),
		Stack:     captureStack(),
	}
}

func (e *ProxyError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s] %s", e.Type, e.Operation))
	if e.Service != "" {
		sb.WriteString(fmt.Sprintf(" for %s", e.Service))
	}
	if e.Err != nil {
		sb.WriteString(fmt.Sprintf(": %v", e.Err))
	}
	if len(e.Details) > 0 {
		sb.WriteString(" (")
		first := true
		for k, v := range e.Details {
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%s=%v", k, v))
			first = false
		}
		sb.WriteString(")")
	}
	return sb.String()
}

func (e *ProxyError) WithDetail(key string, value interface{}) *ProxyError {
	e.Details[key] = value
	return e
}

func (e *ProxyError) Unwrap() error {
	return e.Err
}

func (e *ProxyError) Is(target error) bool {
	t, ok := target.(*ProxyError)
	if !ok {
		return false
	}
	return e.Type == t.Type
}

func captureStack() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	
	var sb strings.Builder
	for {
		frame, more := frames.Next()
		if !strings.Contains(frame.File, "runtime/") {
			sb.WriteString(fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function))
		}
		if !more {
			break
		}
	}
	return sb.String()
}

func Wrap(err error, errType ErrorType, operation, service string) error {
	if err == nil {
		return nil
	}
	if pe, ok := err.(*ProxyError); ok {
		return pe
	}
	return New(errType, operation, service, err)
}

func IsType(err error, errType ErrorType) bool {
	pe, ok := err.(*ProxyError)
	return ok && pe.Type == errType
}

func GetDetails(err error) map[string]interface{} {
	pe, ok := err.(*ProxyError)
	if !ok {
		return nil
	}
	return pe.Details
}