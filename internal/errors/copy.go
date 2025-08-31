package errors

import (
	"context"
	"fmt"
	"io"
	"sync"
	
	"github.com/artyom/leproxy/internal/metrics"
)

// CopyWithContext performs an io.Copy operation with directional error context.
// It wraps errors to include source and destination information for better debugging.
func CopyWithContext(dst io.Writer, src io.Reader, srcName, dstName string) (int64, error) {
	n, err := io.Copy(dst, src)
	if err != nil {
		// Record the error in metrics
		if metrics.IsEnabled() {
			errorType := "unknown"
			if err == io.EOF {
				errorType = "eof"
			} else if err == io.ErrUnexpectedEOF {
				errorType = "unexpected_eof"
			} else if err == context.Canceled {
				errorType = "canceled"
			} else if err == context.DeadlineExceeded {
				errorType = "timeout"
			} else {
				errorType = "io_error"
			}
			metrics.RecordCopyError(srcName, dstName, errorType)
		}
		return n, fmt.Errorf("copying from %s to %s: %w", srcName, dstName, err)
	}
	
	// Record successful bytes transferred
	if metrics.IsEnabled() && n > 0 {
		metrics.RecordCopyBytes(srcName, dstName, n)
	}
	
	return n, nil
}

// ProxyCopyConfig provides configuration for proxy copy operations
type ProxyCopyConfig struct {
	ClientName  string
	BackendName string
	OnError     func(direction string, err error)
}

// ProxyCopy performs bidirectional copying between client and backend connections
// with proper error context and directional information.
func ProxyCopy(client, backend io.ReadWriter, config *ProxyCopyConfig) error {
	if config == nil {
		config = &ProxyCopyConfig{
			ClientName:  "client",
			BackendName: "backend",
		}
	}

	errc := make(chan error, 2)

	// Copy from client to backend
	go func() {
		_, err := CopyWithContext(backend, client, config.ClientName, config.BackendName)
		if err != nil && config.OnError != nil {
			config.OnError(fmt.Sprintf("%s->%s", config.ClientName, config.BackendName), err)
		}
		errc <- err
	}()

	// Copy from backend to client
	go func() {
		_, err := CopyWithContext(client, backend, config.BackendName, config.ClientName)
		if err != nil && config.OnError != nil {
			config.OnError(fmt.Sprintf("%s->%s", config.BackendName, config.ClientName), err)
		}
		errc <- err
	}()

	// Wait for first error or both completions
	err1 := <-errc
	err2 := <-errc

	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}

// ProxyCopyWithContext performs bidirectional copying with context support
// for cancellation and proper cleanup.
func ProxyCopyWithContext(ctx context.Context, client, backend io.ReadWriter, config *ProxyCopyConfig) error {
	if config == nil {
		config = &ProxyCopyConfig{
			ClientName:  "client",
			BackendName: "backend",
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	// Helper function to copy with context awareness
	copyWithCtx := func(dst io.Writer, src io.Reader, srcName, dstName string) {
		defer wg.Done()

		// Create a cancellable reader/writer if possible
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				// Try to close connections if they support it
				if closer, ok := src.(io.Closer); ok {
					closer.Close()
				}
				if closer, ok := dst.(io.Closer); ok {
					closer.Close()
				}
			case <-done:
			}
		}()

		_, err := CopyWithContext(dst, src, srcName, dstName)
		close(done)

		if err != nil && err != io.EOF && err != context.Canceled {
			if config.OnError != nil {
				config.OnError(fmt.Sprintf("%s->%s", srcName, dstName), err)
			}
			cancel() // Cancel the other copy operation
		}
		errc <- err
	}

	wg.Add(2)
	go copyWithCtx(backend, client, config.ClientName, config.BackendName)
	go copyWithCtx(client, backend, config.BackendName, config.ClientName)

	// Wait for both goroutines to complete
	go func() {
		wg.Wait()
		close(errc)
	}()

	// Collect errors
	var firstErr error
	for err := range errc {
		if err != nil && err != io.EOF && err != context.Canceled && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// SafeCopy performs a copy operation with panic recovery and directional context
func SafeCopy(dst io.Writer, src io.Reader, srcName, dstName string) (n int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during copy from %s to %s: %v", srcName, dstName, r)
		}
	}()

	return CopyWithContext(dst, src, srcName, dstName)
}