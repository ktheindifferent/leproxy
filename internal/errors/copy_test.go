package errors

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// mockReader simulates a reader that can return errors
type mockReader struct {
	data []byte
	err  error
	pos  int
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

// mockWriter simulates a writer that can return errors
type mockWriter struct {
	buf *bytes.Buffer
	err error
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.buf.Write(p)
}

// mockReadWriter combines reader and writer
type mockReadWriter struct {
	io.Reader
	io.Writer
}

func TestCopyWithContext(t *testing.T) {
	tests := []struct {
		name      string
		src       io.Reader
		dst       io.Writer
		srcName   string
		dstName   string
		wantErr   bool
		errContains string
	}{
		{
			name:    "successful copy",
			src:     strings.NewReader("test data"),
			dst:     &bytes.Buffer{},
			srcName: "testSource",
			dstName: "testDest",
			wantErr: false,
		},
		{
			name:    "read error",
			src:     &mockReader{err: errors.New("read failed")},
			dst:     &bytes.Buffer{},
			srcName: "failSource",
			dstName: "testDest",
			wantErr: true,
			errContains: "copying from failSource to testDest: read failed",
		},
		{
			name:    "write error",
			src:     strings.NewReader("test data"),
			dst:     &mockWriter{buf: &bytes.Buffer{}, err: errors.New("write failed")},
			srcName: "testSource",
			dstName: "failDest",
			wantErr: true,
			errContains: "copying from testSource to failDest: write failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CopyWithContext(tt.dst, tt.src, tt.srcName, tt.dstName)
			if (err != nil) != tt.wantErr {
				t.Errorf("CopyWithContext() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("CopyWithContext() error = %v, want error containing %v", err, tt.errContains)
				}
			}
		})
	}
}

func TestProxyCopy(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (io.ReadWriter, io.ReadWriter)
		config  *ProxyCopyConfig
		wantErr bool
	}{
		{
			name: "successful bidirectional copy",
			setup: func() (io.ReadWriter, io.ReadWriter) {
				client := &mockReadWriter{
					Reader: strings.NewReader("client data"),
					Writer: &bytes.Buffer{},
				}
				backend := &mockReadWriter{
					Reader: strings.NewReader("backend data"),
					Writer: &bytes.Buffer{},
				}
				return client, backend
			},
			config:  nil,
			wantErr: false,
		},
		{
			name: "with custom config",
			setup: func() (io.ReadWriter, io.ReadWriter) {
				client := &mockReadWriter{
					Reader: strings.NewReader("client data"),
					Writer: &bytes.Buffer{},
				}
				backend := &mockReadWriter{
					Reader: strings.NewReader("backend data"),
					Writer: &bytes.Buffer{},
				}
				return client, backend
			},
			config: &ProxyCopyConfig{
				ClientName:  "webClient",
				BackendName: "dbServer",
				OnError: func(direction string, err error) {
					t.Logf("Error in direction %s: %v", direction, err)
				},
			},
			wantErr: false,
		},
		{
			name: "client read error",
			setup: func() (io.ReadWriter, io.ReadWriter) {
				client := &mockReadWriter{
					Reader: &mockReader{err: errors.New("client read error")},
					Writer: &bytes.Buffer{},
				}
				backend := &mockReadWriter{
					Reader: strings.NewReader("backend data"),
					Writer: &bytes.Buffer{},
				}
				return client, backend
			},
			config:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, backend := tt.setup()
			err := ProxyCopy(client, backend, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProxyCopy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProxyCopyWithContext(t *testing.T) {
	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		
		// Create slow readers that will block
		client := &mockReadWriter{
			Reader: &slowReader{delay: 100 * time.Millisecond},
			Writer: &bytes.Buffer{},
		}
		backend := &mockReadWriter{
			Reader: &slowReader{delay: 100 * time.Millisecond},
			Writer: &bytes.Buffer{},
		}

		// Cancel context after a short delay
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := ProxyCopyWithContext(ctx, client, backend, nil)
		// We expect no error or context.Canceled
		if err != nil && err != context.Canceled {
			t.Errorf("ProxyCopyWithContext() unexpected error = %v", err)
		}
	})

	t.Run("with error callback", func(t *testing.T) {
		var capturedDirection string
		var capturedError error

		config := &ProxyCopyConfig{
			ClientName:  "testClient",
			BackendName: "testBackend",
			OnError: func(direction string, err error) {
				capturedDirection = direction
				capturedError = err
			},
		}

		client := &mockReadWriter{
			Reader: &mockReader{err: errors.New("test error")},
			Writer: &bytes.Buffer{},
		}
		backend := &mockReadWriter{
			Reader: strings.NewReader("data"),
			Writer: &bytes.Buffer{},
		}

		ctx := context.Background()
		err := ProxyCopyWithContext(ctx, client, backend, config)

		if err == nil {
			t.Error("ProxyCopyWithContext() expected error, got nil")
		}
		if capturedDirection == "" {
			t.Error("OnError callback was not called")
		}
		if capturedError == nil {
			t.Error("OnError callback did not receive error")
		}
	})
}

func TestSafeCopy(t *testing.T) {
	t.Run("successful copy", func(t *testing.T) {
		src := strings.NewReader("test data")
		dst := &bytes.Buffer{}
		
		n, err := SafeCopy(dst, src, "source", "destination")
		if err != nil {
			t.Errorf("SafeCopy() unexpected error = %v", err)
		}
		if n != 9 { // len("test data")
			t.Errorf("SafeCopy() copied %d bytes, expected 9", n)
		}
		if dst.String() != "test data" {
			t.Errorf("SafeCopy() copied data = %q, expected %q", dst.String(), "test data")
		}
	})

	t.Run("panic recovery", func(t *testing.T) {
		src := &panicReader{}
		dst := &bytes.Buffer{}
		
		_, err := SafeCopy(dst, src, "panicSource", "destination")
		if err == nil {
			t.Error("SafeCopy() expected error from panic, got nil")
		}
		if !strings.Contains(err.Error(), "panic during copy from panicSource to destination") {
			t.Errorf("SafeCopy() error = %v, expected panic error message", err)
		}
	})
}

// Helper types for testing

type slowReader struct {
	delay time.Duration
}

func (s *slowReader) Read(p []byte) (n int, err error) {
	time.Sleep(s.delay)
	return 0, io.EOF
}

type panicReader struct{}

func (p *panicReader) Read([]byte) (n int, err error) {
	panic("test panic")
}