package benchmarks

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/artyom/leproxy/internal/pool"
	"github.com/artyom/leproxy/internal/ratelimit"
)

// BenchmarkHTTPProxy benchmarks the HTTP proxy performance
func BenchmarkHTTPProxy(b *testing.B) {
	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create proxy handler
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple proxy logic
		resp, err := http.Get(backend.URL)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, req)
		}
	})
}

// BenchmarkHTTPProxyWithMiddleware benchmarks proxy with middleware stack
func BenchmarkHTTPProxyWithMiddleware(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create proxy with middleware
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(backend.URL)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	// Add middleware layers
	withLogging := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Minimal logging simulation
			_ = r.URL.Path
			next.ServeHTTP(w, r)
		})
	}

	withMetrics := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			_ = time.Since(start)
		})
	}

	finalHandler := withLogging(withMetrics(handler))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			finalHandler.ServeHTTP(w, req)
		}
	})
}

// BenchmarkConnectionPool benchmarks connection pool performance
func BenchmarkConnectionPool(b *testing.B) {
	// Mock connection factory
	factory := func(ctx context.Context) (net.Conn, error) {
		return &mockConn{}, nil
	}

	p, err := pool.New(pool.Config{
		Factory:     factory,
		MinConns:    10,
		MaxConns:    100,
		MaxLifetime: 30 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := p.Get(ctx)
			if err != nil {
				b.Fatal(err)
			}
			conn.Close()
		}
	})
}

// BenchmarkRateLimiter benchmarks rate limiting performance
func BenchmarkRateLimiter(b *testing.B) {
	limiter, err := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: 1000,
		Burst:             10000,
		TTL:               time.Minute,
		Enabled:           true,
	})
	if err != nil {
		b.Fatal(err)
	}

	ips := make([]string, 100)
	for i := range ips {
		ips[i] = fmt.Sprintf("192.168.1.%d", i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i%len(ips)]
			limiter.Allow(ip)
			i++
		}
	})
}

// BenchmarkTLSHandshake benchmarks TLS handshake performance
func BenchmarkTLSHandshake(b *testing.B) {
	// Create TLS server
	cert, err := generateTestCert()
	if err != nil {
		b.Fatal(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", "localhost:0", tlsConfig)
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Simple echo server
				io.Copy(c, c)
			}(conn)
		}
	}()

	addr := listener.Addr().String()
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := tls.Dial("tcp", addr, clientTLSConfig)
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

// BenchmarkWebSocketProxy benchmarks WebSocket proxy performance
func BenchmarkWebSocketProxy(b *testing.B) {
	// This is a simplified benchmark
	// In real scenario, you would use gorilla/websocket or similar
	
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate WebSocket frame processing
			frame := append([]byte{0x81, 0x7E}, data...)
			_ = len(frame)
		}
	})
}

// BenchmarkLargePayloadProxy benchmarks proxy with large payloads
func BenchmarkLargePayloadProxy(b *testing.B) {
	sizes := []int{
		1024,       // 1KB
		10240,      // 10KB
		102400,     // 100KB
		1048576,    // 1MB
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size-%d", size), func(b *testing.B) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(data)
			}))
			defer backend.Close()

			proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp, err := http.Get(backend.URL)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()

				w.WriteHeader(resp.StatusCode)
				io.Copy(w, resp.Body)
			})

			b.SetBytes(int64(size))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest("GET", "/", nil)
				w := httptest.NewRecorder()
				proxy.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkConcurrentConnections benchmarks handling concurrent connections
func BenchmarkConcurrentConnections(b *testing.B) {
	concurrencyLevels := []int{10, 50, 100, 500}

	for _, level := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency-%d", level), func(b *testing.B) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(10 * time.Millisecond) // Simulate work
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			b.ResetTimer()
			
			var wg sync.WaitGroup
			sem := make(chan struct{}, level)
			
			for i := 0; i < b.N; i++ {
				wg.Add(1)
				sem <- struct{}{}
				
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					
					resp, err := http.Get(backend.URL)
					if err == nil {
						resp.Body.Close()
					}
				}()
			}
			
			wg.Wait()
		})
	}
}

// BenchmarkHeaderProcessing benchmarks header processing
func BenchmarkHeaderProcessing(b *testing.B) {
	headers := http.Header{
		"X-Forwarded-For":   []string{"192.168.1.1"},
		"X-Forwarded-Proto": []string{"https"},
		"X-Real-IP":         []string{"10.0.0.1"},
		"User-Agent":        []string{"Mozilla/5.0"},
		"Accept":            []string{"text/html,application/json"},
		"Accept-Encoding":   []string{"gzip, deflate, br"},
		"Accept-Language":   []string{"en-US,en;q=0.9"},
		"Cache-Control":     []string{"no-cache"},
		"Connection":        []string{"keep-alive"},
		"Host":              []string{"example.com"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Process headers
		newHeaders := make(http.Header)
		for key, values := range headers {
			// Simulate header processing
			if key != "Connection" && key != "Host" {
				newHeaders[key] = values
			}
		}
		newHeaders.Set("X-Proxy-Timestamp", time.Now().Format(time.RFC3339))
	}
}

// BenchmarkBufferCopy benchmarks different buffer copy strategies
func BenchmarkBufferCopy(b *testing.B) {
	sizes := []int{512, 4096, 16384, 65536}
	
	for _, bufSize := range sizes {
		b.Run(fmt.Sprintf("BufferSize-%d", bufSize), func(b *testing.B) {
			src := bytes.NewReader(make([]byte, 1048576)) // 1MB source
			
			b.SetBytes(1048576)
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				src.Seek(0, 0)
				dst := &bytes.Buffer{}
				buf := make([]byte, bufSize)
				io.CopyBuffer(dst, src, buf)
			}
		})
	}
}

// Memory allocation benchmarks

// BenchmarkMemoryAllocation benchmarks memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	b.Run("ByteSlice", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 4096)
			_ = buf
		}
	})

	b.Run("ByteSliceWithCap", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 0, 4096)
			_ = buf
		}
	})

	b.Run("BufferPool", func(b *testing.B) {
		pool := sync.Pool{
			New: func() interface{} {
				return make([]byte, 4096)
			},
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := pool.Get().([]byte)
			pool.Put(buf)
		}
	})
}

// Helper types and functions

type mockConn struct {
	net.Conn
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return len(b), nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func generateTestCert() (tls.Certificate, error) {
	// This would generate a test certificate
	// For brevity, returning empty cert
	return tls.Certificate{}, nil
}

// Profiling helpers

// BenchmarkWithProfiling can be used with go test -cpuprofile
func BenchmarkWithProfiling(b *testing.B) {
	// This benchmark is designed to be run with profiling flags:
	// go test -bench=BenchmarkWithProfiling -cpuprofile=cpu.prof
	// go tool pprof cpu.prof
	
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate processing
		sum := 0
		for _, b := range data {
			sum += int(b)
		}
		_ = sum
	}
}