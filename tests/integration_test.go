// +build integration

package tests

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/artyom/leproxy/dbproxy"
	"github.com/artyom/leproxy/internal/pool"
	_ "github.com/lib/pq"
	_ "github.com/go-sql-driver/mysql"
)

// TestPostgresProxy tests PostgreSQL proxy functionality
func TestPostgresProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start PostgreSQL proxy
	proxy := dbproxy.NewPostgresProxy("localhost:5432", nil)
	listener, err := net.Listen("tcp", "localhost:15432")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go proxy.Serve(listener)

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Test connection through proxy
	db, err := sql.Open("postgres", "host=localhost port=15432 user=test password=test dbname=test sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Test basic query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		t.Errorf("Failed to ping database: %v", err)
	}

	// Test query execution
	var result int
	err = db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		t.Errorf("Failed to execute query: %v", err)
	}

	if result != 1 {
		t.Errorf("Expected 1, got %d", result)
	}
}

// TestMySQLProxy tests MySQL proxy functionality
func TestMySQLProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start MySQL proxy
	proxy := &dbproxy.MySQLProxy{
		Backend:   "localhost:3306",
		EnableTLS: false,
	}

	listener, err := net.Listen("tcp", "localhost:13306")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go proxy.Serve(listener)

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Test connection through proxy
	db, err := sql.Open("mysql", "test:test@tcp(localhost:13306)/test")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Test basic query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		t.Errorf("Failed to ping database: %v", err)
	}

	// Test query execution
	var result int
	err = db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		t.Errorf("Failed to execute query: %v", err)
	}

	if result != 1 {
		t.Errorf("Expected 1, got %d", result)
	}
}

// TestConnectionPool tests connection pooling functionality
func TestConnectionPool(t *testing.T) {
	// Create a connection factory
	factory := func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "tcp", "localhost:5432")
	}

	// Create pool
	p, err := pool.New(pool.Config{
		Factory:     factory,
		MinConns:    2,
		MaxConns:    10,
		MaxLifetime: 30 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer p.Close()

	// Test getting connections
	ctx := context.Background()
	conns := make([]net.Conn, 0)

	// Get multiple connections
	for i := 0; i < 5; i++ {
		conn, err := p.Get(ctx)
		if err != nil {
			t.Errorf("Failed to get connection %d: %v", i, err)
			continue
		}
		conns = append(conns, conn)
	}

	// Check pool statistics
	stats := p.Stats()
	if stats.Active != 5 {
		t.Errorf("Expected 5 active connections, got %d", stats.Active)
	}

	// Return connections to pool
	for _, conn := range conns {
		conn.Close()
	}

	// Give time for connections to return
	time.Sleep(100 * time.Millisecond)

	// Check pool statistics again
	stats = p.Stats()
	if stats.Active != 0 {
		t.Errorf("Expected 0 active connections after closing, got %d", stats.Active)
	}
}

// TestProxyWithPooling tests database proxy with connection pooling
func TestProxyWithPooling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create pooled proxy configuration
	poolManager := pool.NewPoolManager()
	defer poolManager.CloseAll()

	// Create connection factory for PostgreSQL
	factory := func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "tcp", "localhost:5432")
	}

	// Get or create pool for this backend
	p, err := poolManager.GetPool("postgres-backend", pool.Config{
		Factory:     factory,
		MinConns:    2,
		MaxConns:    10,
		MaxLifetime: 30 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Failed to get pool: %v", err)
	}

	// Simulate multiple concurrent connections
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := p.Get(ctx)
			if err != nil {
				t.Errorf("Worker %d: Failed to get connection: %v", id, err)
				return
			}
			defer conn.Close()

			// Simulate work
			time.Sleep(100 * time.Millisecond)
		}(i)
	}

	// Wait for all workers
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check final pool statistics
	stats := p.Stats()
	t.Logf("Pool stats - Created: %d, Active: %d, Idle: %d, Closed: %d",
		stats.Created, stats.Active, stats.Idle, stats.Closed)
}

// BenchmarkConnectionPool benchmarks connection pool performance
func BenchmarkConnectionPool(b *testing.B) {
	factory := func(ctx context.Context) (net.Conn, error) {
		// Mock connection for benchmarking
		return &mockConn{}, nil
	}

	p, err := pool.New(pool.Config{
		Factory:     factory,
		MinConns:    5,
		MaxConns:    20,
		MaxLifetime: 30 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	})
	if err != nil {
		b.Fatalf("Failed to create pool: %v", err)
	}
	defer p.Close()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := p.Get(ctx)
			if err != nil {
				b.Errorf("Failed to get connection: %v", err)
				continue
			}
			conn.Close()
		}
	})

	stats := p.Stats()
	b.Logf("Pool stats - Created: %d, Active: %d, Idle: %d, Closed: %d",
		stats.Created, stats.Active, stats.Idle, stats.Closed)
}

// mockConn is a mock connection for testing
type mockConn struct {
	net.Conn
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestRedisProxy tests Redis proxy functionality
func TestRedisProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start Redis proxy
	proxy := &dbproxy.RedisProxy{
		Backend:   "localhost:6379",
		EnableTLS: false,
	}

	listener, err := net.Listen("tcp", "localhost:16379")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn)
		}
	}()

	// Test connection through proxy
	conn, err := net.Dial("tcp", "localhost:16379")
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send PING command
	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if err != nil {
		t.Errorf("Failed to send PING: %v", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Errorf("Failed to read response: %v", err)
	}

	response := string(buf[:n])
	if response != "+PONG\r\n" {
		t.Errorf("Expected +PONG, got %s", response)
	}
}

// TestMongoDBProxy tests MongoDB proxy functionality
func TestMongoDBProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start MongoDB proxy
	proxy := &dbproxy.MongoDBProxy{
		Backend:   "localhost:27017",
		EnableTLS: false,
	}

	listener, err := net.Listen("tcp", "localhost:27018")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn)
		}
	}()

	// Test connection through proxy
	conn, err := net.Dial("tcp", "localhost:27018")
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Basic connection test
	// In a real test, you would send MongoDB wire protocol messages
	t.Log("MongoDB proxy started successfully")
}

// TestCassandraProxy tests Cassandra proxy functionality
func TestCassandraProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start Cassandra proxy
	proxy := &dbproxy.CassandraProxy{
		Backend:   "localhost:9042",
		EnableTLS: false,
	}

	listener, err := net.Listen("tcp", "localhost:19042")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn)
		}
	}()

	// Test connection through proxy
	conn, err := net.Dial("tcp", "localhost:19042")
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Basic connection test
	// In a real test, you would send CQL protocol messages
	t.Log("Cassandra proxy started successfully")
}

// TestProxyFailover tests proxy failover scenarios
func TestProxyFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test scenarios:
	// 1. Backend unavailable
	// 2. Backend becomes available
	// 3. Connection timeout
	// 4. Connection interrupted

	t.Run("BackendUnavailable", func(t *testing.T) {
		proxy := dbproxy.NewPostgresProxy("localhost:9999", nil) // Non-existent port
		listener, err := net.Listen("tcp", "localhost:15433")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		defer listener.Close()

		go proxy.Serve(listener)

		// Try to connect
		conn, err := net.Dial("tcp", "localhost:15433")
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Connection should be closed by proxy when backend fails
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("Expected connection to be closed")
		}
	})

	t.Run("ConnectionTimeout", func(t *testing.T) {
		// Create a listener that accepts but never responds
		backend, err := net.Listen("tcp", "localhost:15434")
		if err != nil {
			t.Fatalf("Failed to create backend listener: %v", err)
		}
		defer backend.Close()

		go func() {
			conn, _ := backend.Accept()
			if conn != nil {
				// Accept but don't respond
				time.Sleep(10 * time.Second)
				conn.Close()
			}
		}()

		// Test timeout handling
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		d := net.Dialer{Timeout: 1 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", "localhost:15434")
		if err != nil {
			// This is expected in some cases
			return
		}
		defer conn.Close()

		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		if err == nil {
			t.Error("Expected timeout error")
		}
	})
}