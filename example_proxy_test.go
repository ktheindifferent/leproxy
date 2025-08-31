package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/artyom/leproxy/internal/proxy"
)

// This example demonstrates the fixed proxy factory with proper goroutine lifecycle management
func ExampleProxyFactory() {
	// Create factory and manager
	factory := proxy.NewFactory()
	manager := proxy.NewManager(factory)

	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	// Configure proxy
	config := &proxy.Config{
		ListenAddr: addr,
		Backend:    "127.0.0.1:3306", // MySQL backend
		Type:       proxy.TypeMySQL,
	}

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start proxy with context support
	err = manager.StartProxyWithContext(ctx, config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Proxy started on %s\n", addr)

	// Simulate some work
	time.Sleep(2 * time.Second)

	// Get proxy status
	status := manager.GetStatus()
	for addr, s := range status {
		fmt.Printf("Proxy %s: Type=%s, Connections=%d\n", 
			addr, s.Type, s.Connections)
	}

	// Stop proxy gracefully
	err = manager.StopProxy(addr)
	if err != nil {
		log.Printf("Error stopping proxy: %v", err)
	}

	fmt.Println("Proxy stopped successfully")
}

func main() {
	ExampleProxyFactory()
}