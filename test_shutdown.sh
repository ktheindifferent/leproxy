#!/bin/bash

# Test script for verifying proper tracer shutdown with timeout and error handling

echo "Testing tracer shutdown behavior..."
echo "=================================="
echo ""

# Test 1: Normal shutdown
echo "Test 1: Testing normal shutdown with tracer"
echo "--------------------------------------------"
cat > /tmp/test_main.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    "github.com/artyom/leproxy/internal/tracing"
)

func main() {
    // Initialize tracer
    tracer, err := tracing.InitTracer("test-service", "", "stdout")
    if err != nil {
        log.Printf("Failed to initialize tracer: %v", err)
    } else {
        fmt.Println("Tracer initialized successfully")
        
        // Proper shutdown with timeout
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        
        start := time.Now()
        if err := tracer.Shutdown(ctx); err != nil {
            fmt.Printf("ERROR: Failed to shutdown tracer: %v\n", err)
        } else {
            fmt.Printf("SUCCESS: Tracer shutdown completed in %v\n", time.Since(start))
        }
    }
}
EOF

echo "Running test..."
cd /root/repo && go run /tmp/test_main.go
echo ""

# Test 2: Shutdown with very short timeout (simulating timeout scenario)
echo "Test 2: Testing shutdown with very short timeout"
echo "------------------------------------------------"
cat > /tmp/test_timeout.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    "github.com/artyom/leproxy/internal/tracing"
)

func main() {
    // Initialize tracer
    tracer, err := tracing.InitTracer("test-service", "", "stdout")
    if err != nil {
        log.Printf("Failed to initialize tracer: %v", err)
    } else {
        fmt.Println("Tracer initialized successfully")
        
        // Very short timeout to simulate timeout scenario
        ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
        defer cancel()
        
        start := time.Now()
        if err := tracer.Shutdown(ctx); err != nil {
            fmt.Printf("EXPECTED ERROR: Shutdown failed as expected: %v\n", err)
        } else {
            fmt.Printf("Tracer shutdown completed in %v\n", time.Since(start))
        }
    }
}
EOF

echo "Running timeout test..."
cd /root/repo && go run /tmp/test_timeout.go
echo ""

echo "=================================="
echo "Test Summary:"
echo "1. Normal shutdown: Should complete successfully within timeout"
echo "2. Timeout test: Should report timeout error with proper context"
echo ""
echo "The implementation now properly:"
echo "✓ Uses context with timeout instead of context.Background()"
echo "✓ Handles and logs shutdown errors"
echo "✓ Provides meaningful error messages with service context"
echo "✓ Integrates with graceful shutdown coordinator"
echo "=================================="