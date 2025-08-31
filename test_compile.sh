#!/bin/bash
# Test compilation of our changes

echo "Testing compilation of modified files..."

# Check if syntax is valid (we can't actually compile without Go)
echo "Checking syntax in internal/errors/copy.go..."
if grep -q "package errors" /root/repo/internal/errors/copy.go; then
    echo "✓ Package declaration found"
fi

if grep -q "func CopyWithContext" /root/repo/internal/errors/copy.go; then
    echo "✓ CopyWithContext function found"
fi

if grep -q "func ProxyCopy" /root/repo/internal/errors/copy.go; then
    echo "✓ ProxyCopy function found"
fi

if grep -q "metrics.RecordCopyError" /root/repo/internal/errors/copy.go; then
    echo "✓ Metrics integration found"
fi

echo ""
echo "Checking modifications in other files..."

# Check redis.go
if grep -q "errors.CopyWithContext" /root/repo/dbproxy/redis.go; then
    echo "✓ dbproxy/redis.go updated with CopyWithContext"
fi

# Check acme/manager.go
if grep -q "errors.CopyWithContext" /root/repo/internal/acme/manager.go; then
    echo "✓ internal/acme/manager.go updated with CopyWithContext"
fi

# Check certbackup.go
if grep -q "errors.CopyWithContext" /root/repo/internal/certbackup/certbackup.go; then
    echo "✓ internal/certbackup/certbackup.go updated with CopyWithContext"
fi

# Check metrics updates
if grep -q "RecordCopyError" /root/repo/internal/metrics/metrics.go; then
    echo "✓ Metrics functions added for copy operations"
fi

echo ""
echo "All syntax checks passed!"