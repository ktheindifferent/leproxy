#!/bin/bash

# LeProxy Admin Web Utility Startup Script

echo "Starting LeProxy Admin Web Utility..."
echo "================================================"
echo "Admin Interface: http://localhost:8090"
echo "================================================"
echo ""

# Set configuration file paths (relative to repository root)
export LEPROXY_HTTP_CONFIG="${LEPROXY_HTTP_CONFIG:-../mapping.yml}"
export LEPROXY_DB_CONFIG="${LEPROXY_DB_CONFIG:-../dbproxy_config.yml}"

# Optional: Set authentication credentials for security
# Uncomment and modify these lines to enable basic authentication
# export LEPROXY_ADMIN_USER="admin"
# export LEPROXY_ADMIN_PASS="changeme"

# Change to admin directory
cd "$(dirname "$0")"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go to run the admin utility."
    exit 1
fi

# Display security warning if no auth is set
if [ -z "$LEPROXY_ADMIN_USER" ] || [ -z "$LEPROXY_ADMIN_PASS" ]; then
    echo "⚠️  WARNING: Running without authentication!"
    echo "   Set LEPROXY_ADMIN_USER and LEPROXY_ADMIN_PASS environment variables for security."
    echo ""
fi

# Run the admin server
echo "Starting server on port 8090..."
go run server.go