#!/bin/bash

# Test script for database proxy functionality

echo "Database Proxy Test Configuration"
echo "================================="
echo ""

# Create a test configuration file
cat > dbproxy-test.conf <<EOF
# Test MSSQL proxy with TLS
localhost:11433:mssql:actual-mssql-server.example.com:1433:tls

# Test PostgreSQL proxy with TLS  
localhost:15432:postgres:actual-postgres-server.example.com:5432:tls

# Test without TLS
localhost:15433:postgres:another-postgres.example.com:5432
EOF

echo "Created test configuration file: dbproxy-test.conf"
echo ""
echo "Configuration contents:"
cat dbproxy-test.conf
echo ""

echo "To run the proxy with database support:"
echo "----------------------------------------"
echo "./leproxy \\"
echo "  -addr :443 \\"
echo "  -map mapping.yml \\"
echo "  -cacheDir /var/cache/letsencrypt \\"
echo "  -dbmap dbproxy-test.conf \\"
echo "  -dbcerts /tmp/dbproxy-certs"
echo ""

echo "Test connections:"
echo "-----------------"
echo "# For MSSQL (requires sqlcmd or similar):"
echo "sqlcmd -S localhost,11433 -U username -P password -Q \"SELECT @@VERSION\""
echo ""
echo "# For PostgreSQL (requires psql):"
echo "psql \"host=localhost port=15432 dbname=mydb user=myuser sslmode=require\""
echo ""

# Create certificate directory
mkdir -p /tmp/dbproxy-certs
echo "Created temporary certificate directory: /tmp/dbproxy-certs"