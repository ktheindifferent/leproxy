#!/bin/bash

# Test script for new proxy services
echo "Testing new database proxy services..."

# Create a test configuration file
cat > test-dbproxy.conf <<EOF
# Test configuration for new proxy services
# MySQL proxy
0.0.0.0:3306:mysql:mysql.internal:3306:tls

# Redis proxy  
0.0.0.0:6379:redis:redis.internal:6379:tls

# MongoDB proxy
0.0.0.0:27017:mongodb:mongodb.internal:27017:tls

# Multiple instances of same service type
0.0.0.0:3307:mysql:mysql2.internal:3306
0.0.0.0:6380:redis:redis2.internal:6379
0.0.0.0:27018:mongo:mongodb2.internal:27017
EOF

echo "Configuration file created: test-dbproxy.conf"
echo ""
echo "To run the proxy with the new services:"
echo "  ./leproxy -dbmap test-dbproxy.conf -dbcerts /tmp/dbcerts"
echo ""
echo "Supported proxy types:"
echo "  - MySQL (port 3306)"
echo "  - Redis (port 6379)"  
echo "  - MongoDB (port 27017)"
echo "  - MSSQL (port 1433) [existing]"
echo "  - PostgreSQL (port 5432) [existing]"
echo ""
echo "Connection examples:"
echo "  MySQL:   mysql -h localhost -P 3306 -u user -p --ssl-mode=REQUIRED"
echo "  Redis:   redis-cli -h localhost -p 6379 --tls"
echo "  MongoDB: mongosh 'mongodb://localhost:27017/?tls=true&tlsAllowInvalidCertificates=true'"