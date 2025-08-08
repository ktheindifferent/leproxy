# Database Proxy Features

This enhanced version of leproxy now includes support for proxying database connections with automatic TLS certificate generation.

## Supported Database Types

- **MSSQL (SQL Server)**: Full support for TDS protocol with TLS negotiation
- **PostgreSQL**: Full support for PostgreSQL protocol with SSL negotiation
- **MySQL**: Full support for MySQL protocol with SSL/TLS negotiation
- **Redis**: Full support for Redis protocol with STARTTLS and direct TLS
- **MongoDB**: Full support for MongoDB wire protocol with TLS

## Features

- **Automatic Certificate Generation**: Automatically generates and caches TLS certificates for secure database connections
- **Protocol-Aware Proxying**: Understands database protocols for proper TLS/SSL negotiation
- **Multiple Backend Support**: Can proxy multiple database servers simultaneously
- **Certificate Caching**: Certificates are cached and reused, automatically regenerated when expired

## Configuration

### Command Line Arguments

New command line arguments have been added:

```bash
leproxy \
  -addr :https \
  -map /path/to/mapping.yml \
  -cacheDir /path/to/letsencrypt \
  -dbmap /path/to/dbproxy-mapping.conf \
  -dbcerts /path/to/db-certificates
```

- `-dbmap`: Path to database proxy configuration file
- `-dbcerts`: Path to directory for caching database certificates (default: `/var/cache/dbproxy-certs`)

### Database Proxy Configuration File

Create a configuration file with the following format:

```
# Format: host:port:type:backend_host:backend_port[:tls]
0.0.0.0:1433:mssql:internal-mssql.example.com:1433:tls
0.0.0.0:5432:postgres:internal-postgres.example.com:5432:tls
```

Each line specifies:
- `host:port`: The address to listen on for incoming connections
- `type`: Database type (`mssql`, `postgres`/`postgresql`, `mysql`, `redis`, `mongodb`/`mongo`)
- `backend_host:backend_port`: The actual database server to proxy to
- `:tls` (optional): Enable automatic TLS certificate generation

## Usage Examples

### Example 1: MSSQL with TLS

```bash
# Configuration line in dbproxy-mapping.conf:
0.0.0.0:1433:mssql:sql-server.internal:1433:tls

# Connect using SQL Server Management Studio or sqlcmd:
sqlcmd -S your-proxy-host,1433 -U username -P password -Q "SELECT @@VERSION"
```

### Example 2: PostgreSQL with TLS

```bash
# Configuration line in dbproxy-mapping.conf:
0.0.0.0:5432:postgres:postgres.internal:5432:tls

# Connect using psql:
psql "host=your-proxy-host port=5432 dbname=mydb user=myuser sslmode=require"
```

### Example 3: MySQL with TLS

```bash
# Configuration line in dbproxy-mapping.conf:
0.0.0.0:3306:mysql:mysql.internal:3306:tls

# Connect using mysql client:
mysql -h your-proxy-host -P 3306 -u username -p --ssl-mode=REQUIRED
```

### Example 4: Redis with TLS

```bash
# Configuration line in dbproxy-mapping.conf:
0.0.0.0:6379:redis:redis.internal:6379:tls

# Connect using redis-cli with TLS:
redis-cli -h your-proxy-host -p 6379 --tls
```

### Example 5: MongoDB with TLS

```bash
# Configuration line in dbproxy-mapping.conf:
0.0.0.0:27017:mongodb:mongodb.internal:27017:tls

# Connect using mongosh:
mongosh "mongodb://your-proxy-host:27017/?tls=true&tlsAllowInvalidCertificates=true"
```

### Example 6: Multiple Databases

```bash
# dbproxy-mapping.conf:
0.0.0.0:1433:mssql:sqlserver1.internal:1433:tls
0.0.0.0:1434:mssql:sqlserver2.internal:1433:tls
0.0.0.0:5432:postgres:postgres1.internal:5432:tls
0.0.0.0:5433:postgres:postgres2.internal:5432:tls
0.0.0.0:3306:mysql:mysql1.internal:3306:tls
0.0.0.0:6379:redis:redis1.internal:6379:tls
0.0.0.0:27017:mongodb:mongodb1.internal:27017:tls
```

## How It Works

### TLS Certificate Generation

1. When a database proxy with `:tls` is configured, the proxy automatically generates a self-signed certificate
2. Certificates are stored in the directory specified by `-dbcerts`
3. Certificates are valid for 365 days and automatically regenerated when expired
4. Each host gets its own certificate based on the listening address

### Protocol Handling

#### MSSQL (TDS Protocol)
- Intercepts the TDS prelogin packet
- Negotiates TLS when requested by the client
- Maintains protocol compatibility with SQL Server

#### PostgreSQL
- Intercepts SSL negotiation requests (SSLRequest packet)
- Handles SSL upgrade when supported by both client and backend
- Maintains protocol compatibility with PostgreSQL

#### MySQL
- Intercepts the initial handshake packet
- Checks for SSL capability flags
- Negotiates TLS when requested by the client
- Maintains protocol compatibility with MySQL/MariaDB

#### Redis
- Supports both STARTTLS command and direct TLS connections
- Handles RESP protocol for command parsing
- Maintains protocol compatibility with Redis

#### MongoDB
- Supports MongoDB wire protocol
- Handles direct TLS connections
- Intercepts and forwards wire protocol messages
- Maintains protocol compatibility with MongoDB

## Security Considerations

1. **Self-Signed Certificates**: The automatically generated certificates are self-signed. For production use, consider:
   - Configuring clients to accept the specific certificate
   - Using proper CA-signed certificates
   - Implementing certificate pinning

2. **Backend Connections**: When connecting to backend databases:
   - The proxy validates backend certificates by default
   - For development, the proxy can be configured to skip verification
   - Always use TLS for backend connections in production

3. **Access Control**: The proxy itself doesn't implement authentication. Ensure:
   - Network-level access controls are in place
   - Database authentication is properly configured
   - Firewall rules restrict access to the proxy

## Troubleshooting

### Certificate Issues

If you encounter certificate errors:

1. Check the certificate cache directory permissions:
   ```bash
   ls -la /var/cache/dbproxy-certs/
   ```

2. Clear the certificate cache to force regeneration:
   ```bash
   rm /var/cache/dbproxy-certs/*.{crt,key}
   ```

3. Verify certificate generation in logs:
   ```bash
   leproxy -dbmap dbproxy.conf -dbcerts /tmp/certs 2>&1 | grep -i cert
   ```

### Connection Issues

1. Test basic connectivity:
   ```bash
   telnet proxy-host 1433  # For MSSQL
   telnet proxy-host 5432  # For PostgreSQL
   telnet proxy-host 3306  # For MySQL
   telnet proxy-host 6379  # For Redis
   telnet proxy-host 27017 # For MongoDB
   ```

2. Check proxy logs for error messages

3. Verify backend database is accessible:
   ```bash
   nc -zv backend-host backend-port
   ```

## Full Example Setup

```bash
# 1. Create configuration file
cat > /etc/leproxy/dbproxy.conf <<EOF
# Production MSSQL
0.0.0.0:1433:mssql:prod-sql.internal:1433:tls

# Development PostgreSQL
0.0.0.0:5432:postgres:dev-postgres.internal:5432:tls
EOF

# 2. Create certificate directory
mkdir -p /var/cache/dbproxy-certs
chmod 700 /var/cache/dbproxy-certs

# 3. Run leproxy with database proxy support
leproxy \
  -addr :443 \
  -map /etc/leproxy/mapping.yml \
  -cacheDir /var/cache/letsencrypt \
  -dbmap /etc/leproxy/dbproxy.conf \
  -dbcerts /var/cache/dbproxy-certs

# 4. Test connections
# MSSQL
sqlcmd -S localhost,1433 -U sa -P YourPassword -Q "SELECT 1"

# PostgreSQL  
psql "host=localhost port=5432 dbname=postgres user=postgres sslmode=require"
```

## Limitations

- Certificates are self-signed (not from a trusted CA)
- No built-in connection pooling or load balancing
- Redis STARTTLS support depends on client implementation
- MongoDB TLS requires client to support TLS from connection start