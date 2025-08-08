# LeProxy Admin Web Utility

A web-based administration interface for managing LeProxy configuration files.

## Features

- **HTTP/HTTPS Proxy Mappings**: Manage hostname-to-backend mappings
- **Database & Service Proxies**: Configure TLS proxy support for various services
- **Real-time Configuration**: Load and save configuration changes
- **User-friendly Interface**: Modern web UI with intuitive controls

## Supported Service Types

- Databases: PostgreSQL, MySQL, MongoDB, Redis, MSSQL, Cassandra
- Services: LDAP, SMTP, FTP, Elasticsearch, RabbitMQ (AMQP), Kafka, Memcached

## Installation & Usage

### Quick Start

1. Navigate to the admin directory:
   ```bash
   cd admin/
   ```

2. Run the startup script:
   ```bash
   ./start-admin.sh
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8090
   ```

### Manual Start

If you prefer to run manually or customize the configuration:

```bash
# Set configuration file paths (optional)
export LEPROXY_HTTP_CONFIG="path/to/mapping.yml"
export LEPROXY_DB_CONFIG="path/to/dbproxy_config.yml"

# Run the server
go run admin/server.go
```

## Configuration

The admin utility uses the following environment variables:

- `LEPROXY_HTTP_CONFIG`: Path to HTTP mappings file (default: `mapping.yml`)
- `LEPROXY_DB_CONFIG`: Path to database proxy config file (default: `dbproxy_config.yml`)

## Port Configuration

The admin utility runs on port **8090** by default to avoid conflicts with the main proxy operations (typically on ports 80/443).

## Usage Guide

### HTTP Mappings Tab

1. **Add Mapping**: Click "+ Add Mapping" and enter the hostname
2. **Edit**: Modify hostname or backend directly in the input fields
3. **Remove**: Click "Remove" button next to any mapping
4. **Save**: Click "Save Changes" to persist modifications
5. **Reload**: Click "Reload" to fetch latest configuration

### Database Proxies Tab

1. **Add Proxy**: Click "+ Add Proxy" to create a new proxy configuration
2. **Configure**: Set the following for each proxy:
   - Listen Host: The IP address to listen on (e.g., 0.0.0.0)
   - Listen Port: The port to listen on
   - Service Type: Select from dropdown (postgres, mysql, redis, etc.)
   - Backend Host: The actual service host
   - Backend Port: The actual service port
   - TLS: Check to enable TLS encryption
3. **Save**: Click "Save Changes" to persist modifications

## Security Considerations

- The admin interface has no authentication by default
- Consider running behind a reverse proxy with authentication
- Restrict access to port 8090 using firewall rules
- Use HTTPS when exposing to network

## File Format Examples

### HTTP Mappings (mapping.yml)
```yaml
# Format: hostname: backend
api.example.com: 127.0.0.1:8080
secure.example.com: https://backend.internal.com
app.example.com: /var/run/app.sock
```

### Database Proxies (dbproxy_config.yml)
```
# Format: host:port:type:backend_host:backend_port[:tls]
0.0.0.0:5432:postgres:internal-db.example.com:5432:tls
0.0.0.0:6379:redis:internal-redis.example.com:6379:tls
```

## Troubleshooting

- **Cannot connect to admin interface**: Ensure port 8090 is not blocked by firewall
- **Configuration not saving**: Check file permissions for mapping files
- **Changes not taking effect**: Restart the main LeProxy service after configuration changes