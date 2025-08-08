Command leproxy implements an advanced HTTPS reverse proxy with automatic ACME certificate
management (Let's Encrypt/ZeroSSL) for multiple hostnames/backends, plus TLS proxy support
for databases and various network services

Install:

	go get github.com/artyom/leproxy	

Run with Let's Encrypt (default):

	leproxy -addr :https -map /path/to/mapping.yml -cacheDir /path/to/certificates

Run with ZeroSSL:

	leproxy -addr :https -map /path/to/mapping.yml -cacheDir /path/to/certificates \
	        -provider zerossl -email your@email.com \
	        -eab-kid YOUR_EAB_KID -eab-hmac YOUR_EAB_HMAC_KEY

Run with Let's Encrypt staging (for testing):

	leproxy -addr :https -map /path/to/mapping.yml -cacheDir /path/to/certificates \
	        -provider letsencrypt-staging

`mapping.yml` contains host-to-backend mapping, where backend can be specified as:

 * http/https url for http(s) connections to backend *without* passing "Host"
   header from request;
 * host:port for http over TCP connections to backend;
 * absolute path for http over unix socket connections;
 * @name for http over abstract unix socket connections (linux only);
 * absolute path with trailing slash to serve files from given directory.

Example:

	subdomain1.example.com: 127.0.0.1:8080
	subdomain2.example.com: /var/run/http.socket
	subdomain3.example.com: @abstractUnixSocket
	uploads.example.com: https://uploads-bucket.s3.amazonaws.com
	static.example.com: /var/www/

## New Features: Database and Service Proxy Support

Leproxy now includes comprehensive TLS proxy support for databases and various network services,
allowing you to add TLS encryption to services that don't natively support it or to terminate
TLS at the proxy level.

### Supported Services

#### Databases
- **PostgreSQL** - Full protocol support with SSL negotiation
- **MySQL/MariaDB** - SSL/TLS negotiation support
- **MSSQL (SQL Server)** - TDS protocol with TLS negotiation
- **MongoDB** - Wire protocol with TLS support
- **Redis** - RESP protocol with STARTTLS and direct TLS
- **Cassandra** - CQL protocol with TLS encryption
- **Memcached** - Text and binary protocol support

#### Network Services
- **LDAP/LDAPS** - Directory services with StartTLS and implicit TLS
- **SMTP/SMTPS** - Email with STARTTLS command support
- **FTP/FTPS** - File transfer with AUTH TLS/SSL commands
- **Elasticsearch** - REST API with TLS encryption
- **RabbitMQ/AMQP** - Message queuing with AMQP 0-9-1 protocol
- **Apache Kafka** - Event streaming with TLS support

### Database Proxy Configuration

To enable database/service proxying, use the `-dbmap` flag with a configuration file:

```bash
leproxy \
  -addr :https \
  -map mapping.yml \
  -cacheDir /var/cache/letsencrypt \
  -dbmap dbproxy-mapping.conf \
  -dbcerts /var/cache/dbproxy-certs
```

Configuration file format:
```
# Format: host:port:type:backend_host:backend_port[:tls]
0.0.0.0:5432:postgres:internal-db.example.com:5432:tls
0.0.0.0:3306:mysql:mysql.internal:3306:tls
0.0.0.0:27017:mongodb:mongo.internal:27017:tls
0.0.0.0:6379:redis:redis.internal:6379:tls
0.0.0.0:9093:kafka:kafka-broker:9092:tls
```

For detailed database proxy documentation, see [README-DBPROXY.md](README-DBPROXY.md)
For TLS proxy services documentation, see [TLS_PROXY_SERVICES.md](TLS_PROXY_SERVICES.md)

Note that when `@name` backend is specified, connection to abstract unix socket
is made in a manner compatible with some other implementations like uWSGI, that
calculate addrlen including trailing zero byte despite [documentation not
requiring that](http://man7.org/linux/man-pages/man7/unix.7.html). It won't
work with other implementations that calculate addrlen differently (i.e. by
taking into account only `strlen(addr)` like Go, or even `UNIX_PATH_MAX`).

## Command-line Options

### Core Proxy Options
* `-addr` - HTTPS listen address (default: `:https`)
* `-http` - HTTP listen address for redirects and ACME challenges (default: `:http`)
* `-map` - Path to mapping configuration file (default: `mapping.yml`)
* `-cacheDir` - Directory to cache certificates (default: `/var/cache/letsencrypt`)
* `-email` - Contact email for ACME provider (required for ZeroSSL)
* `-hsts` - Add Strict-Transport-Security header with preload directive

### ACME Provider Options
* `-provider` - ACME provider: `letsencrypt` (default), `zerossl`, or `letsencrypt-staging`
* `-acme-url` - Custom ACME directory URL (overrides provider)
* `-eab-kid` - EAB Key ID for ZeroSSL (required for ZeroSSL)
* `-eab-hmac` - EAB HMAC key for ZeroSSL (required for ZeroSSL)

### Timeout Options
* `-rto` - Read timeout duration
* `-wto` - Write timeout duration
* `-idle` - Idle connection timeout

### Database/Service Proxy Options (New)
* `-dbmap` - Path to database/service proxy configuration file
* `-dbcerts` - Directory to cache database certificates (default: `/var/cache/dbproxy-certs`)

## ACME Providers

### Let's Encrypt (default)
Free SSL certificates, no registration required. Rate limits apply.

### ZeroSSL
Free SSL certificates with registration. Requires EAB (External Account Binding) credentials.
1. Sign up at https://app.zerossl.com/signup
2. Get your EAB credentials from https://app.zerossl.com/developer
3. Use the `-eab-kid` and `-eab-hmac` flags with your credentials

### Custom ACME Provider
Use the `-acme-url` flag to specify any RFC 8555 compliant ACME server.

## Quick Start Examples

### Basic HTTPS Reverse Proxy
```bash
# Simple reverse proxy with Let's Encrypt
leproxy -addr :443 -map mapping.yml -cacheDir /var/cache/certs
```

### Database Proxy with TLS
```bash
# Create database proxy configuration
cat > dbproxy.conf <<EOF
0.0.0.0:5432:postgres:db.internal:5432:tls
0.0.0.0:3306:mysql:mysql.internal:3306:tls
EOF

# Run with database proxy support
leproxy \
  -addr :443 \
  -map mapping.yml \
  -dbmap dbproxy.conf \
  -dbcerts /var/cache/dbcerts
```

### Full Production Setup
```bash
# Complete setup with HTTPS proxy, database proxy, and HSTS
leproxy \
  -addr :443 \
  -http :80 \
  -map /etc/leproxy/mapping.yml \
  -cacheDir /var/cache/letsencrypt \
  -dbmap /etc/leproxy/dbproxy.conf \
  -dbcerts /var/cache/dbproxy-certs \
  -hsts \
  -email admin@example.com \
  -rto 30s \
  -wto 2m
```

## Key Features

- **Automatic HTTPS**: Automatic certificate generation and renewal via ACME (Let's Encrypt/ZeroSSL)
- **Multiple Backends**: Support for HTTP, HTTPS, Unix sockets, and static file serving
- **Database Proxying**: TLS termination for PostgreSQL, MySQL, MongoDB, Redis, and more
- **Service Proxying**: TLS support for LDAP, SMTP, FTP, Elasticsearch, Kafka, and other services
- **Protocol-Aware**: Understands database and service protocols for proper TLS negotiation
- **Certificate Caching**: Efficient certificate storage and automatic regeneration
- **HSTS Support**: Strict-Transport-Security header with preload directive
- **Flexible Configuration**: YAML-based configuration for easy management

## Documentation

- [Database Proxy Documentation](README-DBPROXY.md) - Detailed guide for database proxying
- [TLS Proxy Services](TLS_PROXY_SERVICES.md) - Complete list of supported services
- [Example Configurations](dbproxy-mapping.example) - Sample configuration files

## License

See [LICENSE.txt](LICENSE.txt) for details.
