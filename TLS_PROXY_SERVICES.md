# TLS Proxy Services Documentation

This document describes all the TLS proxy services supported by leproxy.

## Overview

Leproxy now supports TLS termination and encryption for a wide variety of services beyond HTTPS. This allows you to:

1. Add TLS encryption to services that don't natively support it
2. Terminate TLS at the proxy level for internal non-TLS services
3. Use ACME/Let's Encrypt certificates for any TCP service
4. Provide a unified TLS management layer for all services

## Supported Services

### Web Services
- **HTTPS** - Standard web traffic (existing)

### Database Services
- **PostgreSQL** - Port 5432 (existing)
- **MySQL** - Port 3306 (existing)
- **MSSQL** - Port 1433 (existing)
- **MongoDB** - Port 27017 (existing)
- **Redis** - Port 6379 (existing)
- **Cassandra** - Port 9042 (NEW)
- **Memcached** - Port 11211 (NEW)

### Directory Services
- **LDAP/LDAPS** - Port 389/636 (NEW)
  - Supports both StartTLS and implicit TLS
  - Handles LDAP protocol negotiation

### Email Services
- **SMTP/SMTPS** - Port 25/465/587 (NEW)
  - Supports STARTTLS command
  - Works with both submission (587) and SMTPS (465) ports

### File Transfer Services
- **FTP/FTPS** - Port 21/990 (NEW)
  - Supports AUTH TLS/SSL commands
  - Handles both explicit and implicit FTPS

### Search & Analytics
- **Elasticsearch** - Port 9200 (NEW)
  - Direct TLS encryption for Elasticsearch REST API
  - Compatible with Elasticsearch clients

### Message Queuing
- **RabbitMQ/AMQP** - Port 5672/5671 (NEW)
  - AMQP 0-9-1 protocol support
  - TLS encryption for message queue traffic

### Event Streaming
- **Kafka** - Port 9092/9093 (NEW)
  - Apache Kafka protocol support
  - TLS encryption for Kafka brokers

## Configuration

Add service proxy configurations to your `dbmap` file:

```yaml
# Format: host:port:type:backend_host:backend_port[:tls]

# LDAP with TLS
0.0.0.0:636:ldap:internal-ldap:389:tls

# SMTP with TLS
0.0.0.0:465:smtp:mail-server:25:tls

# Elasticsearch with TLS
0.0.0.0:9200:elasticsearch:elastic-cluster:9200:tls

# Kafka with TLS
0.0.0.0:9093:kafka:kafka-broker:9092:tls
```

## Usage Example

```bash
# Start leproxy with database/service proxy configuration
./leproxy \
  -addr :443 \
  -map mapping.yml \
  -dbmap dbproxy_config.yml \
  -dbcerts /var/cache/dbproxy-certs \
  -cacheDir /var/cache/letsencrypt
```

## Protocol-Specific Features

### LDAP
- Handles LDAP StartTLS extension
- Supports both LDAP (389) and LDAPS (636)
- Properly negotiates TLS upgrade

### SMTP
- Implements STARTTLS command handling
- Supports submission port (587) and SMTPS (465)
- Maintains SMTP protocol compliance

### FTP
- Handles AUTH TLS/SSL commands
- Supports explicit FTPS (port 21) and implicit FTPS (port 990)
- Preserves FTP command/response structure

### Elasticsearch
- Direct TLS wrapping for HTTP/REST traffic
- Compatible with Elasticsearch Java/Python/Go clients
- Preserves all Elasticsearch API functionality

### RabbitMQ/AMQP
- AMQP 0-9-1 protocol support
- Handles AMQP connection negotiation
- TLS upgrade for AMQP connections

### Kafka
- Kafka wire protocol support
- TLS encryption for producer/consumer connections
- Compatible with Kafka clients

### Cassandra
- CQL protocol support
- Handles Cassandra native protocol negotiation
- TLS encryption for CQL queries

### Memcached
- Supports both text and binary protocols
- Handles STARTTLS command (if supported by server)
- Transparent TLS encryption

## Benefits

1. **Unified Certificate Management**: Use ACME/Let's Encrypt certificates for all services
2. **Enhanced Security**: Add TLS to legacy services without modification
3. **Simplified Architecture**: Single point for TLS termination
4. **Compliance**: Meet security requirements for encrypted data in transit
5. **Zero Application Changes**: No need to modify client applications or backend services

## Testing

Test each service proxy with appropriate clients:

```bash
# Test LDAPS
ldapsearch -H ldaps://localhost:636 -x -b "dc=example,dc=com"

# Test SMTPS
openssl s_client -connect localhost:465 -crlf

# Test FTPS
lftp ftps://localhost:990

# Test Elasticsearch
curl -k https://localhost:9200/_cluster/health

# Test Kafka (with kafka-console-producer)
kafka-console-producer --broker-list localhost:9093 --topic test \
  --producer-property security.protocol=SSL

# Test Cassandra
cqlsh localhost 9042 --ssl

# Test Memcached
openssl s_client -connect localhost:11211
```

## Security Considerations

1. **Backend Verification**: Currently uses `InsecureSkipVerify` for backend connections. In production, configure proper certificate verification.
2. **Certificate Storage**: Certificates are cached in the specified directory with appropriate permissions (700).
3. **Protocol Detection**: Each proxy implements protocol-specific detection to ensure proper TLS negotiation.
4. **Connection Pooling**: Each connection is handled independently; consider implementing connection pooling for high-traffic scenarios.

## Future Enhancements

Potential services to add:
- **etcd** - Distributed key-value store
- **Consul** - Service mesh and configuration
- **ZooKeeper** - Distributed coordination
- **InfluxDB** - Time series database
- **Prometheus** - Metrics and monitoring
- **NATS** - Cloud native messaging
- **GraphQL** - API gateway
- **gRPC** - RPC framework