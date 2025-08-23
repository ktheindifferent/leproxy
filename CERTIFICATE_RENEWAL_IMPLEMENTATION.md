# Certificate Renewal Implementation with Robust Retry Logic

## Overview

This implementation adds comprehensive certificate renewal capabilities with exponential backoff retry logic, monitoring, alerting, and a web dashboard for the LeProxy ACME certificate management system.

## Key Features Implemented

### 1. Exponential Backoff Retry Mechanism
- **File**: `internal/acme/renewal.go`
- Implements intelligent retry logic with exponential backoff and jitter
- Maximum of 5 retry attempts with increasing delays (1min, 2min, 4min, 8min, up to 1hr max)
- Prevents thundering herd problems with randomized jitter (±25%)

### 2. Pre-Expiry Renewal (30 Days)
- Proactive renewal 30 days before certificate expiry
- Configurable renewal window via `RenewalWindow` constant
- Automatic detection of expiring certificates

### 3. Renewal Status Tracking and Metrics
- **Files**: `internal/acme/renewal.go`, `internal/metrics/metrics.go`
- Real-time status tracking for each domain
- Prometheus-compatible metrics:
  - `cert_renewal_attempts_total` - Total renewal attempts
  - `cert_renewal_successes_total` - Successful renewals
  - `cert_renewal_failures_total` - Failed renewals
  - `cert_renewal_duration_seconds` - Renewal duration histogram
  - `cert_expiry_days` - Days until certificate expiry

### 4. Alert Mechanism
- **File**: `internal/acme/alerts.go`
- Multi-channel alerting support:
  - Email notifications via SMTP
  - Webhook integration for custom systems
  - Slack notifications with rich formatting
- Configurable alert thresholds and cooldown periods
- Severity levels: info, warning, critical

### 5. Certificate Expiry Dashboard
- **File**: `internal/acme/dashboard.go`
- Web-based monitoring dashboard at `/certificates/dashboard`
- REST API endpoints:
  - `/certificates` - List all certificates
  - `/certificates/status` - Detailed status for specific domain
  - `/certificates/history` - Renewal history
  - `/api/certificates/renew` - Manual renewal trigger
- Real-time updates with auto-refresh
- Visual severity indicators

### 6. Renewal History Storage
- Persistent storage of renewal history in JSON format
- 90-day retention period (configurable)
- Includes success/failure status, duration, and attempt count
- Useful for debugging and audit trails

### 7. Comprehensive Testing
- **Files**: `internal/acme/renewal_test.go`, `internal/acme/integration_test.go`
- Mock ACME server for unit testing
- Tests for:
  - Exponential backoff calculation
  - Retry logic with failures
  - Concurrent renewal handling
  - Alert triggering
  - Network failure recovery
  - Certificate rotation without downtime
  - Load testing during renewal

## Integration with Existing Code

### Manager Integration
The renewal functionality is integrated into the existing `Manager` struct in `internal/acme/manager.go`:

```go
// Start automatic renewal
manager.StartRenewalManager(ctx)

// Set alert handler
manager.SetRenewalAlertHandler(alertHandler)

// Get renewal status
status := manager.GetRenewalStatus()

// Get renewal history
history := manager.GetRenewalHistory()
```

### Main Application Integration
To use in the main application:

```go
// Create ACME manager
acmeConfig := &acme.Config{
    Provider: "letsencrypt",
    CacheDir: "/var/cache/certs",
    Domains:  []string{"example.com"},
    Email:    "admin@example.com",
}

manager, err := acme.NewManager(acmeConfig)
if err != nil {
    log.Fatal(err)
}

// Configure alerts
alertConfig := &acme.AlertConfig{
    EmailEnabled: true,
    SMTPHost:     "smtp.example.com",
    SMTPPort:     587,
    EmailTo:      []string{"ops@example.com"},
    
    SlackEnabled:    true,
    SlackWebhookURL: "https://hooks.slack.com/...",
}

alertHandler := acme.DefaultAlertHandler(alertConfig)
manager.SetRenewalAlertHandler(alertHandler)

// Start renewal manager
ctx := context.Background()
manager.StartRenewalManager(ctx)
defer manager.StopRenewalManager()

// Register dashboard handlers
dashboardHandler := acme.NewDashboardHandler(manager)
dashboardHandler.RegisterHandlers(http.DefaultServeMux)
```

## Configuration Examples

### Alert Configuration
```go
alertConfig := &acme.AlertConfig{
    // Email settings
    EmailEnabled: true,
    SMTPHost:     "smtp.gmail.com",
    SMTPPort:     587,
    SMTPUser:     "alerts@example.com",
    SMTPPass:     "password",
    EmailFrom:    "alerts@example.com",
    EmailTo:      []string{"ops@example.com", "admin@example.com"},
    
    // Webhook settings
    WebhookEnabled: true,
    WebhookURL:     "https://api.example.com/alerts",
    WebhookMethod:  "POST",
    WebhookHeaders: map[string]string{
        "Authorization": "Bearer token123",
    },
    
    // Slack settings
    SlackEnabled:    true,
    SlackWebhookURL: "https://hooks.slack.com/services/...",
    SlackChannel:    "#ops-alerts",
    SlackUsername:   "Certificate Bot",
    
    // Thresholds
    MaxFailuresBeforeAlert:   3,
    AlertCooldown:            1 * time.Hour,
    WarnDaysBeforeExpiry:     7,
    CriticalDaysBeforeExpiry: 3,
}
```

## Monitoring and Operations

### Health Checks
The renewal manager integrates with the health check system:
- Certificate expiry monitoring
- Renewal failure tracking
- System resource usage

### Metrics Endpoint
Prometheus metrics available at `/metrics`:
```
# HELP cert_renewal_attempts_total Total certificate renewal attempts
# TYPE cert_renewal_attempts_total counter
cert_renewal_attempts_total{domain="example.com"} 5

# HELP cert_expiry_days Days until certificate expiry
# TYPE cert_expiry_days gauge
cert_expiry_days{domain="example.com"} 89
```

### Dashboard Access
Access the web dashboard at `https://your-server/certificates/dashboard`

## Testing

### Unit Tests
```bash
go test ./internal/acme/...
```

### Integration Tests (requires ACME staging environment)
```bash
ACME_TEST_EMAIL=test@example.com go test -tags=integration ./internal/acme/...
```

### Load Testing
```bash
go test -run TestLoadDuringRenewal -tags=integration ./internal/acme/...
```

## Benefits

1. **Zero Downtime**: Certificate rotation happens without service interruption
2. **Automatic Recovery**: Exponential backoff ensures eventual success despite transient failures
3. **Proactive Monitoring**: 30-day pre-expiry renewal prevents emergency situations
4. **Multi-Channel Alerting**: Never miss a critical renewal failure
5. **Audit Trail**: Complete history for compliance and debugging
6. **Load Resilience**: Continues operating under high load during renewals

## Future Enhancements

1. **Distributed Locking**: For multi-instance deployments
2. **Certificate Transparency Logging**: Integration with CT logs
3. **HSM Support**: Hardware security module integration
4. **OCSP Stapling**: Improved certificate validation
5. **Custom Renewal Policies**: Per-domain renewal windows
6. **Backup Provider Failover**: Automatic failover to alternative ACME providers

## Conclusion

This implementation provides enterprise-grade certificate renewal capabilities with comprehensive error handling, monitoring, and alerting. The system is designed to prevent certificate expiry-related outages through proactive renewal, intelligent retry logic, and multi-channel alerting.