# ACME Provider Configuration Guide

LeProxy supports multiple ACME certificate authorities for automatic SSL/TLS certificate management. This guide helps you choose and configure the right provider for your needs.

## Quick Start

```bash
# List all available providers
./acme-config -list

# Show details about a specific provider
./acme-config -show buypass

# Generate a configuration file
./acme-config -generate config.yaml -provider letsencrypt -email admin@example.com
```

## Supported Providers

| Provider | Validity | Wildcard | EAB Required | Staging | Best For |
|----------|----------|----------|--------------|---------|----------|
| **Let's Encrypt** | 90 days | ✅ | ❌ | ✅ | Most users, widely trusted |
| **ZeroSSL** | 90 days | ✅ | ✅ | ❌ | Alternative to Let's Encrypt |
| **Buypass** | 180 days | ❌ | ❌ | ✅ | Longer validity, European users |
| **SSL.com** | 90 days | ❌ | ✅ | ❌ | Single domain + www only |
| **Entrust** | 90 days | ✅ | ❌ | ❌ | Enterprise environments |
| **Google** | 90 days | ✅ | ✅ | ✅ | Google Cloud users |

## Provider Details

### Let's Encrypt (Default)
The most popular free ACME CA. Great for most use cases.

**Command Line:**
```bash
leproxy \
  --provider letsencrypt \
  --email admin@example.com \
  --test-mode  # Optional: use staging for testing
```

**Configuration:**
```yaml
server:
  acme:
    provider: letsencrypt
    email: admin@example.com
    test_mode: false  # Set to true for staging
```

### ZeroSSL
Free alternative to Let's Encrypt with EAB requirement.

**Setup:**
1. Register at https://app.zerossl.com/
2. Get EAB credentials from https://app.zerossl.com/developer

**Command Line:**
```bash
leproxy \
  --provider zerossl \
  --email admin@example.com \
  --eab-kid YOUR_KID \
  --eab-hmac YOUR_HMAC
```

**Configuration:**
```yaml
server:
  acme:
    provider: zerossl
    email: admin@example.com
    eab_kid: YOUR_KID
    eab_hmac: YOUR_HMAC
```

### Buypass Go SSL
European CA offering 180-day certificates (2x standard).

**Limitations:**
- No wildcard support
- Must list each subdomain explicitly

**Command Line:**
```bash
leproxy \
  --provider buypass \
  --email admin@example.com \
  --test-mode  # Optional: use test environment
```

**Configuration:**
```yaml
server:
  acme:
    provider: buypass
    email: admin@example.com
    test_mode: false
    domains:
      - example.com
      - www.example.com
      - api.example.com  # Must list each explicitly
```

### SSL.com
Commercial CA with limited free tier.

**Limitations:**
- Only single domain + www
- Requires EAB credentials

**Setup:**
1. Register at https://www.ssl.com/
2. Get EAB credentials from your account

**Command Line:**
```bash
leproxy \
  --provider sslcom \
  --email admin@example.com \
  --eab-kid YOUR_KID \
  --eab-hmac YOUR_HMAC
```

### Entrust
Enterprise-grade CA with ACME support.

**Command Line:**
```bash
leproxy \
  --provider entrust \
  --email admin@example.com
```

### Google Trust Services
Google's public CA with excellent infrastructure.

**Setup:**
1. Follow https://cloud.google.com/certificate-manager/docs/public-ca-tutorial
2. Get EAB credentials from Google Cloud Console

**Command Line:**
```bash
leproxy \
  --provider google \
  --email admin@example.com \
  --eab-kid YOUR_KID \
  --eab-hmac YOUR_HMAC \
  --test-mode  # Optional: use test environment
```

## Provider Selection Guide

### Choose Let's Encrypt if you:
- Want the most tested and widely supported option
- Need wildcard certificates
- Don't want to manage additional credentials
- Are just getting started

### Choose ZeroSSL if you:
- Want redundancy with multiple CAs
- Need an alternative to Let's Encrypt
- Don't mind managing EAB credentials

### Choose Buypass if you:
- Want 180-day certificates (less frequent renewals)
- Are in Europe and prefer a European CA
- Don't need wildcard certificates
- Have a finite list of subdomains

### Choose Google if you:
- Already use Google Cloud Platform
- Want Google's infrastructure reliability
- Need enterprise features
- Don't mind managing EAB credentials

## Testing with Staging Environments

Several providers offer staging/test environments for development:

```bash
# Let's Encrypt staging
leproxy --provider letsencrypt --test-mode

# Buypass test environment
leproxy --provider buypass --test-mode

# Google test environment
leproxy --provider google --test-mode
```

**Important:** Staging certificates are not trusted by browsers. Use them only for testing.

## Migration Between Providers

To switch providers:

1. **Update configuration:**
   ```yaml
   server:
     acme:
       provider: new_provider  # Change this
       # Add/remove EAB credentials as needed
   ```

2. **Clear certificate cache** (optional):
   ```bash
   rm -rf /var/cache/letsencrypt/*
   ```

3. **Restart LeProxy:**
   ```bash
   systemctl restart leproxy
   ```

The new provider will be used for the next certificate issuance.

## Rate Limits

Each provider has different rate limits:

| Provider | Certificates/Domain/Week | Domains/Certificate |
|----------|-------------------------|-------------------|
| Let's Encrypt | 50 | 100 |
| ZeroSSL | Unlimited (ACME) | 100 |
| Buypass | 20 | 5 |
| SSL.com | Varies | 2 (domain + www) |
| Google | Varies | 100 |

## Troubleshooting

### EAB Credentials Issues
```
Error: EAB credentials required for provider
```
**Solution:** Get credentials from the provider's website and add them to your configuration.

### Wildcard Not Supported
```
Error: Buypass does not support wildcard certificates
```
**Solution:** List each subdomain explicitly or switch to a provider that supports wildcards.

### Rate Limit Exceeded
```
Error: too many certificates already issued
```
**Solution:** Wait for the rate limit window to reset or use staging environment for testing.

### Certificate Not Trusted
```
Error: certificate signed by unknown authority
```
**Solution:** Ensure you're not using test/staging mode in production.

## Advanced Configuration

### Custom ACME Directory URL
Use any ACME-compliant server:

```yaml
server:
  acme:
    directory_url: https://your-acme-server.com/directory
    email: admin@example.com
    # Add EAB if required
    eab_kid: YOUR_KID
    eab_hmac: YOUR_HMAC
```

### Multiple Domains Configuration
```yaml
server:
  acme:
    provider: letsencrypt
    email: admin@example.com
    domains:
      - example.com
      - "*.example.com"
      - another-domain.com
      - "*.another-domain.com"
```

### Environment Variables
```bash
export LEPROXY_PROVIDER=buypass
export LEPROXY_EMAIL=admin@example.com
export LEPROXY_TEST_MODE=true
```

## Security Best Practices

1. **Keep EAB credentials secure** - Never commit them to version control
2. **Use environment variables** for sensitive data
3. **Test with staging first** before production deployment
4. **Monitor certificate expiry** - Set up alerts for renewal failures
5. **Have a backup provider** configured in case of outages

## Support and Resources

- **Let's Encrypt Community:** https://community.letsencrypt.org/
- **ZeroSSL Support:** https://zerossl.com/support/
- **Buypass Documentation:** https://www.buypass.com/support
- **Google Public CA:** https://cloud.google.com/certificate-manager/docs

## Contributing

To add support for a new ACME provider:

1. Add provider constants to `internal/acme/manager.go`
2. Update provider URLs in `main.go`
3. Add provider info to `GetProviderInfo()`
4. Update validation logic if needed
5. Test with the provider's staging environment
6. Submit a pull request

For questions or issues, please open an issue on GitHub.