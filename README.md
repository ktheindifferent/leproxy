Command leproxy implements https reverse proxy with automatic ACME certificate
management (Let's Encrypt/ZeroSSL) for multiple hostnames/backends

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

Note that when `@name` backend is specified, connection to abstract unix socket
is made in a manner compatible with some other implementations like uWSGI, that
calculate addrlen including trailing zero byte despite [documentation not
requiring that](http://man7.org/linux/man-pages/man7/unix.7.html). It won't
work with other implementations that calculate addrlen differently (i.e. by
taking into account only `strlen(addr)` like Go, or even `UNIX_PATH_MAX`).

## Command-line Options

* `-addr` - HTTPS listen address (default: `:https`)
* `-http` - HTTP listen address for redirects and ACME challenges (default: `:http`)
* `-map` - Path to mapping configuration file (default: `mapping.yml`)
* `-cacheDir` - Directory to cache certificates (default: `/var/cache/letsencrypt`)
* `-email` - Contact email for ACME provider (required for ZeroSSL)
* `-hsts` - Add Strict-Transport-Security header
* `-provider` - ACME provider: `letsencrypt` (default), `zerossl`, or `letsencrypt-staging`
* `-acme-url` - Custom ACME directory URL (overrides provider)
* `-eab-kid` - EAB Key ID for ZeroSSL (required for ZeroSSL)
* `-eab-hmac` - EAB HMAC key for ZeroSSL (required for ZeroSSL)
* `-rto` - Read timeout duration
* `-wto` - Write timeout duration
* `-idle` - Idle connection timeout

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
