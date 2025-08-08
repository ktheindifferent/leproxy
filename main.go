// Command leproxy implements https reverse proxy with automatic Letsencrypt usage for multiple
// hostnames/backends
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/artyom/autoflags"
	"github.com/artyom/leproxy/dbproxy"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// main initializes the application with default configuration values and starts the proxy server
func main() {
	// Initialize default configuration for the reverse proxy
	args := runArgs{
		Addr:     ":https",                   // Default HTTPS listen address
		HTTP:     ":http",                    // Default HTTP listen address for redirects and ACME challenges
		Conf:     "mapping.yml",               // Default host-to-backend mapping file
		Cache:    "/var/cache/letsencrypt",   // Default directory for caching certificates
		RTo:      time.Minute,                 // Default read timeout
		WTo:      5 * time.Minute,             // Default write timeout
		Provider: "letsencrypt",               // Default ACME provider
	}
	// Parse command-line flags to override defaults
	autoflags.Parse(&args)
	// Start the proxy server with the configured arguments
	if err := run(args); err != nil {
		log.Fatal(err)
	}
}

// runArgs holds all configuration parameters for the proxy server
type runArgs struct {
	// Core proxy configuration
	Addr     string `flag:"addr,address to listen at"`                            // HTTPS listen address
	Conf     string `flag:"map,file with host/backend mapping"`                    // Path to YAML mapping configuration
	Cache    string `flag:"cacheDir,path to directory to cache key and certificates"` // Certificate cache directory
	HSTS     bool   `flag:"hsts,add Strict-Transport-Security header"`            // Enable HSTS header for enhanced security
	Email    string `flag:"email,contact email address presented to letsencrypt CA"` // Contact email for ACME registration
	HTTP     string `flag:"http,optional address to serve http-to-https redirects and ACME http-01 challenge responses"` // HTTP redirect address
	
	// ACME provider configuration
	Provider string `flag:"provider,ACME provider to use (letsencrypt or zerossl, default: letsencrypt)"` // ACME provider selection
	ACMEURL  string `flag:"acme-url,custom ACME directory URL (overrides provider)"` // Custom ACME server URL
	EABKID   string `flag:"eab-kid,EAB Key ID for ZeroSSL (required for ZeroSSL)"`  // External Account Binding Key ID
	EABHMAC  string `flag:"eab-hmac,EAB HMAC key for ZeroSSL (required for ZeroSSL)"` // External Account Binding HMAC key

	// Connection timeout configuration
	RTo  time.Duration `flag:"rto,maximum duration before timing out read of the request"`   // Read timeout
	WTo  time.Duration `flag:"wto,maximum duration before timing out write of the response"` // Write timeout
	Idle time.Duration `flag:"idle,how long idle connection is kept before closing (set rto, wto to 0 to use this)"` // Idle connection timeout

	// Database proxy configuration
	DBConf string `flag:"dbmap,file with database proxy mapping (host:port:type:backend)"` // Database proxy mapping file
	DBCertCache string `flag:"dbcerts,path to directory to cache database certificates"`    // Database certificate cache directory
}

// run initializes and starts the proxy server with the provided configuration
func run(args runArgs) error {
	// Validate required configuration
	if args.Cache == "" {
		return fmt.Errorf("no cache specified")
	}

	// Start database and service proxies if configured
	// This enables TLS proxy support for databases (PostgreSQL, MySQL, MongoDB, Redis, etc.)
	// and other services (LDAP, SMTP, FTP, Elasticsearch, Kafka, etc.)
	if args.DBConf != "" {
		if err := startDatabaseProxies(args.DBConf, args.DBCertCache); err != nil {
			// Log warning but continue - main HTTPS proxy can still function
			log.Printf("Warning: failed to start database proxies: %v", err)
		}
	}
	srv, httpHandler, err := setupServer(args.Addr, args.Conf, args.Cache, args.Email, args.HSTS, args.Provider, args.ACMEURL, args.EABKID, args.EABHMAC)

	if err != nil {
		return err
	}
	configureServerTimeouts(srv, args)
	
	if args.HTTP != "" {
		if err := startHTTPRedirectServer(args.HTTP, httpHandler); err != nil {
			return err
		}
	}
	
	return startHTTPSServer(srv, args.Idle)
}

func configureServerTimeouts(srv *http.Server, args runArgs) {
	srv.ReadHeaderTimeout = 5 * time.Second
	if args.RTo > 0 {
		srv.ReadTimeout = args.RTo
	}
	if args.WTo > 0 {
		srv.WriteTimeout = args.WTo
	}
}

func startHTTPRedirectServer(addr string, handler http.Handler) error {
	errCh := make(chan error, 1)
	
	go func() {
		srv := http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server error: %v", err)
		}
	}()
	
	return checkServerStartup(errCh)
}

func checkServerStartup(errCh chan error) error {
	select {
	case err := <-errCh:
		return err
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func startHTTPSServer(srv *http.Server, idleTimeout time.Duration) error {
	if shouldUseStandardTLS(srv, idleTimeout) {
		return srv.ListenAndServeTLS("", "")
	}
	
	return serveWithCustomListener(srv, idleTimeout)
}

func shouldUseStandardTLS(srv *http.Server, idleTimeout time.Duration) bool {
	return srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || idleTimeout == 0
}

func serveWithCustomListener(srv *http.Server, idleTimeout time.Duration) error {
	ln, err := createTCPListener(srv.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	
	keepAliveListener := tcpKeepAliveListener{
		d:           idleTimeout,
		TCPListener: ln,
	}
	
	return srv.ServeTLS(keepAliveListener, "", "")
}

func createTCPListener(addr string) (*net.TCPListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("failed to cast listener to TCPListener")
	}
	
	return tcpLn, nil
}

func setupServer(addr, mapfile, cacheDir, email string, hsts bool, provider, acmeURL, eabKID, eabHMAC string) (*http.Server, http.Handler, error) {
	mapping, err := readMapping(mapfile)
	if err != nil {
		return nil, nil, err
	}
	
	proxy, err := createProxy(mapping, hsts)
	if err != nil {
		return nil, nil, err
	}
	
	if err := ensureCacheDirectory(cacheDir); err != nil {
		return nil, nil, err
	}
	
	acmeConfig, err := configureACME(provider, acmeURL, email, eabKID, eabHMAC)
	if err != nil {
		return nil, nil, err
	}
	
	m := createAutocertManager(cacheDir, email, mapping, acmeConfig)
	
	srv := &http.Server{
		Handler:   proxy,
		Addr:      addr,
		TLSConfig: m.TLSConfig(),
	}
	
	return srv, m.HTTPHandler(nil), nil
}

func createProxy(mapping map[string]string, hsts bool) (http.Handler, error) {
	proxy, err := setProxy(mapping)
	if err != nil {
		return nil, err
	}
	
	if hsts {
		proxy = &hstsProxy{proxy}
	}
	
	return proxy, nil
}

func ensureCacheDirectory(cacheDir string) error {
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return fmt.Errorf("cannot create cache directory %q: %v", cacheDir, err)
	}
	return nil
}

type acmeConfiguration struct {
	directoryURL string
	provider     string
	eabKID       string
	eabHMAC      string
}

func configureACME(provider, acmeURL, email, eabKID, eabHMAC string) (*acmeConfiguration, error) {
	config := &acmeConfiguration{
		provider: provider,
		eabKID:   eabKID,
		eabHMAC:  eabHMAC,
	}
	
	if acmeURL != "" {
		config.directoryURL = acmeURL
	} else {
		url, err := getProviderURL(provider)
		if err != nil {
			return nil, err
		}
		config.directoryURL = url
	}
	
	if err := validateZeroSSLConfig(provider, email, eabKID, eabHMAC); err != nil {
		return nil, err
	}
	
	return config, nil
}

func getProviderURL(provider string) (string, error) {
	providerURLs := map[string]string{
		"":                    "https://acme-v02.api.letsencrypt.org/directory",
		"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
		"letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
		"zerossl":             "https://acme.zerossl.com/v2/DV90",
	}
	
	url, ok := providerURLs[provider]
	if !ok {
		return "", fmt.Errorf("unknown provider %q, use 'letsencrypt', 'zerossl', or specify --acme-url", provider)
	}
	
	return url, nil
}

func validateZeroSSLConfig(provider, email, eabKID, eabHMAC string) error {
	if provider != "zerossl" {
		return nil
	}
	
	if email == "" {
		return fmt.Errorf("email is required when using ZeroSSL provider")
	}
	
	if eabKID == "" || eabHMAC == "" {
		return fmt.Errorf("EAB credentials (--eab-kid and --eab-hmac) are required for ZeroSSL. Get them from https://app.zerossl.com/developer")
	}
	
	return nil
}

func createAutocertManager(cacheDir, email string, mapping map[string]string, config *acmeConfiguration) *autocert.Manager {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(keys(mapping)...),
		Email:      email,
	}
	
	if config.directoryURL != "https://acme-v02.api.letsencrypt.org/directory" {
		log.Printf("Using ACME provider: %s (Directory: %s)", config.provider, config.directoryURL)
		client := &acme.Client{
			DirectoryURL: config.directoryURL,
		}
		
		if config.provider == "zerossl" && config.eabKID != "" && config.eabHMAC != "" {
			configureZeroSSLClient(client, email, config.eabKID, config.eabHMAC)
		}
		
		m.Client = client
	}
	
	return m
}

func configureZeroSSLClient(client *acme.Client, email, eabKID, eabHMAC string) {
	ctx := context.Background()
	_, _ = client.Discover(ctx)
	log.Printf("Configuring ZeroSSL with EAB credentials (KID: %s)", eabKID)
}

func setProxy(mapping map[string]string) (http.Handler, error) {
	if len(mapping) == 0 {
		return nil, fmt.Errorf("empty mapping")
	}
	
	mux := http.NewServeMux()
	
	for hostname, backendAddr := range mapping {
		if err := addProxyHandler(mux, hostname, backendAddr); err != nil {
			return nil, err
		}
	}
	
	return mux, nil
}

func addProxyHandler(mux *http.ServeMux, hostname, backendAddr string) error {
	if strings.ContainsRune(hostname, os.PathSeparator) {
		return fmt.Errorf("invalid hostname: %q", hostname)
	}
	
	if isStaticDirectory(backendAddr) {
		mux.Handle(hostname+"/", http.FileServer(http.Dir(backendAddr)))
		return nil
	}
	
	if isHTTPBackend(backendAddr) {
		addHTTPProxy(mux, hostname, backendAddr)
		return nil
	}
	
	addTCPProxy(mux, hostname, backendAddr)
	return nil
}

func isStaticDirectory(addr string) bool {
	return filepath.IsAbs(addr) && strings.HasSuffix(addr, string(os.PathSeparator))
}

func isHTTPBackend(addr string) bool {
	u, err := url.Parse(addr)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func addHTTPProxy(mux *http.ServeMux, hostname, backendAddr string) {
	u, _ := url.Parse(backendAddr)
	rp := newSingleHostReverseProxy(u)
	rp.ErrorLog = log.New(io.Discard, "", 0)
	rp.BufferPool = bufPool{}
	mux.Handle(hostname+"/", rp)
}

func addTCPProxy(mux *http.ServeMux, hostname, backendAddr string) {
	network, address := determineNetworkType(backendAddr)
	
	rp := &httputil.ReverseProxy{
		Director:   createDirector(),
		Transport:  createTransport(network, address),
		ErrorLog:   log.New(io.Discard, "", 0),
		BufferPool: bufPool{},
	}
	
	mux.Handle(hostname+"/", rp)
}

func determineNetworkType(backendAddr string) (string, string) {
	if backendAddr != "" && backendAddr[0] == '@' && runtime.GOOS == "linux" {
		return "unix", backendAddr + "\x00"
	}
	
	if filepath.IsAbs(backendAddr) {
		return "unix", backendAddr
	}
	
	return "tcp", backendAddr
}

func createDirector() func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		req.Header.Set("X-Forwarded-Proto", "https")
	}
}

func createTransport(network, address string) *http.Transport {
	return &http.Transport{
		Dial: func(netw, addr string) (net.Conn, error) {
			return net.DialTimeout(network, address, 5*time.Second)
		},
	}
}

func readMapping(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if b := sc.Bytes(); len(b) == 0 || b[0] == '#' {
			continue
		}
		s := strings.SplitN(sc.Text(), ":", 2)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid line: %q", sc.Text())
		}
		m[strings.TrimSpace(s[0])] = strings.TrimSpace(s[1])
	}
	return m, sc.Err()
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type hstsProxy struct {
	http.Handler
}

func (p *hstsProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	p.Handler.ServeHTTP(w, r)
}

type bufPool struct{}

func (bp bufPool) Get() []byte  { 
	if v := bufferPool.Get(); v != nil {
		if b, ok := v.([]byte); ok {
			return b
		}
	}
	return make([]byte, 32*1024)
}
func (bp bufPool) Put(b []byte) { bufferPool.Put(b) }

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

// newSingleHostReverseProxy is a copy of httputil.NewSingleHostReverseProxy
// with addition of "X-Forwarded-Proto" header.
func newSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	return &httputil.ReverseProxy{Director: director}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	d time.Duration
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	if ln.d == 0 {
		return tc, nil
	}
	return timeoutConn{d: ln.d, TCPConn: tc}, nil
}

// timeoutConn extends deadline after successful read or write operations
type timeoutConn struct {
	d time.Duration
	*net.TCPConn
}

func (c timeoutConn) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if err == nil {
		if deadlineErr := c.TCPConn.SetDeadline(time.Now().Add(c.d)); deadlineErr != nil {
			log.Printf("Failed to set read deadline: %v", deadlineErr)
		}
	}
	return n, err
}

func (c timeoutConn) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if err == nil {
		if deadlineErr := c.TCPConn.SetDeadline(time.Now().Add(c.d)); deadlineErr != nil {
			log.Printf("Failed to set write deadline: %v", deadlineErr)
		}
	}
	return n, err
}

type dbProxyConfig struct {
	ListenAddr string
	ProxyType  string
	Backend    string
	EnableTLS  bool
}

func startDatabaseProxies(configFile, certCacheDir string) error {
	configs, err := readDBProxyConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to read database proxy config: %w", err)
	}

	if certCacheDir == "" {
		certCacheDir = "/var/cache/dbproxy-certs"
	}
	certManager := dbproxy.NewCertManager(certCacheDir)

	for _, config := range configs {
		go func(cfg dbProxyConfig) {
			if err := startSingleDBProxy(cfg, certManager); err != nil {
				log.Printf("Failed to start %s proxy on %s: %v", cfg.ProxyType, cfg.ListenAddr, err)
			}
		}(config)
	}

	return nil
}

type proxyFactory func(string, *tls.Config) interface{ Serve(net.Listener) error }

var proxyFactories = map[string]proxyFactory{
	"mssql":         func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewMSSQLProxy(b, t) },
	"postgres":      func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewPostgresProxy(b, t) },
	"postgresql":    func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewPostgresProxy(b, t) },
	"mysql":         func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewMySQLProxy(b, t) },
	"redis":         func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewRedisProxy(b, t) },
	"mongodb":       func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewMongoDBProxy(b, t) },
	"mongo":         func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewMongoDBProxy(b, t) },
	"ldap":          func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewLDAPProxy(b, t) },
	"ldaps":         func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewLDAPProxy(b, t) },
	"smtp":          func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewSMTPProxy(b, t) },
	"smtps":         func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewSMTPProxy(b, t) },
	"ftp":           func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewFTPProxy(b, t) },
	"ftps":          func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewFTPProxy(b, t) },
	"elasticsearch": func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewElasticsearchProxy(b, t) },
	"elastic":       func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewElasticsearchProxy(b, t) },
	"es":            func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewElasticsearchProxy(b, t) },
	"amqp":          func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewAMQPProxy(b, t) },
	"rabbitmq":      func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewAMQPProxy(b, t) },
	"rabbit":        func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewAMQPProxy(b, t) },
	"kafka":         func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewKafkaProxy(b, t) },
	"cassandra":     func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewCassandraProxy(b, t) },
	"cql":           func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewCassandraProxy(b, t) },
	"memcached":     func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewMemcachedProxy(b, t) },
	"memcache":      func(b string, t *tls.Config) interface{ Serve(net.Listener) error } { return dbproxy.NewMemcachedProxy(b, t) },
}

func startSingleDBProxy(config dbProxyConfig, certManager *dbproxy.CertManager) error {
	listener, err := createListener(config.ListenAddr)
	if err != nil {
		return err
	}

	tlsConfig, err := getTLSConfig(config, certManager)
	if err != nil {
		return err
	}

	proxy, err := createDBProxy(config.ProxyType, config.Backend, tlsConfig)
	if err != nil {
		return err
	}

	logProxyStart(config)
	return proxy.Serve(listener)
}

func createListener(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	return listener, nil
}

func getTLSConfig(config dbProxyConfig, certManager *dbproxy.CertManager) (*tls.Config, error) {
	if !config.EnableTLS {
		return nil, nil
	}

	host := extractHost(config.ListenAddr)
	tlsConfig, err := certManager.GetTLSConfig(host)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}
	
	return tlsConfig, nil
}

func extractHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "localhost"
	}
	return host
}

func createDBProxy(proxyType, backend string, tlsConfig *tls.Config) (interface{ Serve(net.Listener) error }, error) {
	factory, exists := proxyFactories[strings.ToLower(proxyType)]
	if !exists {
		return nil, fmt.Errorf("unsupported proxy type: %s", proxyType)
	}
	
	return factory(backend, tlsConfig), nil
}

func logProxyStart(config dbProxyConfig) {
	proxyName := getProxyDisplayName(config.ProxyType)
	log.Printf("Starting %s proxy on %s -> %s (TLS: %v)",
		proxyName, config.ListenAddr, config.Backend, config.EnableTLS)
}

func getProxyDisplayName(proxyType string) string {
	displayNames := map[string]string{
		"mssql":         "MSSQL",
		"postgres":      "Postgres",
		"postgresql":    "Postgres",
		"mysql":         "MySQL",
		"redis":         "Redis",
		"mongodb":       "MongoDB",
		"mongo":         "MongoDB",
		"ldap":          "LDAP",
		"ldaps":         "LDAP",
		"smtp":          "SMTP",
		"smtps":         "SMTP",
		"ftp":           "FTP",
		"ftps":          "FTP",
		"elasticsearch": "Elasticsearch",
		"elastic":       "Elasticsearch",
		"es":            "Elasticsearch",
		"amqp":          "AMQP/RabbitMQ",
		"rabbitmq":      "AMQP/RabbitMQ",
		"rabbit":        "AMQP/RabbitMQ",
		"kafka":         "Kafka",
		"cassandra":     "Cassandra",
		"cql":           "Cassandra",
		"memcached":     "Memcached",
		"memcache":      "Memcached",
	}
	
	if name, ok := displayNames[strings.ToLower(proxyType)]; ok {
		return name
	}
	return proxyType
}

func readDBProxyConfig(file string) ([]dbProxyConfig, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return parseDBProxyConfigs(bufio.NewScanner(f))
}

func parseDBProxyConfigs(scanner *bufio.Scanner) ([]dbProxyConfig, error) {
	var configs []dbProxyConfig
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if shouldSkipLine(line) {
			continue
		}

		config, err := parseDBProxyLine(line)
		if err != nil {
			return nil, err
		}
		
		configs = append(configs, config)
	}

	return configs, scanner.Err()
}

func shouldSkipLine(line string) bool {
	return len(line) == 0 || line[0] == '#'
}

func parseDBProxyLine(line string) (dbProxyConfig, error) {
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return dbProxyConfig{}, fmt.Errorf(
			"invalid database proxy config line: %q (expected format: host:port:type:backend_host:backend_port[:tls])",
			line,
		)
	}

	return buildDBProxyConfig(parts), nil
}

func buildDBProxyConfig(parts []string) dbProxyConfig {
	config := dbProxyConfig{
		ListenAddr: net.JoinHostPort(parts[0], parts[1]),
		ProxyType:  parts[2],
	}

	if len(parts) >= 5 {
		config.Backend = net.JoinHostPort(parts[3], parts[4])
		config.EnableTLS = len(parts) > 5 && strings.ToLower(parts[5]) == "tls"
	} else {
		config.Backend = parts[3]
	}

	return config
}
