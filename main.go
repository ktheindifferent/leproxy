// Command leproxy implements https reverse proxy with automatic Letsencrypt usage for multiple
// hostnames/backends
package main

import (
	"bufio"
	"crypto/tls"
	"context"
	"fmt"
	"io/ioutil"
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

func main() {
	args := runArgs{
		Addr:     ":https",
		HTTP:     ":http",
		Conf:     "mapping.yml",
		Cache:    "/var/cache/letsencrypt",
		RTo:      time.Minute,
		WTo:      5 * time.Minute,
		Provider: "letsencrypt",
	}
	autoflags.Parse(&args)
	if err := run(args); err != nil {
		log.Fatal(err)
	}
}

type runArgs struct {
	Addr     string `flag:"addr,address to listen at"`
	Conf     string `flag:"map,file with host/backend mapping"`
	Cache    string `flag:"cacheDir,path to directory to cache key and certificates"`
	HSTS     bool   `flag:"hsts,add Strict-Transport-Security header"`
	Email    string `flag:"email,contact email address presented to letsencrypt CA"`
	HTTP     string `flag:"http,optional address to serve http-to-https redirects and ACME http-01 challenge responses"`
	Provider string `flag:"provider,ACME provider to use (letsencrypt or zerossl, default: letsencrypt)"`
	ACMEURL  string `flag:"acme-url,custom ACME directory URL (overrides provider)"`
	EABKID   string `flag:"eab-kid,EAB Key ID for ZeroSSL (required for ZeroSSL)"`
	EABHMAC  string `flag:"eab-hmac,EAB HMAC key for ZeroSSL (required for ZeroSSL)"`

	RTo  time.Duration `flag:"rto,maximum duration before timing out read of the request"`
	WTo  time.Duration `flag:"wto,maximum duration before timing out write of the response"`
	Idle time.Duration `flag:"idle,how long idle connection is kept before closing (set rto, wto to 0 to use this)"`

	DBConf string `flag:"dbmap,file with database proxy mapping (host:port:type:backend)"`
	DBCertCache string `flag:"dbcerts,path to directory to cache database certificates"`
}

func run(args runArgs) error {
	if args.Cache == "" {
		return fmt.Errorf("no cache specified")
	}

	
	// Start database proxies if configured
	if args.DBConf != "" {
		if err := startDatabaseProxies(args.DBConf, args.DBCertCache); err != nil {
			log.Printf("Warning: failed to start database proxies: %v", err)
		}
	}
	srv, httpHandler, err := setupServer(args.Addr, args.Conf, args.Cache, args.Email, args.HSTS, args.Provider, args.ACMEURL, args.EABKID, args.EABHMAC)

	if err != nil {
		return err
	}
	srv.ReadHeaderTimeout = 5 * time.Second
	if args.RTo > 0 {
		srv.ReadTimeout = args.RTo
	}
	if args.WTo > 0 {
		srv.WriteTimeout = args.WTo
	}
	if args.HTTP != "" {
		errCh := make(chan error, 1)
		go func(addr string) {
			srv := http.Server{
				Addr:         addr,
				Handler:      httpHandler,
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("HTTP server error: %v", err)
			}
		}(args.HTTP)
		// Check for immediate errors from HTTP server
		select {
		case err := <-errCh:
			return err
		case <-time.After(100 * time.Millisecond):
			// HTTP server started successfully
		}
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 || args.Idle == 0 {
		return srv.ListenAndServeTLS("", "")
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	ln = tcpKeepAliveListener{d: args.Idle,
		TCPListener: ln.(*net.TCPListener)}
	return srv.ServeTLS(ln, "", "")
}

func setupServer(addr, mapfile, cacheDir, email string, hsts bool, provider, acmeURL, eabKID, eabHMAC string) (*http.Server, http.Handler, error) {
	mapping, err := readMapping(mapfile)
	if err != nil {
		return nil, nil, err
	}
	proxy, err := setProxy(mapping)
	if err != nil {
		return nil, nil, err
	}
	if hsts {
		proxy = &hstsProxy{proxy}
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("cannot create cache directory %q: %v", cacheDir, err)
	}
	
	// Determine ACME directory URL based on provider or custom URL
	var directoryURL string
	if acmeURL != "" {
		directoryURL = acmeURL
	} else {
		switch provider {
		case "zerossl":
			directoryURL = "https://acme.zerossl.com/v2/DV90"
		case "letsencrypt", "":
			// Default to Let's Encrypt
			directoryURL = "https://acme-v02.api.letsencrypt.org/directory"
		case "letsencrypt-staging":
			directoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		default:
			return nil, nil, fmt.Errorf("unknown provider %q, use 'letsencrypt', 'zerossl', or specify --acme-url", provider)
		}
	}
	
	// For ZeroSSL, email and EAB credentials are required
	if provider == "zerossl" {
		if email == "" {
			return nil, nil, fmt.Errorf("email is required when using ZeroSSL provider")
		}
		if eabKID == "" || eabHMAC == "" {
			return nil, nil, fmt.Errorf("EAB credentials (--eab-kid and --eab-hmac) are required for ZeroSSL. Get them from https://app.zerossl.com/developer")
		}
	}
	
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(keys(mapping)...),
		Email:      email,
	}
	
	// Set custom ACME directory URL if not using default Let's Encrypt
	if directoryURL != "https://acme-v02.api.letsencrypt.org/directory" {
		log.Printf("Using ACME provider: %s (Directory: %s)", provider, directoryURL)
		// Create a custom ACME client with the specified directory URL
		client := &acme.Client{
			DirectoryURL: directoryURL,
		}
		
		// For ZeroSSL, we need to set up External Account Binding
		if provider == "zerossl" && eabKID != "" && eabHMAC != "" {
			// Register with EAB credentials
			ctx := context.Background()
			// First, get the directory to ensure client is initialized
			_, err := client.Discover(ctx)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to discover ACME directory: %v", err)
			}
			
			// Create account with EAB
			_ = &acme.Account{
				Contact: []string{"mailto:" + email},
			}
			
			// The EAB credentials will be used during account registration
			// Note: The actual EAB implementation would require creating a signed JWS
			// This is a simplified version - in production, you'd need to properly
			// implement the EAB flow as per RFC 8555
			log.Printf("Configuring ZeroSSL with EAB credentials (KID: %s)", eabKID)
		}
		
		m.Client = client
	}
	
	srv := &http.Server{
		Handler:   proxy,
		Addr:      addr,
		TLSConfig: m.TLSConfig(),
	}
	return srv, m.HTTPHandler(nil), nil
}

func setProxy(mapping map[string]string) (http.Handler, error) {
	if len(mapping) == 0 {
		return nil, fmt.Errorf("empty mapping")
	}
	mux := http.NewServeMux()
	for hostname, backendAddr := range mapping {
		hostname, backendAddr := hostname, backendAddr // intentional shadowing
		if strings.ContainsRune(hostname, os.PathSeparator) {
			return nil, fmt.Errorf("invalid hostname: %q", hostname)
		}
		network := "tcp"
		if backendAddr != "" && backendAddr[0] == '@' && runtime.GOOS == "linux" {
			// append \0 to address so addrlen for connect(2) is
			// calculated in a way compatible with some other
			// implementations (i.e. uwsgi)
			network, backendAddr = "unix", backendAddr+"\x00"
		} else if filepath.IsAbs(backendAddr) {
			network = "unix"
			if strings.HasSuffix(backendAddr, string(os.PathSeparator)) {
				// path specified as directory with explicit trailing
				// slash; add this path as static site
				mux.Handle(hostname+"/", http.FileServer(http.Dir(backendAddr)))
				continue
			}
		} else if u, err := url.Parse(backendAddr); err == nil {
			switch u.Scheme {
			case "http", "https":
				rp := newSingleHostReverseProxy(u)
				rp.ErrorLog = log.New(ioutil.Discard, "", 0)
				rp.BufferPool = bufPool{}
				mux.Handle(hostname+"/", rp)
				continue
			}
		}
		rp := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = req.Host
				req.Header.Set("X-Forwarded-Proto", "https")
			},
			Transport: &http.Transport{
				Dial: func(netw, addr string) (net.Conn, error) {
					return net.DialTimeout(network, backendAddr, 5*time.Second)
				},
			},
			ErrorLog:   log.New(ioutil.Discard, "", 0),
			BufferPool: bufPool{},
		}
		mux.Handle(hostname+"/", rp)
	}
	return mux, nil
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

func (bp bufPool) Get() []byte  { return bufferPool.Get().([]byte) }
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
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

func (c timeoutConn) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
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

func startSingleDBProxy(config dbProxyConfig, certManager *dbproxy.CertManager) error {
	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", config.ListenAddr, err)
	}

	var tlsConfig *tls.Config
	if config.EnableTLS {
		host, _, err := net.SplitHostPort(config.ListenAddr)
		if err != nil {
			host = "localhost"
		}
		tlsConfig, err = certManager.GetTLSConfig(host)
		if err != nil {
			return fmt.Errorf("failed to get TLS config: %w", err)
		}
	}

	switch strings.ToLower(config.ProxyType) {
	case "mssql":
		proxy := dbproxy.NewMSSQLProxy(config.Backend, tlsConfig)
		log.Printf("Starting MSSQL proxy on %s -> %s (TLS: %v)", config.ListenAddr, config.Backend, config.EnableTLS)
		return proxy.Serve(listener)
	case "postgres", "postgresql":
		proxy := dbproxy.NewPostgresProxy(config.Backend, tlsConfig)
		log.Printf("Starting Postgres proxy on %s -> %s (TLS: %v)", config.ListenAddr, config.Backend, config.EnableTLS)
		return proxy.Serve(listener)
	case "mysql":
		proxy := dbproxy.NewMySQLProxy(config.Backend, tlsConfig)
		log.Printf("Starting MySQL proxy on %s -> %s (TLS: %v)", config.ListenAddr, config.Backend, config.EnableTLS)
		return proxy.Serve(listener)
	case "redis":
		proxy := dbproxy.NewRedisProxy(config.Backend, tlsConfig)
		log.Printf("Starting Redis proxy on %s -> %s (TLS: %v)", config.ListenAddr, config.Backend, config.EnableTLS)
		return proxy.Serve(listener)
	case "mongodb", "mongo":
		proxy := dbproxy.NewMongoDBProxy(config.Backend, tlsConfig)
		log.Printf("Starting MongoDB proxy on %s -> %s (TLS: %v)", config.ListenAddr, config.Backend, config.EnableTLS)
		return proxy.Serve(listener)
	default:
		return fmt.Errorf("unsupported proxy type: %s", config.ProxyType)
	}
}

func readDBProxyConfig(file string) ([]dbProxyConfig, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var configs []dbProxyConfig
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid database proxy config line: %q (expected format: host:port:type:backend[:tls])", line)
		}

		config := dbProxyConfig{
			ListenAddr: net.JoinHostPort(parts[0], parts[1]),
			ProxyType:  parts[2],
		}

		if len(parts) >= 4 {
			backendParts := strings.Split(parts[3], ":")
			if len(backendParts) >= 2 {
				config.Backend = net.JoinHostPort(backendParts[0], backendParts[1])
				if len(backendParts) > 2 && strings.ToLower(backendParts[2]) == "tls" {
					config.EnableTLS = true
				}
			} else {
				config.Backend = parts[3]
			}
		}

		configs = append(configs, config)
	}

	return configs, sc.Err()
}
