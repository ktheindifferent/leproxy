// Command leproxy implements https reverse proxy with automatic Letsencrypt usage for multiple
// hostnames/backends - REFACTORED VERSION
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/artyom/autoflags"
	"github.com/artyom/leproxy/internal/acme"
	"github.com/artyom/leproxy/internal/config"
	"github.com/artyom/leproxy/internal/constants"
	"github.com/artyom/leproxy/internal/errors"
	"github.com/artyom/leproxy/internal/graceful"
	"github.com/artyom/leproxy/internal/health"
	"github.com/artyom/leproxy/internal/logger"
	"github.com/artyom/leproxy/internal/metrics"
	"github.com/artyom/leproxy/internal/middleware"
	"github.com/artyom/leproxy/internal/proxy"
	"github.com/artyom/leproxy/internal/ratelimit"
	"github.com/artyom/leproxy/internal/security"
	"github.com/artyom/leproxy/internal/server"
	"github.com/artyom/leproxy/internal/tracing"
	"github.com/artyom/leproxy/internal/websocket"
)

// Application represents the main application structure
type Application struct {
	config         *AppConfig
	server         *http.Server
	acmeManager    *acme.Manager
	proxyManager   *proxy.ProxyManager
	middleware     *middleware.Stack
	shutdownMgr    *graceful.ShutdownManager
	healthServer   *health.Server
	metricsServer  *metrics.Server
	securityScanner *security.Scanner
}

// AppConfig holds all application configuration
type AppConfig struct {
	// Server configuration
	ServerConfig server.Config
	
	// ACME configuration
	ACMEConfig acme.Config
	
	// Database proxy configuration
	DBProxyEnabled bool
	DBProxyConfig  string
	
	// Observability
	ObservabilityConfig ObservabilityConfig
	
	// Security
	SecurityConfig SecurityConfig
	
	// Features
	FeaturesConfig FeaturesConfig
}

// ObservabilityConfig holds observability settings
type ObservabilityConfig struct {
	LogLevel         string
	LogFormat        string
	MetricsAddr      string
	HealthAddr       string
	TracingEndpoint  string
	TracingExporter  string
}

// SecurityConfig holds security settings
type SecurityConfig struct {
	RateLimit    int
	BurstLimit   int
	DDoSProtect  bool
	SecurityScan bool
}

// FeaturesConfig holds feature flags
type FeaturesConfig struct {
	EnableWebSocket bool
	PluginDir       string
	AdminAddr       string
}

// NewApplication creates a new application instance
func NewApplication(config *AppConfig) (*Application, error) {
	app := &Application{
		config: config,
	}
	
	// Initialize components
	if err := app.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}
	
	return app, nil
}

// initializeComponents initializes all application components
func (app *Application) initializeComponents() error {
	// Initialize logging
	if err := app.initializeLogging(); err != nil {
		return err
	}
	
	// Initialize ACME manager
	if err := app.initializeACME(); err != nil {
		return err
	}
	
	// Initialize middleware stack
	if err := app.initializeMiddleware(); err != nil {
		return err
	}
	
	// Initialize proxy manager
	if err := app.initializeProxyManager(); err != nil {
		return err
	}
	
	// Initialize observability
	if err := app.initializeObservability(); err != nil {
		return err
	}
	
	// Initialize security
	if err := app.initializeSecurity(); err != nil {
		return err
	}
	
	// Build server
	if err := app.buildServer(); err != nil {
		return err
	}
	
	return nil
}

// initializeLogging sets up the logging system
func (app *Application) initializeLogging() error {
	jsonFormat := app.config.ObservabilityConfig.LogFormat == constants.LogFormatJSON
	return logger.Init(app.config.ObservabilityConfig.LogLevel, jsonFormat)
}

// initializeACME sets up the ACME certificate manager
func (app *Application) initializeACME() error {
	manager, err := acme.NewManager(&app.config.ACMEConfig)
	if err != nil {
		return fmt.Errorf("failed to create ACME manager: %w", err)
	}
	app.acmeManager = manager
	return nil
}

// initializeMiddleware sets up the middleware stack
func (app *Application) initializeMiddleware() error {
	stack := middleware.NewStack()
	
	// Add security middleware
	if app.config.SecurityConfig.RateLimit > 0 {
		limiter := ratelimit.NewLimiter(
			app.config.SecurityConfig.RateLimit,
			app.config.SecurityConfig.BurstLimit,
		)
		stack.Use(middleware.RateLimitMiddleware(limiter))
	}
	
	// Add HSTS if configured
	if app.config.ServerConfig.HSTS {
		stack.Use(middleware.HSTSMiddleware())
	}
	
	// Add WebSocket support if enabled
	if app.config.FeaturesConfig.EnableWebSocket {
		wsHandler := websocket.NewHandler()
		stack.Use(middleware.WebSocketMiddleware(wsHandler))
	}
	
	// Add logging middleware
	stack.Use(middleware.LoggingMiddleware())
	
	// Add metrics middleware
	stack.Use(middleware.MetricsMiddleware())
	
	app.middleware = stack
	return nil
}

// initializeProxyManager sets up the database proxy manager
func (app *Application) initializeProxyManager() error {
	if !app.config.DBProxyEnabled {
		return nil
	}
	
	factory := proxy.NewFactory()
	app.proxyManager = proxy.NewManager(factory)
	
	// Load proxy configurations
	if app.config.DBProxyConfig != "" {
		if err := app.loadProxyConfigurations(app.config.DBProxyConfig); err != nil {
			return fmt.Errorf("failed to load proxy configurations: %w", err)
		}
	}
	
	return nil
}

// loadProxyConfigurations loads database proxy configurations from file
func (app *Application) loadProxyConfigurations(configFile string) error {
	// Load and parse configuration file
	configs, err := config.LoadProxyConfigs(configFile)
	if err != nil {
		return err
	}
	
	// Start each configured proxy
	for _, cfg := range configs {
		if err := app.proxyManager.StartProxy(cfg); err != nil {
			logger.Warn("Failed to start proxy", "type", cfg.Type, "error", err)
		}
	}
	
	return nil
}

// initializeObservability sets up monitoring and tracing
func (app *Application) initializeObservability() error {
	cfg := app.config.ObservabilityConfig
	
	// Initialize tracing
	if cfg.TracingEndpoint != "" {
		tracer, err := tracing.InitTracer("leproxy", cfg.TracingEndpoint, cfg.TracingExporter)
		if err != nil {
			logger.Warn("Failed to initialize tracing", "error", err)
		} else {
			logger.Info("Tracing initialized", "endpoint", cfg.TracingEndpoint)
			// Tracer will be managed by the tracing package
			_ = tracer
		}
	}
	
	// Initialize metrics server
	if cfg.MetricsAddr != "" {
		app.metricsServer = metrics.NewServer(cfg.MetricsAddr)
		go func() {
			if err := app.metricsServer.Start(); err != nil {
				logger.Error("Failed to start metrics server", "error", err)
			}
		}()
		logger.Info("Metrics server started", "address", cfg.MetricsAddr)
	}
	
	// Initialize health server
	if cfg.HealthAddr != "" {
		app.healthServer = health.NewServer(cfg.HealthAddr)
		go func() {
			if err := app.healthServer.Start(); err != nil {
				logger.Error("Failed to start health server", "error", err)
			}
		}()
		logger.Info("Health server started", "address", cfg.HealthAddr)
	}
	
	return nil
}

// initializeSecurity sets up security components
func (app *Application) initializeSecurity() error {
	if app.config.SecurityConfig.SecurityScan {
		app.securityScanner = security.NewScanner()
		go app.securityScanner.StartBackgroundScanning()
		logger.Info("Security scanner enabled")
	}
	
	if app.config.SecurityConfig.DDoSProtect {
		// DDoS protection is handled by rate limiting middleware
		logger.Info("DDoS protection enabled")
	}
	
	return nil
}

// buildServer builds the HTTP server
func (app *Application) buildServer() error {
	// Create the main handler
	handler := app.createMainHandler()
	
	// Apply middleware
	handler = app.middleware.Apply(handler)
	
	// Build server configuration
	serverConfig := &server.Config{
		Addr:         app.config.ServerConfig.Addr,
		ReadTimeout:  app.config.ServerConfig.ReadTimeout,
		WriteTimeout: app.config.ServerConfig.WriteTimeout,
		IdleTimeout:  app.config.ServerConfig.IdleTimeout,
	}
	
	// Build server
	builder := server.NewBuilder(serverConfig)
	builder.WithHandler(handler)
	
	if app.acmeManager != nil {
		builder.WithTLSConfig(app.acmeManager.GetTLSConfig())
	}
	
	srv, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to build server: %w", err)
	}
	
	app.server = srv
	return nil
}

// createMainHandler creates the main HTTP handler
func (app *Application) createMainHandler() http.Handler {
	mux := http.NewServeMux()
	
	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Add metrics endpoint if configured
	if app.metricsServer != nil {
		mux.Handle("/metrics", app.metricsServer.Handler())
	}
	
	// Add main proxy handler
	mux.HandleFunc("/", app.handleProxy)
	
	return mux
}

// handleProxy handles proxy requests
func (app *Application) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Proxy logic here - simplified for example
	// This would integrate with the existing proxy logic
	
	logger.Debug("Handling proxy request", 
		"host", r.Host,
		"path", r.URL.Path,
		"method", r.Method,
	)
	
	// Implement actual proxy logic here
	w.WriteHeader(http.StatusOK)
}

// Start starts the application
func (app *Application) Start() error {
	// Set up graceful shutdown
	app.shutdownMgr = graceful.NewShutdownManager(app.server)
	go app.shutdownMgr.HandleSignals()
	
	// Start HTTP redirect server if configured
	if app.config.ServerConfig.HTTP != "" {
		httpHandler := app.acmeManager.Manager.HTTPHandler(nil)
		if err := server.StartHTTPRedirect(app.config.ServerConfig.HTTP, httpHandler); err != nil {
			return err
		}
	}
	
	// Start HTTPS server
	return server.StartHTTPS(app.server, app.config.ServerConfig.IdleTimeout)
}

// Stop stops the application gracefully
func (app *Application) Stop(ctx context.Context) error {
	logger.Info("Shutting down application")
	
	// Stop proxy manager
	if app.proxyManager != nil {
		app.proxyManager.StopAll()
	}
	
	// Stop security scanner
	if app.securityScanner != nil {
		app.securityScanner.Stop()
	}
	
	// Stop health server
	if app.healthServer != nil {
		app.healthServer.Stop(ctx)
	}
	
	// Stop metrics server
	if app.metricsServer != nil {
		app.metricsServer.Stop(ctx)
	}
	
	// Shutdown main server
	if app.server != nil {
		return app.server.Shutdown(ctx)
	}
	
	return nil
}

// main is the refactored entry point
func mainRefactored() {
	// Parse command-line arguments
	args := parseArguments()
	
	// Build application configuration
	appConfig := buildAppConfig(args)
	
	// Create application
	app, err := NewApplication(appConfig)
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}
	
	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// Start application in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- app.Start()
	}()
	
	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info("Received signal", "signal", sig)
		ctx, cancel := context.WithTimeout(context.Background(), constants.DefaultShutdownTimeout)
		defer cancel()
		if err := app.Stop(ctx); err != nil {
			logger.Error("Failed to shutdown gracefully", "error", err)
		}
	case err := <-errChan:
		if err != nil {
			logger.Fatal("Application error", "error", err)
		}
	}
}

// parseArguments parses command-line arguments
func parseArguments() runArgs {
	args := runArgs{
		Addr:        constants.DefaultHTTPSPort,
		HTTP:        constants.DefaultHTTPPort,
		Conf:        "mapping.yml",
		Cache:       constants.DefaultCertCacheDir,
		RTo:         constants.DefaultReadTimeout,
		WTo:         constants.DefaultWriteTimeout,
		Provider:    acme.ProviderLetsEncrypt,
		LogLevel:    constants.LogLevelInfo,
		LogFormat:   constants.LogFormatText,
		RateLimit:   constants.DefaultRateLimit,
		BurstLimit:  constants.DefaultBurstLimit,
		DDoSProtect: true,
		EnableWS:    true,
	}
	autoflags.Parse(&args)
	return args
}

// buildAppConfig builds application configuration from command-line arguments
func buildAppConfig(args runArgs) *AppConfig {
	return &AppConfig{
		ServerConfig: server.Config{
			Addr:         args.Addr,
			HTTP:         args.HTTP,
			Cache:        args.Cache,
			HSTS:         args.HSTS,
			Email:        args.Email,
			Provider:     args.Provider,
			ACMEURL:      args.ACMEURL,
			EABKID:       args.EABKID,
			EABHMAC:      args.EABHMAC,
			ReadTimeout:  args.RTo,
			WriteTimeout: args.WTo,
			IdleTimeout:  args.Idle,
		},
		ACMEConfig: acme.Config{
			Provider:     args.Provider,
			DirectoryURL: args.ACMEURL,
			Email:        args.Email,
			CacheDir:     args.Cache,
			EABKID:       args.EABKID,
			EABHMAC:      args.EABHMAC,
		},
		DBProxyEnabled: args.DBConf != "",
		DBProxyConfig:  args.DBConf,
		ObservabilityConfig: ObservabilityConfig{
			LogLevel:        args.LogLevel,
			LogFormat:       args.LogFormat,
			MetricsAddr:     args.MetricsAddr,
			HealthAddr:      args.HealthAddr,
			TracingEndpoint: args.TracingEndpoint,
			TracingExporter: args.TracingExporter,
		},
		SecurityConfig: SecurityConfig{
			RateLimit:    args.RateLimit,
			BurstLimit:   args.BurstLimit,
			DDoSProtect:  args.DDoSProtect,
			SecurityScan: args.SecurityScan,
		},
		FeaturesConfig: FeaturesConfig{
			EnableWebSocket: args.EnableWS,
			PluginDir:       args.PluginDir,
			AdminAddr:       args.AdminAddr,
		},
	}
}