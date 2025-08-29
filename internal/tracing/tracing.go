package tracing

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds tracing configuration
type Config struct {
	Enabled      bool
	ServiceName  string
	Environment  string
	ExporterType string // "jaeger", "otlp", "stdout"
	Endpoint     string
	SampleRate   float64
	
	// Jaeger specific
	JaegerEndpoint string
	
	// OTLP specific
	OTLPEndpoint string
	OTLPInsecure bool
	OTLPHeaders  map[string]string
}

// TracerProvider wraps the OpenTelemetry tracer provider
type TracerProvider struct {
	provider        *sdktrace.TracerProvider
	tracer          trace.Tracer
	config          ExtendedConfig
	validator       *ConfigValidator
	circuitBreaker  *CircuitBreaker
	metricsCollector *MetricsCollector
	mu              sync.RWMutex
	fallbackActive  bool
}

// NewTracerProvider creates a new tracer provider with enhanced configuration
func NewTracerProvider(cfg Config) (*TracerProvider, error) {
	return NewTracerProviderWithExtendedConfig(ExtendedConfig{Config: cfg})
}

// NewTracerProviderWithExtendedConfig creates a new tracer provider with extended configuration
func NewTracerProviderWithExtendedConfig(cfg ExtendedConfig) (*TracerProvider, error) {
	// Create validator
	validator := NewConfigValidator()
	
	// Validate configuration
	if err := validator.ValidateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	
	if !cfg.Enabled {
		// Return no-op provider if tracing is disabled
		return &TracerProvider{
			tracer:    otel.Tracer(cfg.ServiceName),
			config:    cfg,
			validator: validator,
		}, nil
	}
	
	// Create resource - using NewSchemaless to avoid schema conflicts
	res := resource.NewSchemaless(
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", "1.0.0"),
		attribute.String("environment", cfg.Environment),
	)
	
	// Create metrics collector
	metricsCollector := NewMetricsCollector()
	
	// Create exporter with health checks and fallback
	exporter, fallbackActive, err := createExporterWithFallback(context.Background(), cfg, validator, metricsCollector)
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}
	
	// Create tracer provider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRate)),
	)
	
	// Set global provider
	otel.SetTracerProvider(provider)
	
	// Set global propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	
	tp := &TracerProvider{
		provider:         provider,
		tracer:           provider.Tracer(cfg.ServiceName),
		config:           cfg,
		validator:        validator,
		metricsCollector: metricsCollector,
		fallbackActive:   fallbackActive,
	}
	
	// Get circuit breaker for the endpoint if enabled
	if cfg.EnableCircuitBreaker {
		endpoint := getEndpointFromConfig(cfg)
		tp.circuitBreaker = validator.GetCircuitBreaker(
			endpoint,
			cfg.CircuitBreakerThreshold,
			cfg.CircuitBreakerTimeout,
		)
	}
	
	return tp, nil
}

// Shutdown shuts down the tracer provider
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.provider != nil {
		return tp.provider.Shutdown(ctx)
	}
	return nil
}

// Tracer returns the tracer
func (tp *TracerProvider) Tracer() trace.Tracer {
	return tp.tracer
}

// StartSpan starts a new span
func (tp *TracerProvider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tp.tracer.Start(ctx, name, opts...)
}

// createJaegerExporter creates a Jaeger exporter with timeout support
func createJaegerExporter(cfg ExtendedConfig) (sdktrace.SpanExporter, error) {
	endpoint := cfg.JaegerEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:14268/api/traces"
	}
	
	opts := []jaeger.CollectorEndpointOption{
		jaeger.WithEndpoint(endpoint),
	}
	
	// Add timeout if configured
	if cfg.ExportTimeout > 0 {
		client := &http.Client{
			Timeout: cfg.ExportTimeout,
		}
		opts = append(opts, jaeger.WithHTTPClient(client))
	}
	
	return jaeger.New(jaeger.WithCollectorEndpoint(opts...))
}

// createOTLPExporter creates an OTLP exporter with timeout support
func createOTLPExporter(ctx context.Context, cfg ExtendedConfig) (sdktrace.SpanExporter, error) {
	endpoint := cfg.OTLPEndpoint
	if endpoint == "" {
		endpoint = "localhost:4317"
	}
	
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
	}
	
	// Configure connection with timeout
	if cfg.ConnectionTimeout > 0 {
		dialOpts := []grpc.DialOption{
			grpc.WithBlock(),
			grpc.WithTimeout(cfg.ConnectionTimeout),
		}
		
		if cfg.OTLPInsecure {
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		
		opts = append(opts, otlptracegrpc.WithDialOption(dialOpts...))
	} else if cfg.OTLPInsecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	
	if len(cfg.OTLPHeaders) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(cfg.OTLPHeaders))
	}
	
	// Add timeout for export operations
	if cfg.ExportTimeout > 0 {
		opts = append(opts, otlptracegrpc.WithTimeout(cfg.ExportTimeout))
	}
	
	client := otlptracegrpc.NewClient(opts...)
	
	// Create context with connection timeout
	exportCtx := ctx
	if cfg.ConnectionTimeout > 0 {
		var cancel context.CancelFunc
		exportCtx, cancel = context.WithTimeout(ctx, cfg.ConnectionTimeout)
		defer cancel()
	}
	
	return otlptrace.New(exportCtx, client)
}

// createStdoutExporter creates a stdout exporter for debugging
func createStdoutExporter() (sdktrace.SpanExporter, error) {
	return stdouttrace.New(
		stdouttrace.WithWriter(os.Stdout),
		stdouttrace.WithPrettyPrint(),
	)
}

// HTTPMiddleware creates HTTP middleware for tracing
func HTTPMiddleware(tp *TracerProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract context from headers
			ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			
			// Start span
			spanName := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
			ctx, span := tp.StartSpan(ctx,
				spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.method", r.Method),
					attribute.String("http.target", r.URL.Path),
					attribute.String("http.scheme", r.URL.Scheme),
					attribute.String("http.host", r.Host),
					attribute.String("http.user_agent", r.UserAgent()),
					attribute.Int64("http.request_content_length", r.ContentLength),
				),
			)
			defer span.End()
			
			// Wrap response writer to capture status code
			wrapped := &tracedResponseWriter{
				ResponseWriter: w,
				statusCode:     200,
			}
			
			// Handle request
			start := time.Now()
			next.ServeHTTP(wrapped, r.WithContext(ctx))
			duration := time.Since(start)
			
			// Set span attributes
			span.SetAttributes(
				attribute.Int("http.status_code", wrapped.statusCode),
				attribute.Int64("http.response_content_length", wrapped.bytesWritten),
				attribute.Float64("http.duration_ms", float64(duration.Milliseconds())),
			)
			
			// Set span status based on HTTP status code
			if wrapped.statusCode >= 400 {
				span.SetStatus(codes.Error, http.StatusText(wrapped.statusCode))
			} else {
				span.SetStatus(codes.Ok, "")
			}
		})
	}
}

// tracedResponseWriter wraps http.ResponseWriter to capture response details
type tracedResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	bytesWritten  int64
	headerWritten bool
}

func (w *tracedResponseWriter) WriteHeader(statusCode int) {
	if !w.headerWritten {
		w.statusCode = statusCode
		w.headerWritten = true
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func (w *tracedResponseWriter) Write(data []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytesWritten += int64(n)
	return n, err
}

// TraceRequest traces an outgoing HTTP request
func TraceRequest(ctx context.Context, req *http.Request, spanName string) (*http.Request, trace.Span) {
	tracer := otel.Tracer("http-client")
	
	ctx, span := tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.method", req.Method),
			attribute.String("http.url", req.URL.String()),
			attribute.String("http.target", req.URL.Path),
			attribute.String("http.host", req.Host),
		),
	)
	
	// Inject trace context into headers
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	
	return req.WithContext(ctx), span
}

// TraceResponse updates span with response details
func TraceResponse(span trace.Span, resp *http.Response, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return
	}
	
	span.SetAttributes(
		attribute.Int("http.status_code", resp.StatusCode),
		attribute.Int64("http.response_content_length", resp.ContentLength),
	)
	
	if resp.StatusCode >= 400 {
		span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
	} else {
		span.SetStatus(codes.Ok, "")
	}
}

// DatabaseSpan creates a span for database operations
func DatabaseSpan(ctx context.Context, operation, dbType, query string) (context.Context, trace.Span) {
	tracer := otel.Tracer("database")
	
	return tracer.Start(ctx,
		fmt.Sprintf("%s.%s", dbType, operation),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", dbType),
			attribute.String("db.operation", operation),
			attribute.String("db.statement", query),
		),
	)
}

// ProxySpan creates a span for proxy operations
func ProxySpan(ctx context.Context, proxyType, backend string) (context.Context, trace.Span) {
	tracer := otel.Tracer("proxy")
	
	return tracer.Start(ctx,
		fmt.Sprintf("proxy.%s", proxyType),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("proxy.type", proxyType),
			attribute.String("proxy.backend", backend),
		),
	)
}

// RecordError records an error in the current span
func RecordError(ctx context.Context, err error, description string) {
	span := trace.SpanFromContext(ctx)
	if span != nil {
		span.RecordError(err, trace.WithAttributes(
			attribute.String("error.description", description),
		))
		span.SetStatus(codes.Error, description)
	}
}

// AddEvent adds an event to the current span
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span != nil {
		span.AddEvent(name, trace.WithAttributes(attrs...))
	}
}

// SetAttributes sets attributes on the current span
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span != nil {
		span.SetAttributes(attrs...)
	}
}

// WithSpan executes a function within a span
func WithSpan(ctx context.Context, name string, fn func(context.Context) error, opts ...trace.SpanStartOption) error {
	tracer := otel.Tracer("leproxy")
	ctx, span := tracer.Start(ctx, name, opts...)
	defer span.End()
	
	err := fn(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	
	return err
}

// ExtractTraceID extracts the trace ID from context
func ExtractTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span != nil {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// ExtractSpanID extracts the span ID from context
func ExtractSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span != nil {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// InjectHTTPHeaders injects trace context into HTTP headers
func InjectHTTPHeaders(ctx context.Context, headers http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(headers))
}

// ExtractHTTPHeaders extracts trace context from HTTP headers
func ExtractHTTPHeaders(ctx context.Context, headers http.Header) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(headers))
}

// createExporterWithFallback creates an exporter with health checks and fallback support
func createExporterWithFallback(ctx context.Context, cfg ExtendedConfig, validator *ConfigValidator, metrics *MetricsCollector) (sdktrace.SpanExporter, bool, error) {
	var primaryExporter sdktrace.SpanExporter
	var err error
	fallbackActive := false
	
	// Check endpoint health if not stdout
	if cfg.ExporterType != "stdout" {
		endpoint := getEndpointFromConfig(cfg)
		healthy, healthErr := validator.CheckEndpointHealth(ctx, cfg.ExporterType, endpoint)
		
		if !healthy && cfg.EnableFallback {
			log.Printf("Primary exporter endpoint %s is unhealthy: %v. Using fallback to stdout", endpoint, healthErr)
			metrics.RecordExportFailure(cfg.ExporterType, "health_check_failed")
			fallbackActive = true
		}
	}
	
	// Create primary exporter or fallback
	if !fallbackActive {
		// Try to create the primary exporter with retry
		err = RetryWithBackoff(ctx, func() error {
			switch cfg.ExporterType {
			case "jaeger":
				primaryExporter, err = createJaegerExporter(cfg)
			case "otlp":
				primaryExporter, err = createOTLPExporter(ctx, cfg)
			case "stdout":
				primaryExporter, err = createStdoutExporter()
			default:
				primaryExporter, err = createStdoutExporter()
			}
			return err
		}, cfg.MaxRetries, cfg.RetryDelay)
		
		if err != nil && cfg.EnableFallback {
			log.Printf("Failed to create primary exporter after retries: %v. Using fallback to stdout", err)
			metrics.RecordExportFailure(cfg.ExporterType, "creation_failed")
			fallbackActive = true
		}
	}
	
	// Use fallback if needed
	if fallbackActive && cfg.FallbackToStdout {
		primaryExporter, err = createStdoutExporter()
		if err != nil {
			return nil, false, fmt.Errorf("failed to create fallback stdout exporter: %w", err)
		}
		metrics.RecordFallbackActivation()
	} else if err != nil {
		return nil, false, err
	}
	
	// Wrap exporter with metrics collection
	wrappedExporter := &MetricExporter{
		exporter: primaryExporter,
		metrics:  metrics,
		exporterType: cfg.ExporterType,
	}
	
	return wrappedExporter, fallbackActive, nil
}

// getEndpointFromConfig extracts the endpoint from configuration
func getEndpointFromConfig(cfg ExtendedConfig) string {
	switch cfg.ExporterType {
	case "jaeger":
		if cfg.JaegerEndpoint != "" {
			return cfg.JaegerEndpoint
		}
		return "http://localhost:14268/api/traces"
	case "otlp":
		if cfg.OTLPEndpoint != "" {
			return cfg.OTLPEndpoint
		}
		return "localhost:4317"
	default:
		return ""
	}
}

// MetricsCollector collects metrics for tracing operations
type MetricsCollector struct {
	mu                 sync.RWMutex
	exportSuccesses    map[string]int64
	exportFailures     map[string]int64
	exportLatencies    map[string][]time.Duration
	fallbackActivations int64
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		exportSuccesses: make(map[string]int64),
		exportFailures:  make(map[string]int64),
		exportLatencies: make(map[string][]time.Duration),
	}
}

// RecordExportSuccess records a successful export
func (mc *MetricsCollector) RecordExportSuccess(exporterType string, latency time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	mc.exportSuccesses[exporterType]++
	mc.exportLatencies[exporterType] = append(mc.exportLatencies[exporterType], latency)
	
	// Keep only last 100 latency measurements
	if len(mc.exportLatencies[exporterType]) > 100 {
		mc.exportLatencies[exporterType] = mc.exportLatencies[exporterType][1:]
	}
}

// RecordExportFailure records a failed export
func (mc *MetricsCollector) RecordExportFailure(exporterType string, reason string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	key := fmt.Sprintf("%s_%s", exporterType, reason)
	mc.exportFailures[key]++
}

// RecordFallbackActivation records when fallback is activated
func (mc *MetricsCollector) RecordFallbackActivation() {
	atomic.AddInt64(&mc.fallbackActivations, 1)
}

// GetMetrics returns current metrics
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	metrics := make(map[string]interface{})
	metrics["export_successes"] = mc.exportSuccesses
	metrics["export_failures"] = mc.exportFailures
	metrics["fallback_activations"] = atomic.LoadInt64(&mc.fallbackActivations)
	
	// Calculate average latencies
	avgLatencies := make(map[string]float64)
	for exporterType, latencies := range mc.exportLatencies {
		if len(latencies) > 0 {
			var sum time.Duration
			for _, l := range latencies {
				sum += l
			}
			avgLatencies[exporterType] = float64(sum.Milliseconds()) / float64(len(latencies))
		}
	}
	metrics["average_export_latencies_ms"] = avgLatencies
	
	return metrics
}

// MetricExporter wraps an exporter with metrics collection
type MetricExporter struct {
	exporter     sdktrace.SpanExporter
	metrics      *MetricsCollector
	exporterType string
}

// ExportSpans exports spans with metrics collection
func (me *MetricExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	start := time.Now()
	err := me.exporter.ExportSpans(ctx, spans)
	latency := time.Since(start)
	
	if err != nil {
		me.metrics.RecordExportFailure(me.exporterType, "export_error")
		return err
	}
	
	me.metrics.RecordExportSuccess(me.exporterType, latency)
	return nil
}

// Shutdown shuts down the exporter
func (me *MetricExporter) Shutdown(ctx context.Context) error {
	return me.exporter.Shutdown(ctx)
}

// IsFallbackActive returns true if the fallback exporter is being used
func (tp *TracerProvider) IsFallbackActive() bool {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.fallbackActive
}

// GetMetrics returns tracing metrics
func (tp *TracerProvider) GetMetrics() map[string]interface{} {
	if tp.metricsCollector != nil {
		return tp.metricsCollector.GetMetrics()
	}
	return nil
}

// GetCircuitBreakerState returns the circuit breaker state if enabled
func (tp *TracerProvider) GetCircuitBreakerState() string {
	if tp.circuitBreaker != nil {
		return tp.circuitBreaker.GetState()
	}
	return "disabled"
}