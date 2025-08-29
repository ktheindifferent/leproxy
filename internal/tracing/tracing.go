package tracing

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
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
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	config   Config
}

// NewTracerProvider creates a new tracer provider
func NewTracerProvider(cfg Config) (*TracerProvider, error) {
	if !cfg.Enabled {
		// Return no-op provider if tracing is disabled
		return &TracerProvider{
			tracer: otel.Tracer(cfg.ServiceName),
			config: cfg,
		}, nil
	}
	
	// Create resource without specifying schema to avoid conflicts
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			"", // Empty schema URL to avoid conflicts
			attribute.String("service.name", cfg.ServiceName),
			attribute.String("service.version", "1.0.0"),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}
	
	// Create exporter based on type
	var exporter sdktrace.SpanExporter
	switch cfg.ExporterType {
	case "jaeger":
		exporter, err = createJaegerExporter(cfg)
	case "otlp":
		exporter, err = createOTLPExporter(cfg)
	default:
		// Use stdout exporter as fallback
		exporter, err = createStdoutExporter()
	}
	
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
	
	return &TracerProvider{
		provider: provider,
		tracer:   provider.Tracer(cfg.ServiceName),
		config:   cfg,
	}, nil
}

// Shutdown shuts down the tracer provider with enhanced error handling
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.provider == nil {
		// No-op provider, nothing to shutdown
		return nil
	}
	
	// Create a channel to capture the shutdown result
	done := make(chan error, 1)
	
	go func() {
		done <- tp.provider.Shutdown(ctx)
	}()
	
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("failed to shutdown tracer provider for service %s: %w", tp.config.ServiceName, err)
		}
		return nil
	case <-ctx.Done():
		// Context timeout/cancellation
		return fmt.Errorf("tracer provider shutdown timed out for service %s: %w", tp.config.ServiceName, ctx.Err())
	}
}

// Tracer returns the tracer
func (tp *TracerProvider) Tracer() trace.Tracer {
	return tp.tracer
}

// StartSpan starts a new span
func (tp *TracerProvider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tp.tracer.Start(ctx, name, opts...)
}

// createJaegerExporter creates a Jaeger exporter
func createJaegerExporter(cfg Config) (sdktrace.SpanExporter, error) {
	endpoint := cfg.JaegerEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:14268/api/traces"
	}
	
	return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint)))
}

// createOTLPExporter creates an OTLP exporter
func createOTLPExporter(cfg Config) (sdktrace.SpanExporter, error) {
	endpoint := cfg.OTLPEndpoint
	if endpoint == "" {
		endpoint = "localhost:4317"
	}
	
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
	}
	
	if cfg.OTLPInsecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	
	if len(cfg.OTLPHeaders) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(cfg.OTLPHeaders))
	}
	
	client := otlptracegrpc.NewClient(opts...)
	return otlptrace.New(context.Background(), client)
}

// createStdoutExporter creates a stdout exporter for debugging
func createStdoutExporter() (sdktrace.SpanExporter, error) {
	// Stdout exporter has been moved to a separate package in newer versions
	// For now, return a noop exporter or use Jaeger with a local endpoint
	return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint("http://localhost:14268/api/traces")))
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

// InitTracer initializes a new tracer provider with the given configuration
func InitTracer(serviceName, endpoint, exporterType string) (*TracerProvider, error) {
	// Determine sample rate based on environment
	sampleRate := 1.0 // Default to sampling everything
	if os.Getenv("OTEL_TRACE_SAMPLE_RATE") != "" {
		if rate, err := strconv.ParseFloat(os.Getenv("OTEL_TRACE_SAMPLE_RATE"), 64); err == nil {
			sampleRate = rate
		}
	}
	
	config := Config{
		Enabled:      true,
		ServiceName:  serviceName,
		Environment:  os.Getenv("ENVIRONMENT"),
		ExporterType: exporterType,
		Endpoint:     endpoint,
		SampleRate:   sampleRate,
	}
	
	// Configure based on exporter type
	switch exporterType {
	case "jaeger":
		config.JaegerEndpoint = endpoint
	case "otlp":
		config.OTLPEndpoint = endpoint
		config.OTLPInsecure = true // Use insecure by default for local development
		
		// Check for OTLP headers in environment
		if headers := os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"); headers != "" {
			config.OTLPHeaders = make(map[string]string)
			for _, header := range strings.Split(headers, ",") {
				parts := strings.SplitN(header, "=", 2)
				if len(parts) == 2 {
					config.OTLPHeaders[parts[0]] = parts[1]
				}
			}
		}
	default:
		// Stdout exporter for unknown types
		config.ExporterType = "stdout"
	}
	
	return NewTracerProvider(config)
}