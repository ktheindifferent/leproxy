package tracing

import (
	"context"
	"fmt"
	"net/http"
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
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
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
	
	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(cfg.ServiceName),
			semconv.ServiceVersionKey.String("1.0.0"),
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
	return sdktrace.NewExporter(sdktrace.WithStdout())
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
					semconv.HTTPMethodKey.String(r.Method),
					semconv.HTTPTargetKey.String(r.URL.Path),
					semconv.HTTPSchemeKey.String(r.URL.Scheme),
					semconv.HTTPHostKey.String(r.Host),
					semconv.HTTPUserAgentKey.String(r.UserAgent()),
					semconv.HTTPRequestContentLengthKey.Int64(r.ContentLength),
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
				semconv.HTTPStatusCodeKey.Int(wrapped.statusCode),
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
			semconv.HTTPMethodKey.String(req.Method),
			semconv.HTTPURLKey.String(req.URL.String()),
			semconv.HTTPTargetKey.String(req.URL.Path),
			semconv.HTTPHostKey.String(req.Host),
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
		semconv.HTTPStatusCodeKey.Int(resp.StatusCode),
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