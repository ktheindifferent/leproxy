package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

type Metric struct {
	Name        string
	Type        MetricType
	Help        string
	Labels      map[string]string
	value       float64
	histogram   *Histogram
	mu          sync.RWMutex
}

type Histogram struct {
	buckets  []float64
	counts   []uint64
	sum      float64
	count    uint64
}

type Registry struct {
	mu      sync.RWMutex
	metrics map[string]*Metric
}

var defaultRegistry = &Registry{
	metrics: make(map[string]*Metric),
}

func NewRegistry() *Registry {
	return &Registry{
		metrics: make(map[string]*Metric),
	}
}

// DefaultRegistry returns the default metrics registry
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// IsEnabled returns true if metrics collection is enabled
func IsEnabled() bool {
	// You can make this configurable via environment variable or config
	return true
}

func (r *Registry) Register(name string, metricType MetricType, help string) *Metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	metric := &Metric{
		Name:   name,
		Type:   metricType,
		Help:   help,
		Labels: make(map[string]string),
	}
	
	if metricType == MetricTypeHistogram {
		metric.histogram = &Histogram{
			buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			counts:  make([]uint64, 11),
		}
	}
	
	r.metrics[name] = metric
	return metric
}

func (r *Registry) Get(name string) *Metric {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.metrics[name]
}

func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.WriteTo(w)
	}
}

func (r *Registry) WriteTo(w http.ResponseWriter) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	for _, metric := range r.metrics {
		fmt.Fprintf(w, "# HELP %s %s\n", metric.Name, metric.Help)
		fmt.Fprintf(w, "# TYPE %s %s\n", metric.Name, metric.Type)
		
		labels := formatLabels(metric.Labels)
		
		switch metric.Type {
		case MetricTypeCounter, MetricTypeGauge:
			metric.mu.RLock()
			fmt.Fprintf(w, "%s%s %g\n", metric.Name, labels, metric.value)
			metric.mu.RUnlock()
			
		case MetricTypeHistogram:
			metric.mu.RLock()
			h := metric.histogram
			for i, bucket := range h.buckets {
				fmt.Fprintf(w, "%s_bucket{%sle=\"%g\"} %d\n", 
					metric.Name, 
					labelString(metric.Labels), 
					bucket, 
					h.counts[i])
			}
			fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", metric.Name, labelString(metric.Labels), h.count)
			fmt.Fprintf(w, "%s_sum%s %g\n", metric.Name, labels, h.sum)
			fmt.Fprintf(w, "%s_count%s %d\n", metric.Name, labels, h.count)
			metric.mu.RUnlock()
		}
	}
}

func (m *Metric) Inc() {
	m.Add(1)
}

func (m *Metric) Dec() {
	m.Add(-1)
}

func (m *Metric) Add(v float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value += v
}

func (m *Metric) Set(v float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value = v
}

func (m *Metric) Observe(v float64) {
	if m.Type != MetricTypeHistogram {
		return
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	h := m.histogram
	h.sum += v
	h.count++
	
	for i, bucket := range h.buckets {
		if v <= bucket {
			h.counts[i]++
			break
		}
	}
}

func (m *Metric) WithLabels(labels map[string]string) *Metric {
	newMetric := &Metric{
		Name:      m.Name,
		Type:      m.Type,
		Help:      m.Help,
		Labels:    labels,
		histogram: m.histogram,
	}
	return newMetric
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	
	result := "{"
	first := true
	for k, v := range labels {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%s=\"%s\"", k, v)
		first = false
	}
	result += "}"
	return result
}

func labelString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	
	result := ""
	for k, v := range labels {
		result += fmt.Sprintf("%s=\"%s\",", k, v)
	}
	return result
}

// Pre-defined metrics
var (
	HTTPRequestsTotal = defaultRegistry.Register(
		"http_requests_total",
		MetricTypeCounter,
		"Total number of HTTP requests",
	)
	
	// Declare enhanced certificate renewal metrics
	CertificateRenewalLatency    *Metric
	CertificateRenewalRetries     *Metric
	CertificateRenewalQueueSize   *Metric
	CertificateEmergencyRenewals  *Metric
	ACMEProviderErrors           *Metric
	ACMEProviderLatency          *Metric
	RenewalManagerHealth         *Metric
	
	HTTPRequestDuration = defaultRegistry.Register(
		"http_request_duration_seconds",
		MetricTypeHistogram,
		"HTTP request latencies in seconds",
	)
	
	HTTPActiveConnections = defaultRegistry.Register(
		"http_active_connections",
		MetricTypeGauge,
		"Number of active HTTP connections",
	)
	
	ProxyConnectionsTotal = defaultRegistry.Register(
		"proxy_connections_total",
		MetricTypeCounter,
		"Total number of proxy connections by type",
	)
	
	ProxyActiveConnections = defaultRegistry.Register(
		"proxy_active_connections",
		MetricTypeGauge,
		"Number of active proxy connections by type",
	)
	
	ProxyBytesTransferred = defaultRegistry.Register(
		"proxy_bytes_transferred_total",
		MetricTypeCounter,
		"Total bytes transferred through proxy",
	)
	
	CertificateExpirySeconds = defaultRegistry.Register(
		"certificate_expiry_seconds",
		MetricTypeGauge,
		"Certificate expiry time in seconds since epoch",
	)
	
	CertificateRenewalsTotal = defaultRegistry.Register(
		"certificate_renewals_total",
		MetricTypeCounter,
		"Total number of certificate renewals",
	)
	
	ErrorsTotal = defaultRegistry.Register(
		"errors_total",
		MetricTypeCounter,
		"Total number of errors by type",
	)
	
	ProxyTimeoutsTotal = defaultRegistry.Register(
		"proxy_timeouts_total",
		MetricTypeCounter,
		"Total number of proxy timeouts by type",
	)
	
	ProxyRetriesTotal = defaultRegistry.Register(
		"proxy_retries_total",
		MetricTypeCounter,
		"Total number of proxy operation retries",
	)
)

// init initializes the enhanced certificate renewal metrics
func init() {
	// Initialize enhanced certificate renewal metrics
	CertificateRenewalLatency = defaultRegistry.Register(
		"certificate_renewal_latency_seconds",
		MetricTypeHistogram,
		"Certificate renewal latency in seconds",
	)
	
	CertificateRenewalRetries = defaultRegistry.Register(
		"certificate_renewal_retries_total",
		MetricTypeCounter,
		"Total number of certificate renewal retries",
	)
	
	CertificateRenewalQueueSize = defaultRegistry.Register(
		"certificate_renewal_queue_size",
		MetricTypeGauge,
		"Number of certificates pending renewal",
	)
	
	CertificateEmergencyRenewals = defaultRegistry.Register(
		"certificate_emergency_renewals_total",
		MetricTypeCounter,
		"Total number of emergency certificate renewals",
	)
	
	ACMEProviderErrors = defaultRegistry.Register(
		"acme_provider_errors_total",
		MetricTypeCounter,
		"Total number of ACME provider errors",
	)
	
	ACMEProviderLatency = defaultRegistry.Register(
		"acme_provider_latency_seconds",
		MetricTypeHistogram,
		"ACME provider response latency",
	)
	
	RenewalManagerHealth = defaultRegistry.Register(
		"renewal_manager_health",
		MetricTypeGauge,
		"Renewal manager health status (1=healthy, 0=unhealthy)",
	)
}

// Middleware for HTTP metrics
func HTTPMetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		HTTPActiveConnections.Inc()
		defer HTTPActiveConnections.Dec()
		
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start).Seconds()
		
		labels := map[string]string{
			"method": r.Method,
			"status": strconv.Itoa(wrapped.statusCode),
			"path":   r.URL.Path,
		}
		
		HTTPRequestsTotal.WithLabels(labels).Inc()
		HTTPRequestDuration.WithLabels(labels).Observe(duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Helper functions for proxy metrics
func RecordProxyConnection(proxyType string) {
	labels := map[string]string{"type": proxyType}
	ProxyConnectionsTotal.WithLabels(labels).Inc()
	ProxyActiveConnections.WithLabels(labels).Inc()
}

func RecordProxyDisconnection(proxyType string) {
	labels := map[string]string{"type": proxyType}
	ProxyActiveConnections.WithLabels(labels).Dec()
}

func RecordProxyBytes(proxyType string, direction string, bytes float64) {
	labels := map[string]string{
		"type":      proxyType,
		"direction": direction,
	}
	ProxyBytesTransferred.WithLabels(labels).Add(bytes)
}

func RecordError(errorType string) {
	labels := map[string]string{"type": errorType}
	ErrorsTotal.WithLabels(labels).Inc()
}

func UpdateCertificateExpiry(domain string, expiryTime time.Time) {
	labels := map[string]string{"domain": domain}
	CertificateExpirySeconds.WithLabels(labels).Set(float64(expiryTime.Unix()))
}

func RecordCertificateRenewal(domain string, success bool) {
	labels := map[string]string{
		"domain":  domain,
		"success": strconv.FormatBool(success),
	}
	CertificateRenewalsTotal.WithLabels(labels).Inc()
}

// Enhanced certificate renewal metrics functions

func RecordRenewalLatency(domain string, provider string, duration float64) {
	labels := map[string]string{
		"domain":   domain,
		"provider": provider,
	}
	CertificateRenewalLatency.WithLabels(labels).Observe(duration)
}

func RecordRenewalRetry(domain string, attempt int) {
	labels := map[string]string{
		"domain":  domain,
		"attempt": strconv.Itoa(attempt),
	}
	CertificateRenewalRetries.WithLabels(labels).Inc()
}

func UpdateRenewalQueueSize(size float64) {
	CertificateRenewalQueueSize.Set(size)
}

func RecordEmergencyRenewal(domain string) {
	labels := map[string]string{"domain": domain}
	CertificateEmergencyRenewals.WithLabels(labels).Inc()
}

func RecordACMEError(provider string, errorType string) {
	labels := map[string]string{
		"provider": provider,
		"error":    errorType,
	}
	ACMEProviderErrors.WithLabels(labels).Inc()
}

func RecordACMELatency(provider string, operation string, duration float64) {
	labels := map[string]string{
		"provider":  provider,
		"operation": operation,
	}
	ACMEProviderLatency.WithLabels(labels).Observe(duration)
}

func UpdateRenewalManagerHealth(healthy bool) {
	if healthy {
		RenewalManagerHealth.Set(1)
	} else {
		RenewalManagerHealth.Set(0)
	}
}

// RenewalMetricsCollector provides a unified interface for renewal metrics
type RenewalMetricsCollector struct {
	mu sync.RWMutex
	statuses map[string]RenewalMetricStatus
}

type RenewalMetricStatus struct {
	Domain         string
	LastAttempt    time.Time
	LastSuccess    time.Time
	FailureCount   int
	IsRenewing     bool
	ExpiryDate     time.Time
}

func NewRenewalMetricsCollector() *RenewalMetricsCollector {
	return &RenewalMetricsCollector{
		statuses: make(map[string]RenewalMetricStatus),
	}
}

func (r *RenewalMetricsCollector) UpdateStatus(domain string, status RenewalMetricStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses[domain] = status
	
	// Update queue size metric
	pendingCount := 0
	for _, s := range r.statuses {
		if s.IsRenewing {
			pendingCount++
		}
	}
	UpdateRenewalQueueSize(float64(pendingCount))
}

func (r *RenewalMetricsCollector) GetMetricsSummary() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	totalDomains := len(r.statuses)
	renewingCount := 0
	failedCount := 0
	expiringCount := 0
	
	for _, status := range r.statuses {
		if status.IsRenewing {
			renewingCount++
		}
		if status.FailureCount > 0 {
			failedCount++
		}
		if time.Until(status.ExpiryDate) < 7*24*time.Hour {
			expiringCount++
		}
	}
	
	return map[string]interface{}{
		"total_domains":   totalDomains,
		"renewing_count":  renewingCount,
		"failed_count":    failedCount,
		"expiring_count":  expiringCount,
		"statuses":        r.statuses,
	}
}

func Register(name string, metricType MetricType, help string) *Metric {
	return defaultRegistry.Register(name, metricType, help)
}

func Get(name string) *Metric {
	return defaultRegistry.Get(name)
}

func Handler() http.HandlerFunc {
	return defaultRegistry.Handler()
}

// RecordTimeout records proxy timeout metrics
func RecordTimeout(proxyType string, timeoutType string, direction string) {
	labels := map[string]string{
		"proxy_type":   proxyType,
		"timeout_type": timeoutType,
		"direction":    direction,
	}
	ProxyTimeoutsTotal.WithLabels(labels).Inc()
}

// RecordRetry records proxy retry metrics
func RecordRetry(proxyType string, direction string) {
	labels := map[string]string{
		"proxy_type": proxyType,
		"direction":  direction,
	}
	ProxyRetriesTotal.WithLabels(labels).Inc()
}

// RecordPanic records goroutine panic metrics
func RecordPanic(goroutineName string, panicMessage string) {
	labels := map[string]string{
		"goroutine": goroutineName,
		"panic":     panicMessage,
	}
	// Use an existing counter or create one
	if counter := Get("goroutine_panics_total"); counter != nil {
		counter.WithLabels(labels).Inc()
	}
}

// RecordCopyError records io.Copy operation errors with directional context
func RecordCopyError(srcName, dstName, errorType string) {
	labels := map[string]string{
		"source":      srcName,
		"destination": dstName,
		"error_type":  errorType,
	}
	// Use ErrorsTotal with additional labels for copy operations
	ErrorsTotal.WithLabels(labels).Inc()
}

// RecordCopyBytes records bytes transferred in copy operations
func RecordCopyBytes(srcName, dstName string, bytes int64) {
	labels := map[string]string{
		"source":      srcName,
		"destination": dstName,
	}
	ProxyBytesTransferred.WithLabels(labels).Add(float64(bytes))
}

// Server represents a metrics HTTP server
type Server struct {
	addr       string
	httpServer *http.Server
	mu         sync.Mutex
	started    bool
}

// NewServer creates a new metrics server
func NewServer(addr string) *Server {
	return &Server{
		addr: addr,
	}
}

// Start starts the metrics server
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.started {
		return fmt.Errorf("metrics server already started")
	}
	
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler())
	
	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}
	
	s.started = true
	return s.httpServer.ListenAndServe()
}

// Stop gracefully stops the metrics server
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.started || s.httpServer == nil {
		return nil
	}
	
	s.started = false
	return s.httpServer.Shutdown(ctx)
}