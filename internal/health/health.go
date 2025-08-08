package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

type CheckResult struct {
	Name      string        `json:"name"`
	Status    Status        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Latency   time.Duration `json:"latency_ms"`
	Timestamp time.Time     `json:"timestamp"`
}

type HealthStatus struct {
	Status     Status                 `json:"status"`
	Version    string                 `json:"version"`
	Uptime     time.Duration          `json:"uptime_seconds"`
	Checks     []CheckResult          `json:"checks,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
}

type HealthChecker struct {
	mu        sync.RWMutex
	checks    map[string]CheckFunc
	metadata  map[string]interface{}
	startTime time.Time
	version   string
}

type CheckFunc func(ctx context.Context) error

func New(version string) *HealthChecker {
	return &HealthChecker{
		checks:    make(map[string]CheckFunc),
		metadata:  make(map[string]interface{}),
		startTime: time.Now(),
		version:   version,
	}
}

func (h *HealthChecker) RegisterCheck(name string, check CheckFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = check
}

func (h *HealthChecker) SetMetadata(key string, value interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.metadata[key] = value
}

func (h *HealthChecker) Check(ctx context.Context) HealthStatus {
	h.mu.RLock()
	checks := make(map[string]CheckFunc)
	for name, check := range h.checks {
		checks[name] = check
	}
	metadata := make(map[string]interface{})
	for k, v := range h.metadata {
		metadata[k] = v
	}
	h.mu.RUnlock()

	status := HealthStatus{
		Status:    StatusHealthy,
		Version:   h.version,
		Uptime:    time.Since(h.startTime),
		Checks:    make([]CheckResult, 0, len(checks)),
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	var wg sync.WaitGroup
	resultsCh := make(chan CheckResult, len(checks))

	for name, check := range checks {
		wg.Add(1)
		go func(name string, check CheckFunc) {
			defer wg.Done()
			
			start := time.Now()
			result := CheckResult{
				Name:      name,
				Status:    StatusHealthy,
				Timestamp: time.Now(),
			}

			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			if err := check(checkCtx); err != nil {
				result.Status = StatusUnhealthy
				result.Message = err.Error()
			}
			
			result.Latency = time.Since(start)
			resultsCh <- result
		}(name, check)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	hasUnhealthy := false
	hasDegraded := false
	
	for result := range resultsCh {
		status.Checks = append(status.Checks, result)
		switch result.Status {
		case StatusUnhealthy:
			hasUnhealthy = true
		case StatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		status.Status = StatusUnhealthy
	} else if hasDegraded {
		status.Status = StatusDegraded
	}

	return status
}

func (h *HealthChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")
		
		httpStatus := http.StatusOK
		if status.Status == StatusUnhealthy {
			httpStatus = http.StatusServiceUnavailable
		} else if status.Status == StatusDegraded {
			httpStatus = http.StatusOK
		}

		w.WriteHeader(httpStatus)
		json.NewEncoder(w).Encode(status)
	}
}

func (h *HealthChecker) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		status := h.Check(ctx)

		w.Header().Set("Content-Type", "application/json")
		
		ready := status.Status != StatusUnhealthy
		response := map[string]interface{}{
			"ready":     ready,
			"timestamp": time.Now(),
		}

		httpStatus := http.StatusOK
		if !ready {
			httpStatus = http.StatusServiceUnavailable
			response["reason"] = "Health checks failed"
			
			var failedChecks []string
			for _, check := range status.Checks {
				if check.Status == StatusUnhealthy {
					failedChecks = append(failedChecks, check.Name)
				}
			}
			response["failed_checks"] = failedChecks
		}

		w.WriteHeader(httpStatus)
		json.NewEncoder(w).Encode(response)
	}
}

func (h *HealthChecker) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"alive":     true,
			"timestamp": time.Now(),
			"uptime":    time.Since(h.startTime).Seconds(),
		})
	}
}

func TCPCheck(address string) CheckFunc {
	return func(ctx context.Context) error {
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return fmt.Errorf("tcp check failed: %w", err)
		}
		conn.Close()
		return nil
	}
}

func HTTPCheck(url string) CheckFunc {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("http check failed: %w", err)
		}

		client := &http.Client{
			Timeout: 3 * time.Second,
		}
		
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("http check failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			return fmt.Errorf("http check failed: status %d", resp.StatusCode)
		}

		return nil
	}
}

func CertificateCheck(certPath string) CheckFunc {
	return func(ctx context.Context) error {
		return nil
	}
}

func DiskSpaceCheck(path string, minPercent float64) CheckFunc {
	return func(ctx context.Context) error {
		return nil
	}
}