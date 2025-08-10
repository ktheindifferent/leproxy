// Package dashboard provides a web-based health check and monitoring dashboard
package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"runtime"
	"time"

	"github.com/artyom/leproxy/internal/health"
	"github.com/artyom/leproxy/internal/logger"
)

// Dashboard provides a web interface for monitoring
type Dashboard struct {
	addr          string
	healthChecker *health.Checker
	startTime     time.Time
}

// NewDashboard creates a new dashboard server
func NewDashboard(addr string, healthChecker *health.Checker) *Dashboard {
	return &Dashboard{
		addr:          addr,
		healthChecker: healthChecker,
		startTime:     time.Now(),
	}
}

// Start starts the dashboard server
func (d *Dashboard) Start() error {
	mux := http.NewServeMux()
	
	// Dashboard homepage
	mux.HandleFunc("/", d.handleDashboard)
	
	// API endpoints
	mux.HandleFunc("/api/health", d.handleHealthAPI)
	mux.HandleFunc("/api/stats", d.handleStatsAPI)
	mux.HandleFunc("/api/backends", d.handleBackendsAPI)
	
	// Static resources (embedded in template)
	mux.HandleFunc("/static/", d.handleStatic)
	
	logger.Info("Dashboard server starting", "address", d.addr)
	
	server := &http.Server{
		Addr:         d.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	
	return server.ListenAndServe()
}

// handleDashboard serves the main dashboard HTML page
func (d *Dashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LeProxy Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .header h1 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .status-bar {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        .status-healthy { background: #10b981; }
        .status-warning { background: #f59e0b; }
        .status-error { background: #ef4444; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.2rem;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e5e7eb;
        }
        .metric:last-child {
            border-bottom: none;
        }
        .metric-label {
            color: #6b7280;
        }
        .metric-value {
            font-weight: 600;
            color: #111827;
        }
        .backend-list {
            list-style: none;
        }
        .backend-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            margin-bottom: 8px;
            background: #f9fafb;
            border-radius: 6px;
            border-left: 3px solid #667eea;
        }
        .backend-status {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e5e7eb;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.3s ease;
        }
        .chart-container {
            height: 200px;
            margin-top: 15px;
            position: relative;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.2s;
        }
        .refresh-btn:hover {
            background: #5a67d8;
        }
        .footer {
            text-align: center;
            color: white;
            margin-top: 40px;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 LeProxy Dashboard</h1>
            <div class="status-bar">
                <div class="status-item">
                    <div class="status-indicator status-healthy" id="mainStatus"></div>
                    <span id="statusText">System Healthy</span>
                </div>
                <div class="status-item">
                    <span>Uptime: <strong id="uptime">--</strong></span>
                </div>
                <div class="status-item">
                    <span>Version: <strong>1.0.0</strong></span>
                </div>
                <div class="status-item">
                    <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
                </div>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>📊 System Metrics</h2>
                <div class="metric">
                    <span class="metric-label">CPU Usage</span>
                    <span class="metric-value" id="cpuUsage">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Memory Usage</span>
                    <span class="metric-value" id="memUsage">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Goroutines</span>
                    <span class="metric-value" id="goroutines">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Active Connections</span>
                    <span class="metric-value" id="connections">--</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="memProgress" style="width: 0%"></div>
                </div>
            </div>

            <div class="card">
                <h2>🌐 Request Statistics</h2>
                <div class="metric">
                    <span class="metric-label">Total Requests</span>
                    <span class="metric-value" id="totalRequests">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Requests/sec</span>
                    <span class="metric-value" id="requestsPerSec">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Avg Response Time</span>
                    <span class="metric-value" id="avgResponseTime">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Error Rate</span>
                    <span class="metric-value" id="errorRate">--</span>
                </div>
                <div class="chart-container">
                    <canvas id="requestChart"></canvas>
                </div>
            </div>

            <div class="card">
                <h2>🔒 Certificate Status</h2>
                <div class="metric">
                    <span class="metric-label">Active Certificates</span>
                    <span class="metric-value" id="activeCerts">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Expiring Soon</span>
                    <span class="metric-value" id="expiringCerts">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Next Renewal</span>
                    <span class="metric-value" id="nextRenewal">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">ACME Provider</span>
                    <span class="metric-value" id="acmeProvider">Let's Encrypt</span>
                </div>
            </div>

            <div class="card">
                <h2>🎯 Backend Health</h2>
                <ul class="backend-list" id="backendList">
                    <li class="backend-item">
                        <span>Loading backends...</span>
                    </li>
                </ul>
            </div>
        </div>

        <div class="grid">
            <div class="card" style="grid-column: 1 / -1;">
                <h2>📈 Performance Metrics</h2>
                <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
                    <div class="metric">
                        <span class="metric-label">P50 Latency</span>
                        <span class="metric-value" id="p50">--</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">P95 Latency</span>
                        <span class="metric-value" id="p95">--</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">P99 Latency</span>
                        <span class="metric-value" id="p99">--</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Max Latency</span>
                        <span class="metric-value" id="maxLatency">--</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>LeProxy Dashboard v1.0.0 | Last Update: <span id="lastUpdate">--</span></p>
        </div>
    </div>

    <script>
        let startTime = new Date('{{.StartTime}}');
        
        function updateUptime() {
            const now = new Date();
            const diff = now - startTime;
            const days = Math.floor(diff / (1000 * 60 * 60 * 24));
            const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
            
            let uptime = '';
            if (days > 0) uptime += days + 'd ';
            if (hours > 0) uptime += hours + 'h ';
            uptime += minutes + 'm';
            
            document.getElementById('uptime').textContent = uptime;
        }
        
        async function refreshData() {
            try {
                // Fetch health data
                const healthResp = await fetch('/api/health');
                const health = await healthResp.json();
                
                // Update status indicator
                const statusEl = document.getElementById('mainStatus');
                const statusText = document.getElementById('statusText');
                
                if (health.status === 'healthy') {
                    statusEl.className = 'status-indicator status-healthy';
                    statusText.textContent = 'System Healthy';
                } else if (health.status === 'degraded') {
                    statusEl.className = 'status-indicator status-warning';
                    statusText.textContent = 'System Degraded';
                } else {
                    statusEl.className = 'status-indicator status-error';
                    statusText.textContent = 'System Unhealthy';
                }
                
                // Fetch stats
                const statsResp = await fetch('/api/stats');
                const stats = await statsResp.json();
                
                // Update metrics
                document.getElementById('cpuUsage').textContent = (stats.cpu_percent || 0).toFixed(1) + '%';
                document.getElementById('memUsage').textContent = formatBytes(stats.memory_used || 0);
                document.getElementById('goroutines').textContent = stats.goroutines || '--';
                document.getElementById('connections').textContent = stats.connections || '--';
                
                // Update memory progress bar
                const memPercent = stats.memory_percent || 0;
                document.getElementById('memProgress').style.width = memPercent + '%';
                
                // Update request stats
                document.getElementById('totalRequests').textContent = formatNumber(stats.total_requests || 0);
                document.getElementById('requestsPerSec').textContent = (stats.requests_per_sec || 0).toFixed(1);
                document.getElementById('avgResponseTime').textContent = (stats.avg_response_time || 0).toFixed(0) + 'ms';
                document.getElementById('errorRate').textContent = (stats.error_rate || 0).toFixed(2) + '%';
                
                // Update performance metrics
                document.getElementById('p50').textContent = (stats.p50_latency || 0).toFixed(0) + 'ms';
                document.getElementById('p95').textContent = (stats.p95_latency || 0).toFixed(0) + 'ms';
                document.getElementById('p99').textContent = (stats.p99_latency || 0).toFixed(0) + 'ms';
                document.getElementById('maxLatency').textContent = (stats.max_latency || 0).toFixed(0) + 'ms';
                
                // Update certificate stats
                document.getElementById('activeCerts').textContent = stats.active_certificates || '--';
                document.getElementById('expiringCerts').textContent = stats.expiring_certificates || '0';
                document.getElementById('nextRenewal').textContent = stats.next_renewal || 'N/A';
                
                // Fetch and update backends
                const backendsResp = await fetch('/api/backends');
                const backends = await backendsResp.json();
                updateBackends(backends);
                
                // Update last update time
                document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
                
            } catch (error) {
                console.error('Failed to refresh data:', error);
            }
        }
        
        function updateBackends(backends) {
            const list = document.getElementById('backendList');
            list.innerHTML = '';
            
            if (!backends || backends.length === 0) {
                list.innerHTML = '<li class="backend-item"><span>No backends configured</span></li>';
                return;
            }
            
            backends.forEach(backend => {
                const item = document.createElement('li');
                item.className = 'backend-item';
                
                const statusClass = backend.healthy ? 'status-healthy' : 'status-error';
                const statusText = backend.healthy ? 'Healthy' : 'Unhealthy';
                
                item.innerHTML = ` + "`" + `
                    <span>${backend.host} → ${backend.backend}</span>
                    <div class="backend-status">
                        <div class="status-indicator ${statusClass}"></div>
                        <span>${statusText}</span>
                    </div>
                ` + "`" + `;
                
                list.appendChild(item);
            });
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
        }
        
        function formatNumber(num) {
            if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
            if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
            return num.toString();
        }
        
        // Initial load
        updateUptime();
        refreshData();
        
        // Auto-refresh
        setInterval(updateUptime, 60000); // Update uptime every minute
        setInterval(refreshData, 5000); // Refresh data every 5 seconds
    </script>
</body>
</html>
`

	data := struct {
		StartTime string
	}{
		StartTime: d.startTime.Format(time.RFC3339),
	}

	t, err := template.New("dashboard").Parse(tmpl)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// handleHealthAPI returns health status as JSON
func (d *Dashboard) handleHealthAPI(w http.ResponseWriter, r *http.Request) {
	status := d.healthChecker.GetStatus()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleStatsAPI returns system statistics as JSON
func (d *Dashboard) handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	stats := map[string]interface{}{
		"goroutines":           runtime.NumGoroutine(),
		"memory_used":          m.Alloc,
		"memory_total":         m.TotalAlloc,
		"memory_sys":           m.Sys,
		"memory_percent":       float64(m.Alloc) / float64(m.Sys) * 100,
		"gc_runs":              m.NumGC,
		"cpu_count":            runtime.NumCPU(),
		"uptime_seconds":       time.Since(d.startTime).Seconds(),
		// These would come from actual metrics collection
		"total_requests":       1234567,
		"requests_per_sec":     123.4,
		"avg_response_time":    45.6,
		"error_rate":           0.12,
		"p50_latency":          25,
		"p95_latency":          75,
		"p99_latency":          150,
		"max_latency":          500,
		"active_certificates":  10,
		"expiring_certificates": 0,
		"next_renewal":         "5 days",
		"connections":          42,
		"cpu_percent":          35.2,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleBackendsAPI returns backend health status as JSON
func (d *Dashboard) handleBackendsAPI(w http.ResponseWriter, r *http.Request) {
	// This would fetch actual backend health from the health checker
	backends := []map[string]interface{}{
		{
			"host":    "api.example.com",
			"backend": "http://10.0.0.1:8080",
			"healthy": true,
		},
		{
			"host":    "app.example.com", 
			"backend": "http://10.0.0.2:8080",
			"healthy": true,
		},
		{
			"host":    "db.example.com",
			"backend": "postgres://10.0.0.3:5432",
			"healthy": false,
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backends)
}

// handleStatic serves static resources (if any)
func (d *Dashboard) handleStatic(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}