package acme

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/artyom/leproxy/internal/logger"
)

// DashboardHandler provides HTTP endpoints for certificate monitoring
type DashboardHandler struct {
	manager *Manager
}

// NewDashboardHandler creates a new dashboard handler
func NewDashboardHandler(manager *Manager) *DashboardHandler {
	return &DashboardHandler{
		manager: manager,
	}
}

// RegisterHandlers registers the dashboard HTTP handlers
func (dh *DashboardHandler) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/certificates", dh.handleCertificateList)
	mux.HandleFunc("/certificates/status", dh.handleCertificateStatus)
	mux.HandleFunc("/certificates/history", dh.handleRenewalHistory)
	mux.HandleFunc("/certificates/dashboard", dh.handleDashboard)
	mux.HandleFunc("/api/certificates", dh.handleAPICertificates)
	mux.HandleFunc("/api/certificates/renew", dh.handleAPIRenew)
}

// Certificate information for dashboard
type CertificateInfo struct {
	Domain          string    `json:"domain"`
	Status          string    `json:"status"`
	ExpiryDate      time.Time `json:"expiry_date"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	LastRenewal     time.Time `json:"last_renewal,omitempty"`
	NextRenewal     time.Time `json:"next_renewal,omitempty"`
	RenewalAttempts int       `json:"renewal_attempts"`
	Error           string    `json:"error,omitempty"`
	Severity        string    `json:"severity"`
}

// handleCertificateList returns a JSON list of all certificates
func (dh *DashboardHandler) handleCertificateList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	statuses := dh.manager.GetRenewalStatus()
	certificates := make([]CertificateInfo, 0, len(statuses))
	
	for domain, status := range statuses {
		info := CertificateInfo{
			Domain:          domain,
			Status:          status.Status,
			ExpiryDate:      status.ExpiryDate,
			RenewalAttempts: status.Attempts,
			Error:           status.Error,
		}
		
		if !status.ExpiryDate.IsZero() {
			info.DaysUntilExpiry = int(time.Until(status.ExpiryDate).Hours() / 24)
			info.Severity = dh.determineSeverity(info.DaysUntilExpiry)
		}
		
		if !status.RenewedAt.IsZero() {
			info.LastRenewal = status.RenewedAt
		}
		
		if !status.NextAttempt.IsZero() {
			info.NextRenewal = status.NextAttempt
		}
		
		certificates = append(certificates, info)
	}
	
	// Sort by days until expiry (most urgent first)
	sort.Slice(certificates, func(i, j int) bool {
		return certificates[i].DaysUntilExpiry < certificates[j].DaysUntilExpiry
	})
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certificates)
}

// handleCertificateStatus returns detailed status for a specific certificate
func (dh *DashboardHandler) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain parameter required", http.StatusBadRequest)
		return
	}
	
	statuses := dh.manager.GetRenewalStatus()
	status, exists := statuses[domain]
	if !exists {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleRenewalHistory returns the renewal history
func (dh *DashboardHandler) handleRenewalHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	history := dh.manager.GetRenewalHistory()
	
	// Filter by domain if specified
	domain := r.URL.Query().Get("domain")
	if domain != "" {
		filtered := make([]RenewalHistory, 0)
		for _, h := range history {
			if h.Domain == domain {
				filtered = append(filtered, h)
			}
		}
		history = filtered
	}
	
	// Sort by timestamp (most recent first)
	sort.Slice(history, func(i, j int) bool {
		return history[i].Timestamp.After(history[j].Timestamp)
	})
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

// handleDashboard serves an HTML dashboard
func (dh *DashboardHandler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	
	data := struct {
		Title string
		Time  string
	}{
		Title: "Certificate Management Dashboard",
		Time:  time.Now().Format(time.RFC3339),
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

// handleAPICertificates provides REST API for certificates
func (dh *DashboardHandler) handleAPICertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dh.handleCertificateList(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIRenew triggers manual renewal for a domain
func (dh *DashboardHandler) handleAPIRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Domain string `json:"domain"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	if req.Domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}
	
	// Trigger renewal
	go func() {
		logger.Info("Manual renewal triggered", "domain", req.Domain)
		dh.manager.renewalManager.checkAndRenewCertificate(r.Context(), req.Domain)
	}()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "renewal_initiated",
		"domain":  req.Domain,
		"message": "Certificate renewal has been initiated",
	})
}

// determineSeverity determines the severity based on days until expiry
func (dh *DashboardHandler) determineSeverity(daysUntilExpiry int) string {
	if daysUntilExpiry <= 3 {
		return "critical"
	} else if daysUntilExpiry <= 7 {
		return "warning"
	} else if daysUntilExpiry <= 30 {
		return "info"
	}
	return "ok"
}

// Dashboard HTML template
const dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #666;
            font-size: 14px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        
        .stat-card .label {
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }
        
        .certificate-table {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        
        .certificate-table h2 {
            color: #333;
            margin-bottom: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            text-align: left;
            padding: 12px;
            border-bottom: 2px solid #e0e0e0;
            color: #666;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #f0f0f0;
            color: #333;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-valid { background: #d4edda; color: #155724; }
        .status-warning { background: #fff3cd; color: #856404; }
        .status-critical { background: #f8d7da; color: #721c24; }
        .status-renewing { background: #d1ecf1; color: #0c5460; }
        .status-failed { background: #f8d7da; color: #721c24; }
        
        .action-button {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: background 0.3s;
        }
        
        .action-button:hover {
            background: #5a67d8;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 {{.Title}}</h1>
            <div class="subtitle">Last updated: <span id="lastUpdate">{{.Time}}</span></div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Certificates</div>
                <div class="value" id="totalCerts">-</div>
            </div>
            <div class="stat-card">
                <div class="label">Expiring Soon</div>
                <div class="value" id="expiringSoon">-</div>
            </div>
            <div class="stat-card">
                <div class="label">Critical</div>
                <div class="value" id="criticalCerts">-</div>
            </div>
            <div class="stat-card">
                <div class="label">Average Days to Expiry</div>
                <div class="value" id="avgExpiry">-</div>
            </div>
        </div>
        
        <div class="certificate-table">
            <h2>Certificate Status</h2>
            <div id="errorMessage" class="error" style="display: none;"></div>
            <div id="loading" class="loading">Loading certificates...</div>
            <table id="certTable" style="display: none;">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Status</th>
                        <th>Expiry Date</th>
                        <th>Days Until Expiry</th>
                        <th>Last Renewal</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="certTableBody">
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        async function loadCertificates() {
            try {
                const response = await fetch('/certificates');
                if (!response.ok) {
                    throw new Error('Failed to load certificates');
                }
                
                const certificates = await response.json();
                displayCertificates(certificates);
                updateStats(certificates);
                
                document.getElementById('loading').style.display = 'none';
                document.getElementById('certTable').style.display = 'table';
                document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('errorMessage').textContent = 'Error loading certificates: ' + error.message;
                document.getElementById('errorMessage').style.display = 'block';
            }
        }
        
        function displayCertificates(certificates) {
            const tbody = document.getElementById('certTableBody');
            tbody.innerHTML = '';
            
            certificates.forEach(cert => {
                const row = tbody.insertRow();
                
                row.insertCell(0).textContent = cert.domain;
                
                const statusCell = row.insertCell(1);
                const statusBadge = document.createElement('span');
                statusBadge.className = 'status-badge status-' + getStatusClass(cert);
                statusBadge.textContent = cert.status || 'Unknown';
                statusCell.appendChild(statusBadge);
                
                row.insertCell(2).textContent = cert.expiry_date ? new Date(cert.expiry_date).toLocaleDateString() : '-';
                
                const daysCell = row.insertCell(3);
                if (cert.days_until_expiry !== undefined) {
                    daysCell.textContent = cert.days_until_expiry + ' days';
                    if (cert.days_until_expiry <= 7) {
                        daysCell.style.color = '#dc3545';
                        daysCell.style.fontWeight = 'bold';
                    } else if (cert.days_until_expiry <= 30) {
                        daysCell.style.color = '#ffc107';
                    }
                } else {
                    daysCell.textContent = '-';
                }
                
                row.insertCell(4).textContent = cert.last_renewal ? new Date(cert.last_renewal).toLocaleDateString() : '-';
                
                const actionCell = row.insertCell(5);
                const renewButton = document.createElement('button');
                renewButton.className = 'action-button';
                renewButton.textContent = 'Renew';
                renewButton.onclick = () => renewCertificate(cert.domain);
                actionCell.appendChild(renewButton);
            });
        }
        
        function updateStats(certificates) {
            document.getElementById('totalCerts').textContent = certificates.length;
            
            const expiringSoon = certificates.filter(c => c.days_until_expiry <= 30).length;
            document.getElementById('expiringSoon').textContent = expiringSoon;
            
            const critical = certificates.filter(c => c.days_until_expiry <= 7).length;
            document.getElementById('criticalCerts').textContent = critical;
            
            const validCerts = certificates.filter(c => c.days_until_expiry !== undefined);
            if (validCerts.length > 0) {
                const avgDays = Math.round(validCerts.reduce((sum, c) => sum + c.days_until_expiry, 0) / validCerts.length);
                document.getElementById('avgExpiry').textContent = avgDays;
            } else {
                document.getElementById('avgExpiry').textContent = '-';
            }
        }
        
        function getStatusClass(cert) {
            if (cert.status === 'failed') return 'failed';
            if (cert.status === 'in_progress') return 'renewing';
            if (cert.days_until_expiry <= 3) return 'critical';
            if (cert.days_until_expiry <= 7) return 'warning';
            return 'valid';
        }
        
        async function renewCertificate(domain) {
            if (!confirm('Renew certificate for ' + domain + '?')) {
                return;
            }
            
            try {
                const response = await fetch('/api/certificates/renew', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ domain: domain }),
                });
                
                if (!response.ok) {
                    throw new Error('Failed to initiate renewal');
                }
                
                const result = await response.json();
                alert(result.message);
                
                // Reload certificates after a delay
                setTimeout(loadCertificates, 2000);
            } catch (error) {
                alert('Error initiating renewal: ' + error.message);
            }
        }
        
        // Load certificates on page load
        loadCertificates();
        
        // Refresh every 30 seconds
        setInterval(loadCertificates, 30000);
    </script>
</body>
</html>
`