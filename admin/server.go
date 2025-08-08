package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type ConfigManager struct {
	mu              sync.RWMutex
	httpMappingFile string
	dbMappingFile   string
}

type HTTPMapping map[string]string

type DBProxyEntry struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	Type        string `json:"type"`
	BackendHost string `json:"backend_host"`
	BackendPort string `json:"backend_port"`
	TLS         bool   `json:"tls"`
}

func NewConfigManager(httpMappingFile, dbMappingFile string) *ConfigManager {
	return &ConfigManager{
		httpMappingFile: httpMappingFile,
		dbMappingFile:   dbMappingFile,
	}
}

func (cm *ConfigManager) LoadHTTPMappings() (HTTPMapping, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.httpMappingFile == "" {
		return make(HTTPMapping), nil
	}

	data, err := ioutil.ReadFile(cm.httpMappingFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(HTTPMapping), nil
		}
		return nil, err
	}

	mappings := make(HTTPMapping)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			host := strings.TrimSpace(parts[0])
			backend := strings.TrimSpace(parts[1])
			mappings[host] = backend
		}
	}

	return mappings, nil
}

func (cm *ConfigManager) SaveHTTPMappings(mappings HTTPMapping) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.httpMappingFile == "" {
		return fmt.Errorf("no HTTP mapping file configured")
	}

	var lines []string
	lines = append(lines, "# HTTP/HTTPS proxy mappings")
	lines = append(lines, "# Format: hostname: backend")
	lines = append(lines, "")
	
	for host, backend := range mappings {
		lines = append(lines, fmt.Sprintf("%s: %s", host, backend))
	}

	content := strings.Join(lines, "\n")
	return ioutil.WriteFile(cm.httpMappingFile, []byte(content), 0644)
}

func (cm *ConfigManager) LoadDBProxies() ([]DBProxyEntry, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.dbMappingFile == "" {
		return []DBProxyEntry{}, nil
	}

	data, err := ioutil.ReadFile(cm.dbMappingFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []DBProxyEntry{}, nil
		}
		return nil, err
	}

	var entries []DBProxyEntry
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 5 {
			continue
		}

		entry := DBProxyEntry{
			Host:        parts[0],
			Port:        parts[1],
			Type:        parts[2],
			BackendHost: parts[3],
			BackendPort: parts[4],
			TLS:         len(parts) > 5 && parts[5] == "tls",
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func (cm *ConfigManager) SaveDBProxies(entries []DBProxyEntry) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.dbMappingFile == "" {
		return fmt.Errorf("no database mapping file configured")
	}

	var lines []string
	lines = append(lines, "# Database/Service proxy configuration")
	lines = append(lines, "# Format: host:port:type:backend_host:backend_port[:tls]")
	lines = append(lines, "")

	for _, entry := range entries {
		line := fmt.Sprintf("%s:%s:%s:%s:%s", 
			entry.Host, entry.Port, entry.Type, 
			entry.BackendHost, entry.BackendPort)
		if entry.TLS {
			line += ":tls"
		}
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	return ioutil.WriteFile(cm.dbMappingFile, []byte(content), 0644)
}

func (cm *ConfigManager) HTTPMappingsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mappings, err := cm.LoadHTTPMappings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mappings)

	case http.MethodPost:
		var mappings HTTPMapping
		if err := json.NewDecoder(r.Body).Decode(&mappings); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := cm.SaveHTTPMappings(mappings); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cm *ConfigManager) DBProxiesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		proxies, err := cm.LoadDBProxies()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxies)

	case http.MethodPost:
		var proxies []DBProxyEntry
		if err := json.NewDecoder(r.Body).Decode(&proxies); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := cm.SaveDBProxies(proxies); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func basicAuth(handler http.HandlerFunc, username, password string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username != "" && password != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != username || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="LeProxy Admin"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		handler(w, r)
	}
}

func main() {
	httpMappingFile := os.Getenv("LEPROXY_HTTP_CONFIG")
	if httpMappingFile == "" {
		httpMappingFile = "mapping.yml"
	}

	dbMappingFile := os.Getenv("LEPROXY_DB_CONFIG")
	if dbMappingFile == "" {
		dbMappingFile = "dbproxy_config.yml"
	}

	if !filepath.IsAbs(httpMappingFile) {
		cwd, _ := os.Getwd()
		httpMappingFile = filepath.Join(cwd, httpMappingFile)
	}

	if !filepath.IsAbs(dbMappingFile) {
		cwd, _ := os.Getwd()
		dbMappingFile = filepath.Join(cwd, dbMappingFile)
	}

	adminUser := os.Getenv("LEPROXY_ADMIN_USER")
	adminPass := os.Getenv("LEPROXY_ADMIN_PASS")

	cm := NewConfigManager(httpMappingFile, dbMappingFile)

	mux := http.NewServeMux()
	
	mux.HandleFunc("/api/http-mappings", basicAuth(cm.HTTPMappingsHandler, adminUser, adminPass))
	mux.HandleFunc("/api/db-proxies", basicAuth(cm.DBProxiesHandler, adminUser, adminPass))
	
	mux.HandleFunc("/", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(indexHTML))
			return
		}
		http.NotFound(w, r)
	}, adminUser, adminPass))

	port := ":8090"
	log.Printf("LeProxy Admin Server starting on http://localhost%s", port)
	log.Printf("HTTP Mapping File: %s", httpMappingFile)
	log.Printf("DB Mapping File: %s", dbMappingFile)
	
	if adminUser != "" && adminPass != "" {
		log.Printf("Basic authentication enabled (user: %s)", adminUser)
	} else {
		log.Printf("WARNING: Running without authentication. Set LEPROXY_ADMIN_USER and LEPROXY_ADMIN_PASS for security.")
	}
	
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatal(err)
	}
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LeProxy Admin</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        h1 {
            color: white;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 12px 24px;
            background: white;
            border: none;
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: #4c51bf;
            color: white;
        }
        
        .tab:hover:not(.active) {
            background: #e2e8f0;
        }
        
        .panel {
            background: white;
            border-radius: 0 8px 8px 8px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            display: none;
        }
        
        .panel.active {
            display: block;
        }
        
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: #2d3748;
        }
        
        .mapping-grid {
            display: grid;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .mapping-item {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: 10px;
            align-items: center;
            padding: 15px;
            background: #f7fafc;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }
        
        .db-proxy-item {
            display: grid;
            grid-template-columns: repeat(6, 1fr) auto;
            gap: 10px;
            align-items: center;
            padding: 15px;
            background: #f7fafc;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }
        
        input[type="text"], select {
            padding: 10px;
            border: 1px solid #cbd5e0;
            border-radius: 4px;
            font-size: 14px;
            width: 100%;
        }
        
        input[type="checkbox"] {
            width: 20px;
            height: 20px;
            cursor: pointer;
        }
        
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: #4c51bf;
            color: white;
        }
        
        .btn-primary:hover {
            background: #434190;
        }
        
        .btn-success {
            background: #48bb78;
            color: white;
        }
        
        .btn-success:hover {
            background: #38a169;
        }
        
        .btn-danger {
            background: #f56565;
            color: white;
        }
        
        .btn-danger:hover {
            background: #e53e3e;
        }
        
        .btn-add {
            background: #667eea;
            color: white;
            margin-bottom: 20px;
        }
        
        .btn-add:hover {
            background: #5a67d8;
        }
        
        .actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
            margin-top: 20px;
        }
        
        .status {
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            display: none;
        }
        
        .status.success {
            background: #c6f6d5;
            color: #22543d;
            border: 1px solid #9ae6b4;
        }
        
        .status.error {
            background: #fed7d7;
            color: #742a2a;
            border: 1px solid #fc8181;
        }
        
        .label {
            font-size: 12px;
            font-weight: 600;
            color: #4a5568;
            margin-bottom: 5px;
            text-transform: uppercase;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 LeProxy Admin</h1>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('http')">HTTP Mappings</button>
            <button class="tab" onclick="switchTab('db')">Database Proxies</button>
        </div>
        
        <div id="http-panel" class="panel active">
            <h2 class="section-title">HTTP/HTTPS Proxy Mappings</h2>
            <button class="btn-add" onclick="addHTTPMapping()">+ Add Mapping</button>
            <div id="http-mappings" class="mapping-grid"></div>
            <div class="actions">
                <button class="btn-success" onclick="saveHTTPMappings()">Save Changes</button>
                <button class="btn-primary" onclick="loadHTTPMappings()">Reload</button>
            </div>
            <div id="http-status" class="status"></div>
        </div>
        
        <div id="db-panel" class="panel">
            <h2 class="section-title">Database & Service Proxies</h2>
            <button class="btn-add" onclick="addDBProxy()">+ Add Proxy</button>
            <div id="db-proxies" class="mapping-grid"></div>
            <div class="actions">
                <button class="btn-success" onclick="saveDBProxies()">Save Changes</button>
                <button class="btn-primary" onclick="loadDBProxies()">Reload</button>
            </div>
            <div id="db-status" class="status"></div>
        </div>
    </div>
    
    <script>
        let httpMappings = {};
        let dbProxies = [];
        
        const serviceTypes = [
            'postgres', 'mysql', 'mongodb', 'redis', 'mssql',
            'ldap', 'smtp', 'ftp', 'elasticsearch', 'amqp',
            'kafka', 'cassandra', 'memcached'
        ];
        
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            
            if (tab === 'http') {
                document.querySelector('.tab:nth-child(1)').classList.add('active');
                document.getElementById('http-panel').classList.add('active');
            } else {
                document.querySelector('.tab:nth-child(2)').classList.add('active');
                document.getElementById('db-panel').classList.add('active');
            }
        }
        
        function showStatus(type, message, isError = false) {
            const status = document.getElementById(type + '-status');
            status.textContent = message;
            status.className = 'status ' + (isError ? 'error' : 'success');
            status.style.display = 'block';
            setTimeout(() => {
                status.style.display = 'none';
            }, 3000);
        }
        
        function renderHTTPMappings() {
            const container = document.getElementById('http-mappings');
            container.innerHTML = '';
            
            Object.entries(httpMappings).forEach(([host, backend]) => {
                const item = document.createElement('div');
                item.className = 'mapping-item';
                item.innerHTML = \`
                    <div>
                        <div class="label">Hostname</div>
                        <input type="text" value="\${host}" data-original="\${host}" onchange="updateHTTPMapping(this, 'host')">
                    </div>
                    <div>
                        <div class="label">Backend</div>
                        <input type="text" value="\${backend}" onchange="updateHTTPMapping(this.parentElement.parentElement.querySelector('[data-original]'), 'backend', this.value)">
                    </div>
                    <button class="btn-danger" onclick="removeHTTPMapping('\${host}')">Remove</button>
                \`;
                container.appendChild(item);
            });
        }
        
        function renderDBProxies() {
            const container = document.getElementById('db-proxies');
            container.innerHTML = '';
            
            dbProxies.forEach((proxy, index) => {
                const item = document.createElement('div');
                item.className = 'db-proxy-item';
                item.innerHTML = \`
                    <div>
                        <div class="label">Listen Host</div>
                        <input type="text" value="\${proxy.host}" onchange="updateDBProxy(\${index}, 'host', this.value)">
                    </div>
                    <div>
                        <div class="label">Listen Port</div>
                        <input type="text" value="\${proxy.port}" onchange="updateDBProxy(\${index}, 'port', this.value)">
                    </div>
                    <div>
                        <div class="label">Service Type</div>
                        <select onchange="updateDBProxy(\${index}, 'type', this.value)">
                            \${serviceTypes.map(t => \`<option value="\${t}" \${proxy.type === t ? 'selected' : ''}>\${t}</option>\`).join('')}
                        </select>
                    </div>
                    <div>
                        <div class="label">Backend Host</div>
                        <input type="text" value="\${proxy.backend_host}" onchange="updateDBProxy(\${index}, 'backend_host', this.value)">
                    </div>
                    <div>
                        <div class="label">Backend Port</div>
                        <input type="text" value="\${proxy.backend_port}" onchange="updateDBProxy(\${index}, 'backend_port', this.value)">
                    </div>
                    <div style="text-align: center;">
                        <div class="label">TLS</div>
                        <input type="checkbox" \${proxy.tls ? 'checked' : ''} onchange="updateDBProxy(\${index}, 'tls', this.checked)">
                    </div>
                    <button class="btn-danger" onclick="removeDBProxy(\${index})">Remove</button>
                \`;
                container.appendChild(item);
            });
        }
        
        function addHTTPMapping() {
            const host = prompt('Enter hostname (e.g., api.example.com):');
            if (host) {
                httpMappings[host] = '127.0.0.1:8080';
                renderHTTPMappings();
            }
        }
        
        function updateHTTPMapping(input, field, value) {
            const originalHost = input.dataset.original;
            if (field === 'host') {
                const newHost = input.value;
                if (newHost !== originalHost) {
                    httpMappings[newHost] = httpMappings[originalHost];
                    delete httpMappings[originalHost];
                    input.dataset.original = newHost;
                }
            } else if (field === 'backend') {
                httpMappings[originalHost] = value;
            }
        }
        
        function removeHTTPMapping(host) {
            if (confirm(\`Remove mapping for \${host}?\`)) {
                delete httpMappings[host];
                renderHTTPMappings();
            }
        }
        
        function addDBProxy() {
            dbProxies.push({
                host: '0.0.0.0',
                port: '5432',
                type: 'postgres',
                backend_host: 'localhost',
                backend_port: '5432',
                tls: true
            });
            renderDBProxies();
        }
        
        function updateDBProxy(index, field, value) {
            dbProxies[index][field] = value;
        }
        
        function removeDBProxy(index) {
            if (confirm('Remove this proxy configuration?')) {
                dbProxies.splice(index, 1);
                renderDBProxies();
            }
        }
        
        async function loadHTTPMappings() {
            try {
                const response = await fetch('/api/http-mappings');
                httpMappings = await response.json();
                renderHTTPMappings();
                showStatus('http', 'HTTP mappings loaded successfully');
            } catch (error) {
                showStatus('http', 'Failed to load HTTP mappings: ' + error.message, true);
            }
        }
        
        async function saveHTTPMappings() {
            try {
                const response = await fetch('/api/http-mappings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(httpMappings)
                });
                if (response.ok) {
                    showStatus('http', 'HTTP mappings saved successfully');
                } else {
                    throw new Error('Failed to save');
                }
            } catch (error) {
                showStatus('http', 'Failed to save HTTP mappings: ' + error.message, true);
            }
        }
        
        async function loadDBProxies() {
            try {
                const response = await fetch('/api/db-proxies');
                dbProxies = await response.json();
                renderDBProxies();
                showStatus('db', 'Database proxies loaded successfully');
            } catch (error) {
                showStatus('db', 'Failed to load database proxies: ' + error.message, true);
            }
        }
        
        async function saveDBProxies() {
            try {
                const response = await fetch('/api/db-proxies', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(dbProxies)
                });
                if (response.ok) {
                    showStatus('db', 'Database proxies saved successfully');
                } else {
                    throw new Error('Failed to save');
                }
            } catch (error) {
                showStatus('db', 'Failed to save database proxies: ' + error.message, true);
            }
        }
        
        // Load initial data
        loadHTTPMappings();
        loadDBProxies();
    </script>
</body>
</html>
`