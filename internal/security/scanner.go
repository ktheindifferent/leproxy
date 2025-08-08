package security

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// VulnerabilityLevel represents the severity of a vulnerability
type VulnerabilityLevel string

const (
	VulnCritical VulnerabilityLevel = "CRITICAL"
	VulnHigh     VulnerabilityLevel = "HIGH"
	VulnMedium   VulnerabilityLevel = "MEDIUM"
	VulnLow      VulnerabilityLevel = "LOW"
	VulnInfo     VulnerabilityLevel = "INFO"
)

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string             `json:"id"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Severity    VulnerabilityLevel `json:"severity"`
	CVE         string             `json:"cve,omitempty"`
	CWE         string             `json:"cwe,omitempty"`
	CVSS        float64            `json:"cvss,omitempty"`
	Source      string             `json:"source"`
	FilePath    string             `json:"file_path,omitempty"`
	LineNumber  int                `json:"line_number,omitempty"`
	Remediation string             `json:"remediation"`
	References  []string           `json:"references,omitempty"`
	DetectedAt  time.Time          `json:"detected_at"`
}

// ScanResult represents the result of a security scan
type ScanResult struct {
	ScanID          string          `json:"scan_id"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         ScanSummary     `json:"summary"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ScanSummary provides a summary of scan results
type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Scanner performs security vulnerability scanning
type Scanner struct {
	patterns      map[string][]*Pattern
	cveDatabase   *CVEDatabase
	dependencyDB  *DependencyDatabase
	config        ScannerConfig
	mu            sync.RWMutex
	lastScan      *ScanResult
	scanHistory   []*ScanResult
}

// Pattern represents a vulnerability detection pattern
type Pattern struct {
	ID          string
	Name        string
	Description string
	Regex       *regexp.Regexp
	Severity    VulnerabilityLevel
	CWE         string
	Remediation string
	FileTypes   []string
}

// ScannerConfig holds scanner configuration
type ScannerConfig struct {
	Enabled             bool
	AutoScan            bool
	ScanInterval        time.Duration
	IncludePatterns     []string
	ExcludePatterns     []string
	MaxFileSize         int64
	CheckDependencies   bool
	CheckSecrets        bool
	CheckConfigs        bool
	CheckPermissions    bool
	ReportWebhook       string
	VulnerabilityDBPath string
}

// NewScanner creates a new security scanner
func NewScanner(cfg ScannerConfig) (*Scanner, error) {
	scanner := &Scanner{
		patterns:     make(map[string][]*Pattern),
		config:       cfg,
		scanHistory:  make([]*ScanResult, 0),
	}
	
	// Initialize vulnerability patterns
	scanner.initializePatterns()
	
	// Load CVE database if available
	if cfg.VulnerabilityDBPath != "" {
		scanner.cveDatabase = NewCVEDatabase(cfg.VulnerabilityDBPath)
	}
	
	// Initialize dependency scanner
	scanner.dependencyDB = NewDependencyDatabase()
	
	// Start auto-scan if enabled
	if cfg.AutoScan {
		go scanner.autoScanLoop()
	}
	
	return scanner, nil
}

// initializePatterns initializes built-in vulnerability patterns
func (s *Scanner) initializePatterns() {
	// Secret detection patterns
	s.addPattern("secrets", &Pattern{
		ID:          "SEC001",
		Name:        "Hardcoded API Key",
		Description: "Potential API key found in source code",
		Regex:       regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']`),
		Severity:    VulnHigh,
		CWE:         "CWE-798",
		Remediation: "Use environment variables or secure key management systems",
		FileTypes:   []string{".go", ".js", ".py", ".java", ".yml", ".yaml", ".json"},
	})
	
	s.addPattern("secrets", &Pattern{
		ID:          "SEC002",
		Name:        "Hardcoded Password",
		Description: "Potential password found in source code",
		Regex:       regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']`),
		Severity:    VulnCritical,
		CWE:         "CWE-259",
		Remediation: "Never hardcode passwords. Use secure credential storage",
		FileTypes:   []string{".go", ".js", ".py", ".java", ".yml", ".yaml", ".json", ".xml"},
	})
	
	s.addPattern("secrets", &Pattern{
		ID:          "SEC003",
		Name:        "Private Key",
		Description: "Private key material detected",
		Regex:       regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
		Severity:    VulnCritical,
		CWE:         "CWE-312",
		Remediation: "Store private keys securely and never commit to version control",
		FileTypes:   []string{"*"},
	})
	
	// SQL Injection patterns
	s.addPattern("injection", &Pattern{
		ID:          "INJ001",
		Name:        "SQL Injection Risk",
		Description: "Potential SQL injection vulnerability",
		Regex:       regexp.MustCompile(`(?i)(query|execute)\s*\(\s*["'].*\+.*["']`),
		Severity:    VulnHigh,
		CWE:         "CWE-89",
		Remediation: "Use parameterized queries or prepared statements",
		FileTypes:   []string{".go", ".js", ".py", ".java", ".php"},
	})
	
	// Insecure configuration patterns
	s.addPattern("config", &Pattern{
		ID:          "CFG001",
		Name:        "Insecure TLS Configuration",
		Description: "InsecureSkipVerify is enabled",
		Regex:       regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`),
		Severity:    VulnMedium,
		CWE:         "CWE-295",
		Remediation: "Properly validate TLS certificates",
		FileTypes:   []string{".go"},
	})
	
	s.addPattern("config", &Pattern{
		ID:          "CFG002",
		Name:        "Weak Cryptography",
		Description: "Use of weak cryptographic algorithm",
		Regex:       regexp.MustCompile(`(?i)(md5|sha1|des|rc4)\.`),
		Severity:    VulnMedium,
		CWE:         "CWE-327",
		Remediation: "Use strong cryptographic algorithms (SHA-256, AES-256)",
		FileTypes:   []string{".go", ".js", ".py", ".java"},
	})
	
	// Path traversal patterns
	s.addPattern("path", &Pattern{
		ID:          "PTH001",
		Name:        "Path Traversal Risk",
		Description: "Potential path traversal vulnerability",
		Regex:       regexp.MustCompile(`filepath\.Join\([^,]+,\s*[a-zA-Z_]+`),
		Severity:    VulnMedium,
		CWE:         "CWE-22",
		Remediation: "Validate and sanitize file paths",
		FileTypes:   []string{".go"},
	})
}

// addPattern adds a pattern to the scanner
func (s *Scanner) addPattern(category string, pattern *Pattern) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.patterns[category] = append(s.patterns[category], pattern)
}

// Scan performs a security scan on the specified path
func (s *Scanner) Scan(ctx context.Context, path string) (*ScanResult, error) {
	scanID := generateScanID()
	result := &ScanResult{
		ScanID:          scanID,
		StartTime:       time.Now(),
		Vulnerabilities: make([]Vulnerability, 0),
		Metadata:        make(map[string]interface{}),
	}
	
	// Scan files
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}
		
		// Skip if cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Skip directories and large files
		if info.IsDir() || info.Size() > s.config.MaxFileSize {
			return nil
		}
		
		// Check if file should be scanned
		if !s.shouldScanFile(filePath) {
			return nil
		}
		
		// Scan file for vulnerabilities
		vulns, err := s.scanFile(ctx, filePath)
		if err != nil {
			// Log error but continue
			return nil
		}
		
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		return nil
	})
	
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	
	// Check dependencies if enabled
	if s.config.CheckDependencies {
		depVulns := s.scanDependencies(ctx, path)
		result.Vulnerabilities = append(result.Vulnerabilities, depVulns...)
	}
	
	// Calculate summary
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Summary = s.calculateSummary(result.Vulnerabilities)
	
	// Store scan result
	s.mu.Lock()
	s.lastScan = result
	s.scanHistory = append(s.scanHistory, result)
	if len(s.scanHistory) > 100 {
		s.scanHistory = s.scanHistory[1:]
	}
	s.mu.Unlock()
	
	// Send webhook notification if configured
	if s.config.ReportWebhook != "" && len(result.Vulnerabilities) > 0 {
		go s.sendWebhookNotification(result)
	}
	
	return result, nil
}

// scanFile scans a single file for vulnerabilities
func (s *Scanner) scanFile(ctx context.Context, filePath string) ([]Vulnerability, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	vulnerabilities := make([]Vulnerability, 0)
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		
		// Check each pattern category
		for category, patterns := range s.patterns {
			for _, pattern := range patterns {
				// Check if pattern applies to this file type
				if !s.matchesFileType(filePath, pattern.FileTypes) {
					continue
				}
				
				// Check if pattern matches
				if pattern.Regex.MatchString(line) {
					vuln := Vulnerability{
						ID:          pattern.ID,
						Title:       pattern.Name,
						Description: pattern.Description,
						Severity:    pattern.Severity,
						CWE:         pattern.CWE,
						Source:      category,
						FilePath:    filePath,
						LineNumber:  lineNumber,
						Remediation: pattern.Remediation,
						DetectedAt:  time.Now(),
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}
	
	return vulnerabilities, scanner.Err()
}

// scanDependencies scans for vulnerable dependencies
func (s *Scanner) scanDependencies(ctx context.Context, path string) []Vulnerability {
	vulnerabilities := make([]Vulnerability, 0)
	
	// Check Go modules
	goModPath := filepath.Join(path, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		vulns := s.scanGoModules(goModPath)
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	// Check package.json for Node.js
	packageJSONPath := filepath.Join(path, "package.json")
	if _, err := os.Stat(packageJSONPath); err == nil {
		vulns := s.scanNodeModules(packageJSONPath)
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	return vulnerabilities
}

// shouldScanFile checks if a file should be scanned
func (s *Scanner) shouldScanFile(filePath string) bool {
	// Check exclude patterns
	for _, pattern := range s.config.ExcludePatterns {
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return false
		}
	}
	
	// Check include patterns if specified
	if len(s.config.IncludePatterns) > 0 {
		for _, pattern := range s.config.IncludePatterns {
			if matched, _ := filepath.Match(pattern, filePath); matched {
				return true
			}
		}
		return false
	}
	
	return true
}

// matchesFileType checks if a file matches the specified types
func (s *Scanner) matchesFileType(filePath string, fileTypes []string) bool {
	if len(fileTypes) == 0 {
		return true
	}
	
	for _, ft := range fileTypes {
		if ft == "*" {
			return true
		}
		if strings.HasSuffix(filePath, ft) {
			return true
		}
	}
	
	return false
}

// calculateSummary calculates the summary of vulnerabilities
func (s *Scanner) calculateSummary(vulnerabilities []Vulnerability) ScanSummary {
	summary := ScanSummary{
		Total: len(vulnerabilities),
	}
	
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case VulnCritical:
			summary.Critical++
		case VulnHigh:
			summary.High++
		case VulnMedium:
			summary.Medium++
		case VulnLow:
			summary.Low++
		case VulnInfo:
			summary.Info++
		}
	}
	
	return summary
}

// autoScanLoop performs automatic periodic scans
func (s *Scanner) autoScanLoop() {
	ticker := time.NewTicker(s.config.ScanInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		s.Scan(ctx, ".")
		cancel()
	}
}

// sendWebhookNotification sends scan results to configured webhook
func (s *Scanner) sendWebhookNotification(result *ScanResult) {
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	
	resp, err := http.Post(s.config.ReportWebhook, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// GetLastScan returns the last scan result
func (s *Scanner) GetLastScan() *ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastScan
}

// GetScanHistory returns scan history
func (s *Scanner) GetScanHistory() []*ScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*ScanResult{}, s.scanHistory...)
}

// Helper types and functions

// CVEDatabase manages CVE vulnerability data
type CVEDatabase struct {
	data map[string]*CVEEntry
	mu   sync.RWMutex
}

type CVEEntry struct {
	ID          string
	Description string
	CVSS        float64
	Severity    VulnerabilityLevel
	References  []string
}

func NewCVEDatabase(path string) *CVEDatabase {
	return &CVEDatabase{
		data: make(map[string]*CVEEntry),
	}
}

// DependencyDatabase manages dependency vulnerability data
type DependencyDatabase struct {
	vulnerabilities map[string][]DependencyVuln
	mu              sync.RWMutex
}

type DependencyVuln struct {
	Package     string
	Version     string
	Vulnerability Vulnerability
}

func NewDependencyDatabase() *DependencyDatabase {
	return &DependencyDatabase{
		vulnerabilities: make(map[string][]DependencyVuln),
	}
}

func (s *Scanner) scanGoModules(goModPath string) []Vulnerability {
	// This would integrate with Go vulnerability database
	// For now, return empty
	return []Vulnerability{}
}

func (s *Scanner) scanNodeModules(packageJSONPath string) []Vulnerability {
	// This would integrate with npm audit or similar
	// For now, return empty
	return []Vulnerability{}
}

func generateScanID() string {
	h := sha256.New()
	h.Write([]byte(time.Now().String()))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Report generates a security report
func (s *Scanner) GenerateReport(format string) ([]byte, error) {
	s.mu.RLock()
	lastScan := s.lastScan
	s.mu.RUnlock()
	
	if lastScan == nil {
		return nil, fmt.Errorf("no scan results available")
	}
	
	switch format {
	case "json":
		return json.MarshalIndent(lastScan, "", "  ")
	case "html":
		return s.generateHTMLReport(lastScan)
	case "markdown":
		return s.generateMarkdownReport(lastScan)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func (s *Scanner) generateHTMLReport(result *ScanResult) ([]byte, error) {
	// Generate HTML report
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
        .info { color: #1976d2; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Scan ID: %s</p>
    <p>Date: %s</p>
    <h2>Summary</h2>
    <ul>
        <li>Total: %d</li>
        <li class="critical">Critical: %d</li>
        <li class="high">High: %d</li>
        <li class="medium">Medium: %d</li>
        <li class="low">Low: %d</li>
        <li class="info">Info: %d</li>
    </ul>
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Title</th>
            <th>File</th>
            <th>Line</th>
        </tr>`,
		result.ScanID,
		result.StartTime.Format(time.RFC3339),
		result.Summary.Total,
		result.Summary.Critical,
		result.Summary.High,
		result.Summary.Medium,
		result.Summary.Low,
		result.Summary.Info,
	)
	
	for _, vuln := range result.Vulnerabilities {
		html += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td class="%s">%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%d</td>
        </tr>`,
			vuln.ID,
			strings.ToLower(string(vuln.Severity)),
			vuln.Severity,
			vuln.Title,
			vuln.FilePath,
			vuln.LineNumber,
		)
	}
	
	html += `
    </table>
</body>
</html>`
	
	return []byte(html), nil
}

func (s *Scanner) generateMarkdownReport(result *ScanResult) ([]byte, error) {
	var sb strings.Builder
	
	sb.WriteString("# Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Scan ID:** %s\n", result.ScanID))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", result.StartTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", result.Duration))
	
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total:** %d\n", result.Summary.Total))
	sb.WriteString(fmt.Sprintf("- **Critical:** %d\n", result.Summary.Critical))
	sb.WriteString(fmt.Sprintf("- **High:** %d\n", result.Summary.High))
	sb.WriteString(fmt.Sprintf("- **Medium:** %d\n", result.Summary.Medium))
	sb.WriteString(fmt.Sprintf("- **Low:** %d\n", result.Summary.Low))
	sb.WriteString(fmt.Sprintf("- **Info:** %d\n\n", result.Summary.Info))
	
	sb.WriteString("## Vulnerabilities\n\n")
	sb.WriteString("| ID | Severity | Title | File | Line | Remediation |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	
	for _, vuln := range result.Vulnerabilities {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d | %s |\n",
			vuln.ID,
			vuln.Severity,
			vuln.Title,
			vuln.FilePath,
			vuln.LineNumber,
			vuln.Remediation,
		))
	}
	
	return []byte(sb.String()), nil
}