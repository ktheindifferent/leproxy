package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/artyom/leproxy/internal/logger"
)

// AlertConfig configures the alerting system
type AlertConfig struct {
	// Email alerting
	EmailEnabled bool
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPass     string
	EmailFrom    string
	EmailTo      []string
	
	// Webhook alerting
	WebhookEnabled bool
	WebhookURL     string
	WebhookMethod  string // POST, PUT
	WebhookHeaders map[string]string
	
	// Slack alerting
	SlackEnabled    bool
	SlackWebhookURL string
	SlackChannel    string
	SlackUsername   string
	
	// Alert thresholds
	MaxFailuresBeforeAlert int           // Number of failures before alerting
	AlertCooldown          time.Duration // Minimum time between alerts for same domain
	
	// Alert severity levels
	WarnDaysBeforeExpiry    int // Days before expiry to send warning
	CriticalDaysBeforeExpiry int // Days before expiry to send critical alert
}

// AlertManager handles sending alerts for certificate renewal issues
type AlertManager struct {
	config      *AlertConfig
	mu          sync.RWMutex
	lastAlerts  map[string]time.Time // Track last alert time per domain
	alertCounts map[string]int       // Track alert count per domain
}

// NewAlertManager creates a new alert manager
func NewAlertManager(config *AlertConfig) *AlertManager {
	if config == nil {
		config = &AlertConfig{
			MaxFailuresBeforeAlert:   3,
			AlertCooldown:            1 * time.Hour,
			WarnDaysBeforeExpiry:     7,
			CriticalDaysBeforeExpiry: 3,
		}
	}
	
	return &AlertManager{
		config:      config,
		lastAlerts:  make(map[string]time.Time),
		alertCounts: make(map[string]int),
	}
}

// SendAlert sends an alert for a renewal failure
func (am *AlertManager) SendAlert(status *RenewalStatus) {
	if status == nil {
		return
	}
	
	// Check if we should send an alert
	if !am.shouldAlert(status) {
		return
	}
	
	// Determine alert severity
	severity := am.determineSeverity(status)
	
	// Create alert message
	message := am.formatAlertMessage(status, severity)
	
	// Send alerts through configured channels
	var wg sync.WaitGroup
	
	if am.config.EmailEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := am.sendEmailAlert(message, severity); err != nil {
				logger.Error("Failed to send email alert", "error", err)
			}
		}()
	}
	
	if am.config.WebhookEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := am.sendWebhookAlert(status, severity); err != nil {
				logger.Error("Failed to send webhook alert", "error", err)
			}
		}()
	}
	
	if am.config.SlackEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := am.sendSlackAlert(status, severity); err != nil {
				logger.Error("Failed to send Slack alert", "error", err)
			}
		}()
	}
	
	wg.Wait()
	
	// Update alert tracking
	am.mu.Lock()
	am.lastAlerts[status.Domain] = time.Now()
	am.alertCounts[status.Domain]++
	am.mu.Unlock()
}

// shouldAlert determines if an alert should be sent
func (am *AlertManager) shouldAlert(status *RenewalStatus) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	// Check if enough failures have occurred
	if status.Attempts < am.config.MaxFailuresBeforeAlert {
		return false
	}
	
	// Check cooldown period
	if lastAlert, exists := am.lastAlerts[status.Domain]; exists {
		if time.Since(lastAlert) < am.config.AlertCooldown {
			return false
		}
	}
	
	return true
}

// determineSeverity determines the severity of the alert
func (am *AlertManager) determineSeverity(status *RenewalStatus) string {
	if status.ExpiryDate.IsZero() {
		return "critical"
	}
	
	daysUntilExpiry := int(time.Until(status.ExpiryDate).Hours() / 24)
	
	if daysUntilExpiry <= am.config.CriticalDaysBeforeExpiry {
		return "critical"
	} else if daysUntilExpiry <= am.config.WarnDaysBeforeExpiry {
		return "warning"
	}
	
	return "info"
}

// formatAlertMessage formats the alert message
func (am *AlertManager) formatAlertMessage(status *RenewalStatus, severity string) string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("🚨 Certificate Renewal Alert - %s\n\n", strings.ToUpper(severity)))
	sb.WriteString(fmt.Sprintf("Domain: %s\n", status.Domain))
	sb.WriteString(fmt.Sprintf("Status: %s\n", status.Status))
	sb.WriteString(fmt.Sprintf("Attempts: %d\n", status.Attempts))
	
	if !status.ExpiryDate.IsZero() {
		daysUntilExpiry := int(time.Until(status.ExpiryDate).Hours() / 24)
		sb.WriteString(fmt.Sprintf("Expiry Date: %s\n", status.ExpiryDate.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Days Until Expiry: %d\n", daysUntilExpiry))
	}
	
	if status.Error != "" {
		sb.WriteString(fmt.Sprintf("Error: %s\n", status.Error))
	}
	
	if !status.LastAttempt.IsZero() {
		sb.WriteString(fmt.Sprintf("Last Attempt: %s\n", status.LastAttempt.Format(time.RFC3339)))
	}
	
	if !status.NextAttempt.IsZero() {
		sb.WriteString(fmt.Sprintf("Next Attempt: %s\n", status.NextAttempt.Format(time.RFC3339)))
	}
	
	return sb.String()
}

// sendEmailAlert sends an email alert
func (am *AlertManager) sendEmailAlert(message, severity string) error {
	if len(am.config.EmailTo) == 0 {
		return fmt.Errorf("no email recipients configured")
	}
	
	subject := fmt.Sprintf("[%s] Certificate Renewal Alert", strings.ToUpper(severity))
	
	// Create email message
	var emailBody bytes.Buffer
	emailBody.WriteString(fmt.Sprintf("From: %s\r\n", am.config.EmailFrom))
	emailBody.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(am.config.EmailTo, ", ")))
	emailBody.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	emailBody.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	emailBody.WriteString("\r\n")
	emailBody.WriteString(message)
	
	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", am.config.SMTPHost, am.config.SMTPPort)
	
	var auth smtp.Auth
	if am.config.SMTPUser != "" && am.config.SMTPPass != "" {
		auth = smtp.PlainAuth("", am.config.SMTPUser, am.config.SMTPPass, am.config.SMTPHost)
	}
	
	// Send email
	err := smtp.SendMail(addr, auth, am.config.EmailFrom, am.config.EmailTo, emailBody.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	
	logger.Info("Email alert sent", "severity", severity, "recipients", len(am.config.EmailTo))
	return nil
}

// sendWebhookAlert sends a webhook alert
func (am *AlertManager) sendWebhookAlert(status *RenewalStatus, severity string) error {
	// Create webhook payload
	payload := map[string]interface{}{
		"severity":  severity,
		"timestamp": time.Now().Unix(),
		"domain":    status.Domain,
		"status":    status.Status,
		"attempts":  status.Attempts,
		"error":     status.Error,
	}
	
	if !status.ExpiryDate.IsZero() {
		payload["expiry_date"] = status.ExpiryDate.Format(time.RFC3339)
		payload["days_until_expiry"] = int(time.Until(status.ExpiryDate).Hours() / 24)
	}
	
	// Marshal payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}
	
	// Create HTTP request
	method := am.config.WebhookMethod
	if method == "" {
		method = "POST"
	}
	
	req, err := http.NewRequest(method, am.config.WebhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	// Add custom headers
	for k, v := range am.config.WebhookHeaders {
		req.Header.Set(k, v)
	}
	
	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}
	
	logger.Info("Webhook alert sent", "severity", severity, "url", am.config.WebhookURL)
	return nil
}

// sendSlackAlert sends a Slack alert
func (am *AlertManager) sendSlackAlert(status *RenewalStatus, severity string) error {
	// Determine color based on severity
	color := "#36a64f" // green
	if severity == "warning" {
		color = "#ff9900" // orange
	} else if severity == "critical" {
		color = "#ff0000" // red
	}
	
	// Create Slack message
	daysUntilExpiry := 0
	if !status.ExpiryDate.IsZero() {
		daysUntilExpiry = int(time.Until(status.ExpiryDate).Hours() / 24)
	}
	
	attachment := map[string]interface{}{
		"color":     color,
		"title":     fmt.Sprintf("Certificate Renewal Alert - %s", strings.ToUpper(severity)),
		"text":      fmt.Sprintf("Certificate renewal issue for domain: %s", status.Domain),
		"fields": []map[string]interface{}{
			{
				"title": "Domain",
				"value": status.Domain,
				"short": true,
			},
			{
				"title": "Status",
				"value": status.Status,
				"short": true,
			},
			{
				"title": "Attempts",
				"value": fmt.Sprintf("%d", status.Attempts),
				"short": true,
			},
			{
				"title": "Days Until Expiry",
				"value": fmt.Sprintf("%d", daysUntilExpiry),
				"short": true,
			},
		},
		"footer":      "LeProxy Certificate Manager",
		"footer_icon": "https://api.slack.com/img/api/homepage_custom_integrations-2x.png",
		"ts":          time.Now().Unix(),
	}
	
	if status.Error != "" {
		attachment["fields"] = append(attachment["fields"].([]map[string]interface{}), map[string]interface{}{
			"title": "Error",
			"value": status.Error,
			"short": false,
		})
	}
	
	slackMessage := map[string]interface{}{
		"attachments": []interface{}{attachment},
	}
	
	if am.config.SlackChannel != "" {
		slackMessage["channel"] = am.config.SlackChannel
	}
	
	if am.config.SlackUsername != "" {
		slackMessage["username"] = am.config.SlackUsername
	}
	
	// Marshal to JSON
	jsonPayload, err := json.Marshal(slackMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}
	
	// Send to Slack
	resp, err := http.Post(am.config.SlackWebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Slack alert: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack webhook returned error status: %d", resp.StatusCode)
	}
	
	logger.Info("Slack alert sent", "severity", severity, "channel", am.config.SlackChannel)
	return nil
}

// GetAlertStats returns statistics about alerts
func (am *AlertManager) GetAlertStats() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	stats := make(map[string]interface{})
	stats["total_domains_alerted"] = len(am.alertCounts)
	
	totalAlerts := 0
	for _, count := range am.alertCounts {
		totalAlerts += count
	}
	stats["total_alerts_sent"] = totalAlerts
	
	// Find most recent alert
	var mostRecent time.Time
	var mostRecentDomain string
	for domain, alertTime := range am.lastAlerts {
		if alertTime.After(mostRecent) {
			mostRecent = alertTime
			mostRecentDomain = domain
		}
	}
	
	if !mostRecent.IsZero() {
		stats["most_recent_alert"] = map[string]interface{}{
			"domain": mostRecentDomain,
			"time":   mostRecent.Format(time.RFC3339),
		}
	}
	
	return stats
}

// ResetAlertCount resets the alert count for a domain (e.g., after successful renewal)
func (am *AlertManager) ResetAlertCount(domain string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	delete(am.alertCounts, domain)
	delete(am.lastAlerts, domain)
}

// DefaultAlertHandler creates a default alert handler
func DefaultAlertHandler(config *AlertConfig) AlertHandler {
	manager := NewAlertManager(config)
	
	return func(status *RenewalStatus) {
		manager.SendAlert(status)
	}
}