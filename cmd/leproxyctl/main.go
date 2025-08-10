// leproxyctl - CLI management tool for LeProxy operations
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	defaultAdminAddr = "http://localhost:8081"
	version         = "1.0.0"
)

type Command struct {
	Name        string
	Description string
	Run         func(args []string) error
}

var commands = []Command{
	{Name: "status", Description: "Show proxy status", Run: cmdStatus},
	{Name: "mappings", Description: "Manage host mappings", Run: cmdMappings},
	{Name: "certs", Description: "Manage certificates", Run: cmdCerts},
	{Name: "blacklist", Description: "Manage IP blacklist", Run: cmdBlacklist},
	{Name: "reload", Description: "Reload configuration", Run: cmdReload},
	{Name: "health", Description: "Check health status", Run: cmdHealth},
	{Name: "metrics", Description: "Display metrics", Run: cmdMetrics},
	{Name: "logs", Description: "Tail logs", Run: cmdLogs},
	{Name: "test", Description: "Test backend connectivity", Run: cmdTest},
	{Name: "version", Description: "Show version", Run: cmdVersion},
}

var (
	adminAddr = flag.String("admin", getEnv("LEPROXY_ADMIN", defaultAdminAddr), "Admin API address")
	verbose   = flag.Bool("v", false, "Verbose output")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	cmdName := flag.Arg(0)
	for _, cmd := range commands {
		if cmd.Name == cmdName {
			if err := cmd.Run(flag.Args()[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmdName)
	usage()
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, "LeProxy Control Tool v%s\n\n", version)
	fmt.Fprintf(os.Stderr, "Usage: leproxyctl [options] <command> [args]\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	for _, cmd := range commands {
		fmt.Fprintf(w, "  %s\t%s\n", cmd.Name, cmd.Description)
	}
	w.Flush()
	
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  leproxyctl status              # Show proxy status\n")
	fmt.Fprintf(os.Stderr, "  leproxyctl mappings list        # List all mappings\n")
	fmt.Fprintf(os.Stderr, "  leproxyctl certs list           # List certificates\n")
	fmt.Fprintf(os.Stderr, "  leproxyctl blacklist add 1.2.3.4  # Add IP to blacklist\n")
	fmt.Fprintf(os.Stderr, "  leproxyctl reload               # Reload configuration\n")
}

func cmdStatus(args []string) error {
	resp, err := httpGet("/api/info")
	if err != nil {
		return err
	}
	
	fmt.Println("LeProxy Status")
	fmt.Println("==============")
	
	var info map[string]interface{}
	if err := json.Unmarshal(resp, &info); err != nil {
		return err
	}
	
	fmt.Printf("Version: %v\n", info["version"])
	fmt.Printf("Status: %v\n", info["status"])
	
	// Get health status
	healthResp, err := httpGet("/health")
	if err == nil {
		var health map[string]interface{}
		if json.Unmarshal(healthResp, &health) == nil {
			fmt.Printf("Health: %v\n", health["status"])
		}
	}
	
	// Get metrics summary
	metricsResp, err := httpGet("/metrics")
	if err == nil && *verbose {
		fmt.Println("\nMetrics Summary:")
		// Parse and display key metrics
		lines := strings.Split(string(metricsResp), "\n")
		for _, line := range lines {
			if strings.Contains(line, "http_requests_total") ||
			   strings.Contains(line, "http_request_duration_seconds") ||
			   strings.Contains(line, "rate_limit_rejected_total") {
				fmt.Printf("  %s\n", line)
			}
		}
	}
	
	return nil
}

func cmdMappings(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: list, add, remove, reload")
	}
	
	switch args[0] {
	case "list":
		resp, err := httpGet("/api/mappings")
		if err != nil {
			return err
		}
		
		var result map[string]interface{}
		if err := json.Unmarshal(resp, &result); err != nil {
			return err
		}
		
		fmt.Println("Host Mappings:")
		fmt.Println("==============")
		
		if mappings, ok := result["mappings"].(map[string]interface{}); ok {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "HOST\tBACKEND")
			for host, backend := range mappings {
				fmt.Fprintf(w, "%s\t%s\n", host, backend)
			}
			w.Flush()
		}
		
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("usage: mappings add <host> <backend>")
		}
		data := map[string]string{
			"host":    args[1],
			"backend": args[2],
		}
		_, err := httpPost("/api/mappings", data)
		if err != nil {
			return err
		}
		fmt.Printf("Added mapping: %s -> %s\n", args[1], args[2])
		
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: mappings remove <host>")
		}
		_, err := httpDelete(fmt.Sprintf("/api/mappings/%s", args[1]))
		if err != nil {
			return err
		}
		fmt.Printf("Removed mapping for: %s\n", args[1])
		
	case "reload":
		_, err := httpPost("/api/mappings", map[string]string{"action": "reload"})
		if err != nil {
			return err
		}
		fmt.Println("Mappings reloaded successfully")
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
	
	return nil
}

func cmdCerts(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: list, renew, backup, restore")
	}
	
	switch args[0] {
	case "list":
		resp, err := httpGet("/api/certs")
		if err != nil {
			return err
		}
		
		fmt.Println("Certificates:")
		fmt.Println("=============")
		fmt.Println(string(resp))
		
	case "renew":
		if len(args) < 2 {
			return fmt.Errorf("usage: certs renew <domain>")
		}
		_, err := httpDelete(fmt.Sprintf("/api/certs/%s", args[1]))
		if err != nil {
			return err
		}
		fmt.Printf("Certificate renewal triggered for: %s\n", args[1])
		
	case "backup":
		_, err := httpPost("/api/certs/backup", nil)
		if err != nil {
			return err
		}
		fmt.Println("Certificate backup completed")
		
	case "restore":
		_, err := httpPost("/api/certs/restore", nil)
		if err != nil {
			return err
		}
		fmt.Println("Certificate restore completed")
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
	
	return nil
}

func cmdBlacklist(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: add, remove, list")
	}
	
	switch args[0] {
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("usage: blacklist add <ip>")
		}
		data := map[string]string{"ip": args[1]}
		_, err := httpPost("/api/ratelimit/blacklist", data)
		if err != nil {
			return err
		}
		fmt.Printf("Added %s to blacklist\n", args[1])
		
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: blacklist remove <ip>")
		}
		_, err := httpDelete(fmt.Sprintf("/api/ratelimit/blacklist/%s", args[1]))
		if err != nil {
			return err
		}
		fmt.Printf("Removed %s from blacklist\n", args[1])
		
	case "list":
		resp, err := httpGet("/api/ratelimit/blacklist")
		if err != nil {
			return err
		}
		fmt.Println("Blacklisted IPs:")
		fmt.Println("================")
		fmt.Println(string(resp))
		
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
	
	return nil
}

func cmdReload(args []string) error {
	_, err := httpPost("/api/reload", nil)
	if err != nil {
		return err
	}
	fmt.Println("Configuration reloaded successfully")
	return nil
}

func cmdHealth(args []string) error {
	endpoints := []string{"/health", "/ready", "/live"}
	
	fmt.Println("Health Checks:")
	fmt.Println("==============")
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENDPOINT\tSTATUS\tDETAILS")
	
	for _, endpoint := range endpoints {
		resp, err := httpGet(endpoint)
		status := "OK"
		details := ""
		
		if err != nil {
			status = "FAIL"
			details = err.Error()
		} else {
			var result map[string]interface{}
			if json.Unmarshal(resp, &result) == nil {
				if s, ok := result["status"].(string); ok {
					status = strings.ToUpper(s)
				}
				if msg, ok := result["message"].(string); ok {
					details = msg
				}
			}
		}
		
		fmt.Fprintf(w, "%s\t%s\t%s\n", endpoint, status, details)
	}
	
	w.Flush()
	return nil
}

func cmdMetrics(args []string) error {
	resp, err := httpGet("/metrics")
	if err != nil {
		return err
	}
	
	if len(args) > 0 && args[0] == "raw" {
		fmt.Println(string(resp))
		return nil
	}
	
	fmt.Println("Metrics Summary:")
	fmt.Println("================")
	
	// Parse Prometheus metrics and display summary
	lines := strings.Split(string(resp), "\n")
	metrics := make(map[string]float64)
	
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			metricName := parts[0]
			if strings.Contains(metricName, "{") {
				metricName = strings.Split(metricName, "{")[0]
			}
			metrics[metricName] = 1 // Simplified - would parse actual value
		}
	}
	
	// Display summary
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "METRIC\tVALUE")
	
	for name := range metrics {
		fmt.Fprintf(w, "%s\t%v\n", name, metrics[name])
	}
	
	w.Flush()
	return nil
}

func cmdLogs(args []string) error {
	fmt.Println("Tailing logs...")
	fmt.Println("================")
	
	// In a real implementation, this would connect to a log streaming endpoint
	// For now, we'll show a placeholder
	fmt.Println("Log streaming requires WebSocket connection to /api/logs/stream")
	fmt.Println("Use system logs or docker logs for now")
	
	return nil
}

func cmdTest(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: test <backend-url>")
	}
	
	backend := args[0]
	data := map[string]string{"backend": backend}
	
	resp, err := httpPost("/api/test", data)
	if err != nil {
		return err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return err
	}
	
	fmt.Printf("Backend test for %s:\n", backend)
	fmt.Printf("  Status: %v\n", result["status"])
	fmt.Printf("  Response Time: %v\n", result["response_time"])
	
	return nil
}

func cmdVersion(args []string) error {
	fmt.Printf("leproxyctl version %s\n", version)
	
	// Try to get server version
	resp, err := httpGet("/api/info")
	if err == nil {
		var info map[string]interface{}
		if json.Unmarshal(resp, &info) == nil {
			fmt.Printf("Server version: %v\n", info["version"])
		}
	}
	
	return nil
}

// HTTP helper functions

func httpGet(path string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(*adminAddr + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	
	return body, nil
}

func httpPost(path string, data interface{}) ([]byte, error) {
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(jsonData)
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(*adminAddr+path, "application/json", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	
	return respBody, nil
}

func httpDelete(path string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("DELETE", *adminAddr+path, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	
	return body, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}