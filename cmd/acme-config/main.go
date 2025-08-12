package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/artyom/leproxy/internal/acme"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		listProviders   = flag.Bool("list", false, "List all available ACME providers")
		showProvider    = flag.String("show", "", "Show detailed information about a specific provider")
		generateConfig  = flag.String("generate", "", "Generate sample configuration for a provider (yaml or json)")
		provider        = flag.String("provider", "letsencrypt", "Provider to use for configuration generation")
		email          = flag.String("email", "", "Email address for ACME registration")
		eabKID         = flag.String("eab-kid", "", "EAB Key ID (for providers that require it)")
		eabHMAC        = flag.String("eab-hmac", "", "EAB HMAC key (for providers that require it)")
		testMode       = flag.Bool("test", false, "Use staging/test environment when available")
		outputFormat   = flag.String("format", "yaml", "Output format (yaml or json)")
	)
	
	flag.Parse()
	
	if *listProviders {
		listAllProviders()
		return
	}
	
	if *showProvider != "" {
		showProviderDetails(*showProvider)
		return
	}
	
	if *generateConfig != "" {
		generateConfiguration(*generateConfig, *provider, *email, *eabKID, *eabHMAC, *testMode, *outputFormat)
		return
	}
	
	// Default: show usage
	fmt.Println("ACME Provider Configuration Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  acme-config -list                    # List all available providers")
	fmt.Println("  acme-config -show <provider>         # Show details about a provider")
	fmt.Println("  acme-config -generate <file>         # Generate configuration file")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  acme-config -list")
	fmt.Println("  acme-config -show buypass")
	fmt.Println("  acme-config -generate config.yaml -provider zerossl -email user@example.com -eab-kid YOUR_KID -eab-hmac YOUR_HMAC")
	fmt.Println()
	flag.PrintDefaults()
}

func listAllProviders() {
	providers := acme.GetAvailableProviders()
	
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tCERT VALIDITY\tWILDCARD\tEAB REQUIRED\tSTAGING\tDESCRIPTION")
	fmt.Fprintln(w, "--------\t-------------\t--------\t------------\t-------\t-----------")
	
	for _, p := range providers {
		wildcard := "No"
		if p.SupportsWildcard {
			wildcard = "Yes"
		}
		
		eab := "No"
		if p.RequiresEAB {
			eab = "Yes"
		}
		
		staging := "No"
		if p.StagingURL != "" {
			staging = "Yes"
		}
		
		fmt.Fprintf(w, "%s\t%d days\t%s\t%s\t%s\t%s\n",
			p.Name,
			p.CertValidity,
			wildcard,
			eab,
			staging,
			p.Description,
		)
	}
	
	w.Flush()
	
	fmt.Println("\nNotes:")
	fmt.Println("- Providers marked with 'EAB Required' need External Account Binding credentials")
	fmt.Println("- Use --test-mode flag to use staging environment for providers that support it")
	fmt.Println("- Buypass offers 180-day certificates but doesn't support wildcards")
}

func showProviderDetails(providerName string) {
	info := acme.GetProviderInfo(providerName)
	if info == nil {
		fmt.Fprintf(os.Stderr, "Unknown provider: %s\n", providerName)
		os.Exit(1)
	}
	
	fmt.Printf("Provider: %s\n", info.DisplayName)
	fmt.Printf("Name: %s\n", info.Name)
	fmt.Printf("Description: %s\n", info.Description)
	fmt.Printf("Certificate Validity: %d days\n", info.CertValidity)
	fmt.Printf("Wildcard Support: %v\n", info.SupportsWildcard)
	fmt.Printf("EAB Required: %v\n", info.RequiresEAB)
	fmt.Printf("Production URL: %s\n", info.DirectoryURL)
	
	if info.StagingURL != "" {
		fmt.Printf("Staging URL: %s\n", info.StagingURL)
	}
	
	fmt.Println("\nConfiguration Example:")
	fmt.Println("```yaml")
	fmt.Printf("server:\n")
	fmt.Printf("  acme:\n")
	fmt.Printf("    provider: %s\n", info.Name)
	fmt.Printf("    email: your-email@example.com\n")
	
	if info.RequiresEAB {
		fmt.Printf("    eab_kid: YOUR_EAB_KEY_ID\n")
		fmt.Printf("    eab_hmac: YOUR_EAB_HMAC_KEY\n")
	}
	
	if info.StagingURL != "" {
		fmt.Printf("    test_mode: false  # Set to true for staging\n")
	}
	
	fmt.Println("```")
	
	if info.RequiresEAB {
		fmt.Println("\nEAB Credentials:")
		switch info.Name {
		case "zerossl":
			fmt.Println("Get your EAB credentials from: https://app.zerossl.com/developer")
		case "sslcom":
			fmt.Println("Get your EAB credentials from: https://www.ssl.com/")
		case "google":
			fmt.Println("Get your EAB credentials from: https://cloud.google.com/certificate-manager/docs/public-ca-tutorial")
		}
	}
	
	if !info.SupportsWildcard && info.Name == "buypass" {
		fmt.Println("\nNote: Buypass does not support wildcard certificates (*.example.com)")
		fmt.Println("However, it offers 180-day certificates (double the standard 90 days)")
	}
}

func generateConfiguration(filename, provider, email, eabKID, eabHMAC string, testMode bool, format string) {
	info := acme.GetProviderInfo(provider)
	if info == nil {
		fmt.Fprintf(os.Stderr, "Unknown provider: %s\n", provider)
		os.Exit(1)
	}
	
	if email == "" {
		fmt.Fprintln(os.Stderr, "Email is required for configuration generation")
		os.Exit(1)
	}
	
	if info.RequiresEAB && (eabKID == "" || eabHMAC == "") {
		fmt.Fprintf(os.Stderr, "Provider %s requires EAB credentials (--eab-kid and --eab-hmac)\n", provider)
		os.Exit(1)
	}
	
	// Create configuration structure
	config := map[string]interface{}{
		"server": map[string]interface{}{
			"http_addr":  ":80",
			"https_addr": ":443",
			"acme": map[string]interface{}{
				"provider":  provider,
				"email":     email,
				"cache_dir": "/var/cache/letsencrypt",
				"test_mode": testMode,
			},
		},
		"mappings": map[string]interface{}{
			"example.com": map[string]interface{}{
				"url":            "http://localhost:8080",
				"health_check":   "/health",
				"max_connections": 100,
			},
		},
		"logging": map[string]interface{}{
			"level":  "info",
			"format": "text",
		},
	}
	
	// Add EAB credentials if required
	if info.RequiresEAB {
		acmeConfig := config["server"].(map[string]interface{})["acme"].(map[string]interface{})
		acmeConfig["eab_kid"] = eabKID
		acmeConfig["eab_hmac"] = eabHMAC
	}
	
	// Add domains configuration
	acmeConfig := config["server"].(map[string]interface{})["acme"].(map[string]interface{})
	if info.SupportsWildcard {
		acmeConfig["domains"] = []string{"example.com", "*.example.com"}
	} else {
		acmeConfig["domains"] = []string{"example.com", "www.example.com"}
	}
	
	// Write configuration file
	file, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()
	
	if strings.ToLower(format) == "json" {
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(config); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		encoder := yaml.NewEncoder(file)
		if err := encoder.Encode(config); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write YAML: %v\n", err)
			os.Exit(1)
		}
	}
	
	fmt.Printf("Configuration file generated: %s\n", filename)
	fmt.Printf("Provider: %s\n", info.DisplayName)
	
	if testMode && info.StagingURL != "" {
		fmt.Println("Test mode enabled - using staging environment")
	}
	
	if info.RequiresEAB {
		fmt.Println("\nRemember to keep your EAB credentials secure!")
	}
	
	if !info.SupportsWildcard {
		fmt.Println("\nNote: This provider does not support wildcard certificates")
	}
}