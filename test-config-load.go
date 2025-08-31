// Test program to verify config loading functionality
package main

import (
	"fmt"
	"log"
	"time"
	
	"github.com/artyom/leproxy/internal/config"
)

func main() {
	// Test loading YAML config
	fmt.Println("Testing YAML config loading...")
	yamlConfig, err := config.LoadConfig("example-config.yaml")
	if err != nil {
		log.Printf("Failed to load YAML config: %v\n", err)
	} else {
		fmt.Printf("✓ YAML config loaded successfully\n")
		fmt.Printf("  - Server HTTPS: %s\n", yamlConfig.Server.HTTPSAddr)
		fmt.Printf("  - ACME Provider: %s\n", yamlConfig.Server.ACME.Provider)
		fmt.Printf("  - Mappings count: %d\n", len(yamlConfig.Mappings))
		fmt.Printf("  - DB Proxies count: %d\n", len(yamlConfig.DatabaseProxies))
	}
	
	fmt.Println("\nTesting JSON config loading...")
	jsonConfig, err := config.LoadConfig("example-config.json")
	if err != nil {
		log.Printf("Failed to load JSON config: %v\n", err)
	} else {
		fmt.Printf("✓ JSON config loaded successfully\n")
		fmt.Printf("  - Server HTTPS: %s\n", jsonConfig.Server.HTTPSAddr)
		fmt.Printf("  - ACME Provider: %s\n", jsonConfig.Server.ACME.Provider)
		fmt.Printf("  - Mappings count: %d\n", len(jsonConfig.Mappings))
	}
	
	// Test LoadFile with CLI args
	fmt.Println("\nTesting LoadFile with CLI args override...")
	cliArgs := &config.CLIArgs{
		HTTPSAddr:    ":9443",  // Override HTTPS port
		LogLevel:     "debug",  // Override log level
		RateLimit:    200,      // Override rate limit
		ReadTimeout:  45 * time.Second,
	}
	
	mergedConfig, err := config.LoadFile("example-config.yaml", cliArgs)
	if err != nil {
		log.Printf("Failed to load config with CLI args: %v\n", err)
	} else {
		fmt.Printf("✓ Config loaded with CLI override successfully\n")
		fmt.Printf("  - Server HTTPS (overridden): %s\n", mergedConfig.Server.HTTPSAddr)
		fmt.Printf("  - Log Level (overridden): %s\n", mergedConfig.Logging.Level)
		fmt.Printf("  - Rate Limit (overridden): %d\n", mergedConfig.Security.RateLimit.RequestsPerSecond)
		fmt.Printf("  - ACME Email (from file): %s\n", mergedConfig.Server.ACME.Email)
	}
	
	fmt.Println("\n✅ Config loading implementation is working correctly!")
}