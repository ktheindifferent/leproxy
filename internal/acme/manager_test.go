package acme

import (
	"strings"
	"testing"
)

func TestGetProviderInfo(t *testing.T) {
	tests := []struct {
		provider         string
		expectNil        bool
		expectedName     string
		expectedValidity int
		requiresEAB      bool
		supportsWildcard bool
	}{
		{
			provider:         "letsencrypt",
			expectNil:        false,
			expectedName:     "letsencrypt",
			expectedValidity: 90,
			requiresEAB:      false,
			supportsWildcard: true,
		},
		{
			provider:         "zerossl",
			expectNil:        false,
			expectedName:     "zerossl",
			expectedValidity: 90,
			requiresEAB:      true,
			supportsWildcard: true,
		},
		{
			provider:         "buypass",
			expectNil:        false,
			expectedName:     "buypass",
			expectedValidity: 180,
			requiresEAB:      false,
			supportsWildcard: false,
		},
		{
			provider:         "sslcom",
			expectNil:        false,
			expectedName:     "sslcom",
			expectedValidity: 90,
			requiresEAB:      true,
			supportsWildcard: false,
		},
		{
			provider:         "entrust",
			expectNil:        false,
			expectedName:     "entrust",
			expectedValidity: 90,
			requiresEAB:      false,
			supportsWildcard: true,
		},
		{
			provider:         "google",
			expectNil:        false,
			expectedName:     "google",
			expectedValidity: 90,
			requiresEAB:      true,
			supportsWildcard: true,
		},
		{
			provider:         "unknown",
			expectNil:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			info := GetProviderInfo(tt.provider)
			
			if tt.expectNil {
				if info != nil {
					t.Errorf("Expected nil for unknown provider %s, got %v", tt.provider, info)
				}
				return
			}
			
			if info == nil {
				t.Fatalf("Expected provider info for %s, got nil", tt.provider)
			}
			
			if info.Name != tt.expectedName {
				t.Errorf("Expected name %s, got %s", tt.expectedName, info.Name)
			}
			
			if info.CertValidity != tt.expectedValidity {
				t.Errorf("Expected validity %d days, got %d days", tt.expectedValidity, info.CertValidity)
			}
			
			if info.RequiresEAB != tt.requiresEAB {
				t.Errorf("Expected RequiresEAB %v, got %v", tt.requiresEAB, info.RequiresEAB)
			}
			
			if info.SupportsWildcard != tt.supportsWildcard {
				t.Errorf("Expected SupportsWildcard %v, got %v", tt.supportsWildcard, info.SupportsWildcard)
			}
		})
	}
}

func TestGetAvailableProviders(t *testing.T) {
	providers := GetAvailableProviders()
	
	if len(providers) != 6 {
		t.Errorf("Expected 6 providers, got %d", len(providers))
	}
	
	// Check that all providers are present
	expectedProviders := map[string]bool{
		"letsencrypt": false,
		"zerossl":     false,
		"buypass":     false,
		"sslcom":      false,
		"entrust":     false,
		"google":      false,
	}
	
	for _, p := range providers {
		if _, exists := expectedProviders[p.Name]; exists {
			expectedProviders[p.Name] = true
		}
	}
	
	for name, found := range expectedProviders {
		if !found {
			t.Errorf("Provider %s not found in available providers", name)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_letsencrypt",
			config: &Config{
				Provider: ProviderLetsEncrypt,
				CacheDir: "/tmp/cache",
				Email:    "test@example.com",
				Domains:  []string{"example.com", "*.example.com"},
			},
			expectError: false,
		},
		{
			name: "zerossl_missing_eab",
			config: &Config{
				Provider: ProviderZeroSSL,
				CacheDir: "/tmp/cache",
				Email:    "test@example.com",
			},
			expectError: true,
			errorMsg:    "EAB credentials",
		},
		{
			name: "zerossl_with_eab",
			config: &Config{
				Provider: ProviderZeroSSL,
				CacheDir: "/tmp/cache",
				Email:    "test@example.com",
				EABKID:   "test-kid",
				EABHMAC:  "test-hmac",
			},
			expectError: false,
		},
		{
			name: "buypass_with_wildcard",
			config: &Config{
				Provider: ProviderBuypass,
				CacheDir: "/tmp/cache",
				Email:    "test@example.com",
				Domains:  []string{"*.example.com"},
			},
			expectError: true,
			errorMsg:    "wildcard",
		},
		{
			name: "buypass_without_wildcard",
			config: &Config{
				Provider: ProviderBuypass,
				CacheDir: "/tmp/cache",
				Email:    "test@example.com",
				Domains:  []string{"example.com", "www.example.com"},
			},
			expectError: false,
		},
		{
			name: "google_missing_eab",
			config: &Config{
				Provider: ProviderGoogle,
				CacheDir: "/tmp/cache",
				Email:    "test@example.com",
			},
			expectError: true,
			errorMsg:    "EAB credentials",
		},
		{
			name: "missing_cache_dir",
			config: &Config{
				Provider: ProviderLetsEncrypt,
				Email:    "test@example.com",
			},
			expectError: true,
			errorMsg:    "cache directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestGetDirectoryURL(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		expectedURL  string
		expectCustom bool
	}{
		{
			name: "letsencrypt_prod",
			config: &Config{
				Provider: ProviderLetsEncrypt,
				TestMode: false,
			},
			expectedURL: "",  // Uses default
		},
		{
			name: "letsencrypt_staging",
			config: &Config{
				Provider: ProviderLetsEncrypt,
				TestMode: true,
			},
			expectedURL: LetsEncryptStagingURL,
		},
		{
			name: "zerossl",
			config: &Config{
				Provider: ProviderZeroSSL,
				TestMode: false,
			},
			expectedURL: ZeroSSLProdURL,
		},
		{
			name: "buypass_prod",
			config: &Config{
				Provider: ProviderBuypass,
				TestMode: false,
			},
			expectedURL: BuypassProdURL,
		},
		{
			name: "buypass_test",
			config: &Config{
				Provider: ProviderBuypass,
				TestMode: true,
			},
			expectedURL: BuypassStagingURL,
		},
		{
			name: "google_prod",
			config: &Config{
				Provider: ProviderGoogle,
				TestMode: false,
			},
			expectedURL: GoogleProdURL,
		},
		{
			name: "google_staging",
			config: &Config{
				Provider: ProviderGoogle,
				TestMode: true,
			},
			expectedURL: GoogleStagingURL,
		},
		{
			name: "custom_url",
			config: &Config{
				Provider:     ProviderLetsEncrypt,
				DirectoryURL: "https://custom.acme.com/directory",
				TestMode:     false,
			},
			expectedURL:  "https://custom.acme.com/directory",
			expectCustom: true,
		},
		{
			name: "sslcom_no_staging",
			config: &Config{
				Provider: ProviderSSLcom,
				TestMode: true,  // No staging URL available
			},
			expectedURL: SSLcomProdURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := getDirectoryURL(tt.config)
			
			if url != tt.expectedURL {
				t.Errorf("Expected URL %s, got %s", tt.expectedURL, url)
			}
		})
	}
}

func TestProviderConstants(t *testing.T) {
	// Ensure all provider constants are defined
	providers := []string{
		ProviderLetsEncrypt,
		ProviderZeroSSL,
		ProviderBuypass,
		ProviderSSLcom,
		ProviderEntrust,
		ProviderGoogle,
	}
	
	for _, p := range providers {
		if p == "" {
			t.Error("Provider constant is empty")
		}
	}
	
	// Ensure all production URLs are valid
	urls := []string{
		LetsEncryptProdURL,
		ZeroSSLProdURL,
		BuypassProdURL,
		SSLcomProdURL,
		EntrustProdURL,
		GoogleProdURL,
	}
	
	for _, url := range urls {
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("Invalid HTTPS URL: %s", url)
		}
		if !strings.Contains(url, "/") {
			t.Errorf("URL missing path: %s", url)
		}
	}
	
	// Ensure staging URLs are valid where defined
	stagingURLs := []string{
		LetsEncryptStagingURL,
		BuypassStagingURL,
		GoogleStagingURL,
	}
	
	for _, url := range stagingURLs {
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("Invalid staging HTTPS URL: %s", url)
		}
		if !strings.Contains(url, "staging") && !strings.Contains(url, "test") {
			t.Errorf("Staging URL doesn't contain 'staging' or 'test': %s", url)
		}
	}
}