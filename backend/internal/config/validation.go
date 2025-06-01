package config

import (
	"fmt"
	"os"
)

// validateConfiguration validates the complete configuration
func (cm *ConfigManager) validateConfiguration(config *Config) error {
	if err := cm.validateServerConfig(&config.Server); err != nil {
		return fmt.Errorf("server configuration error: %w", err)
	}

	if err := cm.validateDatabaseConfig(&config.Database); err != nil {
		return fmt.Errorf("database configuration error: %w", err)
	}

	if err := cm.validateAuthConfig(&config.Auth); err != nil {
		return fmt.Errorf("auth configuration error: %w", err)
	}

	if err := cm.validateSecurityConfig(&config.Security); err != nil {
		return fmt.Errorf("security configuration error: %w", err)
	}

	if err := cm.validateSecretsConfig(&config.Secrets); err != nil {
		return fmt.Errorf("secrets configuration error: %w", err)
	}

	if err := cm.validateExternalConfig(&config.External); err != nil {
		return fmt.Errorf("external services configuration error: %w", err)
	}

	return nil
}

// validateServerConfig validates server configuration
func (cm *ConfigManager) validateServerConfig(config *ServerConfig) error {
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Port)
	}

	if config.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}

	if config.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}

	// Validate TLS configuration
	if config.EnableTLS {
		if config.TLSCertFile == "" {
			return fmt.Errorf("TLS cert file required when TLS is enabled")
		}
		if config.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file required when TLS is enabled")
		}

		// Check if files exist
		if _, err := os.Stat(config.TLSCertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS cert file not found: %s", config.TLSCertFile)
		}
		if _, err := os.Stat(config.TLSKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", config.TLSKeyFile)
		}
	}

	return nil
}

// validateDatabaseConfig validates database configuration
func (cm *ConfigManager) validateDatabaseConfig(config *DatabaseConfig) error {
	if config.Host == "" {
		return fmt.Errorf("database host is required")
	}

	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", config.Port)
	}

	if config.User == "" {
		return fmt.Errorf("database user is required")
	}

	if config.DBName == "" {
		return fmt.Errorf("database name is required")
	}

	if config.MaxOpenConns <= 0 {
		return fmt.Errorf("max open connections must be positive")
	}

	if config.MaxIdleConns <= 0 {
		return fmt.Errorf("max idle connections must be positive")
	}

	if config.MaxIdleConns > config.MaxOpenConns {
		return fmt.Errorf("max idle connections cannot exceed max open connections")
	}

	return nil
}

// validateAuthConfig validates authentication configuration
func (cm *ConfigManager) validateAuthConfig(config *AuthConfig) error {
	if config.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if len(config.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	if config.PasswordSaltCost < 4 || config.PasswordSaltCost > 31 {
		return fmt.Errorf("password salt cost must be between 4 and 31")
	}

	if config.MaxLoginAttempts <= 0 {
		return fmt.Errorf("max login attempts must be positive")
	}

	// Validate password policy
	if config.PasswordPolicy.MinLength < 4 {
		return fmt.Errorf("minimum password length must be at least 4")
	}

	if config.PasswordPolicy.MinScore < 0 || config.PasswordPolicy.MinScore > 4 {
		return fmt.Errorf("password policy min score must be between 0 and 4")
	}

	return nil
}

// validateSecurityConfig validates security configuration
func (cm *ConfigManager) validateSecurityConfig(config *SecurityConfig) error {
	if config.EnableRateLimiting && config.RateLimitRequests <= 0 {
		return fmt.Errorf("rate limit requests must be positive when rate limiting is enabled")
	}

	if config.CSRFTokenLength < 16 {
		return fmt.Errorf("CSRF token length must be at least 16")
	}

	if config.MaxUploadSize <= 0 {
		return fmt.Errorf("max upload size must be positive")
	}

	return nil
}

// validateSecretsConfig validates secrets configuration
func (cm *ConfigManager) validateSecretsConfig(config *SecretsConfig) error {
	if config.Provider == "" {
		return fmt.Errorf("secrets provider is required")
	}

	validProviders := []string{"local", "vault", "aws"}
	isValid := false
	for _, provider := range validProviders {
		if config.Provider == provider {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("invalid secrets provider: %s (valid: %v)", config.Provider, validProviders)
	}

	// Provider-specific validation
	switch config.Provider {
	case "local":
		if config.LocalConfig.SecretFile == "" && config.LocalConfig.EncryptedFile == "" {
			return fmt.Errorf("local provider requires either secret_file or encrypted_file")
		}
	case "vault":
		if config.VaultConfig.Address == "" {
			return fmt.Errorf("vault address is required")
		}
		if config.VaultConfig.Token == "" {
			return fmt.Errorf("vault token is required")
		}
	case "aws":
		if config.AWSConfig.Region == "" {
			return fmt.Errorf("AWS region is required")
		}
	}

	return nil
}

// validateExternalConfig validates external services configuration
func (cm *ConfigManager) validateExternalConfig(config *ExternalConfig) error {
	// Validate enabled LLM providers
	for name, provider := range config.LLMProviders {
		if provider.Enabled {
			if provider.APIKey == "" {
				return fmt.Errorf("LLM provider %s requires API key when enabled", name)
			}
			if provider.APIUrl == "" {
				return fmt.Errorf("LLM provider %s requires API URL when enabled", name)
			}
			if provider.MaxTokens <= 0 {
				return fmt.Errorf("LLM provider %s max_tokens must be positive", name)
			}
			if provider.Temperature < 0 || provider.Temperature > 2 {
				return fmt.Errorf("LLM provider %s temperature must be between 0 and 2", name)
			}
		}
	}

	// Validate enabled SMS providers
	for name, provider := range config.SMSProviders {
		if provider.Enabled {
			if provider.AccountSID == "" {
				return fmt.Errorf("SMS provider %s requires account SID when enabled", name)
			}
			if provider.AuthToken == "" {
				return fmt.Errorf("SMS provider %s requires auth token when enabled", name)
			}
		}
	}

	// Validate email provider if enabled
	if config.EmailProvider.Enabled {
		if config.EmailProvider.SMTPHost == "" {
			return fmt.Errorf("email provider requires SMTP host when enabled")
		}
		if config.EmailProvider.Username == "" {
			return fmt.Errorf("email provider requires username when enabled")
		}
	}

	return nil
}
