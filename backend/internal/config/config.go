package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Config struct {
	Server   ServerConfig   `json:"server" mapstructure:"server"`
	Database DatabaseConfig `json:"database" mapstructure:"database"`
	Logger   LoggerConfig   `json:"logger" mapstructure:"logger"`
	Auth     AuthConfig     `json:"auth" mapstructure:"auth"`
	Security SecurityConfig `json:"security" mapstructure:"security"`
	Secrets  SecretsConfig  `json:"secrets" mapstructure:"secrets"`
	External ExternalConfig `json:"external" mapstructure:"external"`
}

type ServerConfig struct {
	Host            string            `json:"host" mapstructure:"host"`
	Port            int               `json:"port" mapstructure:"port"`
	Environment     string            `json:"environment" mapstructure:"environment"`
	ReadTimeout     int               `json:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout    int               `json:"write_timeout" mapstructure:"write_timeout"`
	TrustedProxies  []string          `json:"trusted_proxies" mapstructure:"trusted_proxies"`
	AllowedHosts    []string          `json:"allowed_hosts" mapstructure:"allowed_hosts"`
	EnableTLS       bool              `json:"enable_tls" mapstructure:"enable_tls"`
	TLSCertFile     string            `json:"tls_cert_file" mapstructure:"tls_cert_file"`
	TLSKeyFile      string            `json:"tls_key_file" mapstructure:"tls_key_file"`
	GracefulTimeout int               `json:"graceful_timeout" mapstructure:"graceful_timeout"`
	HealthCheckPath string            `json:"health_check_path" mapstructure:"health_check_path"`
	MetricsPath     string            `json:"metrics_path" mapstructure:"metrics_path"`
	EnableMetrics   bool              `json:"enable_metrics" mapstructure:"enable_metrics"`
	EnableProfiling bool              `json:"enable_profiling" mapstructure:"enable_profiling"`
	CORSOrigins     []string          `json:"cors_origins" mapstructure:"cors_origins"`
	Headers         map[string]string `json:"headers" mapstructure:"headers"`
}

type DatabaseConfig struct {
	Host             string        `json:"host" mapstructure:"host"`
	Port             int           `json:"port" mapstructure:"port"`
	User             string        `json:"user" mapstructure:"user"`
	Password         string        `json:"password" mapstructure:"password"`
	DBName           string        `json:"dbname" mapstructure:"dbname"`
	SSLMode          string        `json:"sslmode" mapstructure:"sslmode"`
	MaxOpenConns     int           `json:"max_open_conns" mapstructure:"max_open_conns"`
	MaxIdleConns     int           `json:"max_idle_conns" mapstructure:"max_idle_conns"`
	ConnMaxLifetime  time.Duration `json:"conn_max_lifetime" mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime  time.Duration `json:"conn_max_idle_time" mapstructure:"conn_max_idle_time"`
	EnableLogging    bool          `json:"enable_logging" mapstructure:"enable_logging"`
	SlowQueryTime    time.Duration `json:"slow_query_time" mapstructure:"slow_query_time"`
	RetryAttempts    int           `json:"retry_attempts" mapstructure:"retry_attempts"`
	RetryDelay       time.Duration `json:"retry_delay" mapstructure:"retry_delay"`
	EncryptionKey    string        `json:"encryption_key" mapstructure:"encryption_key"`
	BackupSchedule   string        `json:"backup_schedule" mapstructure:"backup_schedule"`
	EnableMigrations bool          `json:"enable_migrations" mapstructure:"enable_migrations"`
}

type LoggerConfig struct {
	Level            string            `json:"level" mapstructure:"level"`
	Format           string            `json:"format" mapstructure:"format"`
	OutputPath       string            `json:"output_path" mapstructure:"output_path"`
	ErrorOutputPath  string            `json:"error_output_path" mapstructure:"error_output_path"`
	MaxSize          int               `json:"max_size" mapstructure:"max_size"`
	MaxBackups       int               `json:"max_backups" mapstructure:"max_backups"`
	MaxAge           int               `json:"max_age" mapstructure:"max_age"`
	Compress         bool              `json:"compress" mapstructure:"compress"`
	EnableConsole    bool              `json:"enable_console" mapstructure:"enable_console"`
	EnableFile       bool              `json:"enable_file" mapstructure:"enable_file"`
	EnableSyslog     bool              `json:"enable_syslog" mapstructure:"enable_syslog"`
	SyslogNetwork    string            `json:"syslog_network" mapstructure:"syslog_network"`
	SyslogAddress    string            `json:"syslog_address" mapstructure:"syslog_address"`
	SyslogTag        string            `json:"syslog_tag" mapstructure:"syslog_tag"`
	EnableSampling   bool              `json:"enable_sampling" mapstructure:"enable_sampling"`
	SamplingInitial  int               `json:"sampling_initial" mapstructure:"sampling_initial"`
	SamplingInterval int               `json:"sampling_interval" mapstructure:"sampling_interval"`
	Fields           map[string]string `json:"fields" mapstructure:"fields"`
}

type AuthConfig struct {
	JWTSecret            string        `json:"jwt_secret" mapstructure:"jwt_secret"`
	TokenDuration        time.Duration `json:"token_duration" mapstructure:"token_duration"`
	RefreshTokenDuration time.Duration `json:"refresh_token_duration" mapstructure:"refresh_token_duration"`
	JWTIssuer            string        `json:"jwt_issuer" mapstructure:"jwt_issuer"`
	JWTAudience          string        `json:"jwt_audience" mapstructure:"jwt_audience"`
	PasswordSaltCost     int           `json:"password_salt_cost" mapstructure:"password_salt_cost"`
	EnableTwoFactor      bool          `json:"enable_two_factor" mapstructure:"enable_two_factor"`
	EnableOAuth          bool          `json:"enable_oauth" mapstructure:"enable_oauth"`
	OAuthProviders       []string      `json:"oauth_providers" mapstructure:"oauth_providers"`
	SessionTimeout       time.Duration `json:"session_timeout" mapstructure:"session_timeout"`
	MaxLoginAttempts     int           `json:"max_login_attempts" mapstructure:"max_login_attempts"`
	LockoutDuration      time.Duration `json:"lockout_duration" mapstructure:"lockout_duration"`
	PasswordPolicy       struct {
		MinLength           int  `json:"min_length" mapstructure:"min_length"`
		RequireUppercase    bool `json:"require_uppercase" mapstructure:"require_uppercase"`
		RequireLowercase    bool `json:"require_lowercase" mapstructure:"require_lowercase"`
		RequireNumbers      bool `json:"require_numbers" mapstructure:"require_numbers"`
		RequireSpecialChars bool `json:"require_special_chars" mapstructure:"require_special_chars"`
		ForbidCommon        bool `json:"forbid_common" mapstructure:"forbid_common"`
		MinScore            int  `json:"min_score" mapstructure:"min_score"`
	} `json:"password_policy" mapstructure:"password_policy"`
}

type SecurityConfig struct {
	EncryptionKey           string        `json:"encryption_key" mapstructure:"encryption_key"`
	EnableRateLimiting      bool          `json:"enable_rate_limiting" mapstructure:"enable_rate_limiting"`
	RateLimitRequests       int           `json:"rate_limit_requests" mapstructure:"rate_limit_requests"`
	RateLimitWindow         time.Duration `json:"rate_limit_window" mapstructure:"rate_limit_window"`
	EnableIPWhitelist       bool          `json:"enable_ip_whitelist" mapstructure:"enable_ip_whitelist"`
	WhitelistedIPs          []string      `json:"whitelisted_ips" mapstructure:"whitelisted_ips"`
	EnableIPBlacklist       bool          `json:"enable_ip_blacklist" mapstructure:"enable_ip_blacklist"`
	BlacklistedIPs          []string      `json:"blacklisted_ips" mapstructure:"blacklisted_ips"`
	EnableCSRFProtection    bool          `json:"enable_csrf_protection" mapstructure:"enable_csrf_protection"`
	CSRFTokenLength         int           `json:"csrf_token_length" mapstructure:"csrf_token_length"`
	EnableSQLInjectionCheck bool          `json:"enable_sql_injection_check" mapstructure:"enable_sql_injection_check"`
	EnableXSSProtection     bool          `json:"enable_xss_protection" mapstructure:"enable_xss_protection"`
	EnableSecurityHeaders   bool          `json:"enable_security_headers" mapstructure:"enable_security_headers"`
	EnableAuditLogging      bool          `json:"enable_audit_logging" mapstructure:"enable_audit_logging"`
	MaxUploadSize           int64         `json:"max_upload_size" mapstructure:"max_upload_size"`
	AllowedFileTypes        []string      `json:"allowed_file_types" mapstructure:"allowed_file_types"`
	EnableMaintenance       bool          `json:"enable_maintenance" mapstructure:"enable_maintenance"`
	MaintenanceMessage      string        `json:"maintenance_message" mapstructure:"maintenance_message"`
}

type SecretsConfig struct {
	Provider         string             `json:"provider" mapstructure:"provider"`
	EncryptionKey    string             `json:"encryption_key" mapstructure:"encryption_key"`
	VaultConfig      VaultConfig        `json:"vault" mapstructure:"vault"`
	AWSConfig        AWSSecretsConfig   `json:"aws" mapstructure:"aws"`
	LocalConfig      LocalSecretsConfig `json:"local" mapstructure:"local"`
	RefreshInterval  time.Duration      `json:"refresh_interval" mapstructure:"refresh_interval"`
	CacheTimeout     time.Duration      `json:"cache_timeout" mapstructure:"cache_timeout"`
	EnableEncryption bool               `json:"enable_encryption" mapstructure:"enable_encryption"`
}

type VaultConfig struct {
	Address    string `json:"address" mapstructure:"address"`
	Token      string `json:"token" mapstructure:"token"`
	Path       string `json:"path" mapstructure:"path"`
	Namespace  string `json:"namespace" mapstructure:"namespace"`
	EnableTLS  bool   `json:"enable_tls" mapstructure:"enable_tls"`
	CACert     string `json:"ca_cert" mapstructure:"ca_cert"`
	ClientCert string `json:"client_cert" mapstructure:"client_cert"`
	ClientKey  string `json:"client_key" mapstructure:"client_key"`
}

type AWSSecretsConfig struct {
	Region    string `json:"region" mapstructure:"region"`
	AccessKey string `json:"access_key" mapstructure:"access_key"`
	SecretKey string `json:"secret_key" mapstructure:"secret_key"`
	Profile   string `json:"profile" mapstructure:"profile"`
}

type LocalSecretsConfig struct {
	SecretFile    string `json:"secret_file" mapstructure:"secret_file"`
	EncryptedFile string `json:"encrypted_file" mapstructure:"encrypted_file"`
}

type ExternalConfig struct {
	LLMProviders    map[string]LLMProviderConfig `json:"llm_providers" mapstructure:"llm_providers"`
	SMSProviders    map[string]SMSProviderConfig `json:"sms_providers" mapstructure:"sms_providers"`
	EmailProvider   EmailProviderConfig          `json:"email_provider" mapstructure:"email_provider"`
	StorageProvider StorageProviderConfig        `json:"storage_provider" mapstructure:"storage_provider"`
	CacheProvider   CacheProviderConfig          `json:"cache_provider" mapstructure:"cache_provider"`
	QueueProvider   QueueProviderConfig          `json:"queue_provider" mapstructure:"queue_provider"`
}

type LLMProviderConfig struct {
	Provider    string            `json:"provider" mapstructure:"provider"`
	APIKey      string            `json:"api_key" mapstructure:"api_key"`
	APIUrl      string            `json:"api_url" mapstructure:"api_url"`
	Model       string            `json:"model" mapstructure:"model"`
	MaxTokens   int               `json:"max_tokens" mapstructure:"max_tokens"`
	Temperature float64           `json:"temperature" mapstructure:"temperature"`
	Timeout     time.Duration     `json:"timeout" mapstructure:"timeout"`
	RateLimit   int               `json:"rate_limit" mapstructure:"rate_limit"`
	Enabled     bool              `json:"enabled" mapstructure:"enabled"`
	Headers     map[string]string `json:"headers" mapstructure:"headers"`
}

type SMSProviderConfig struct {
	Provider   string `json:"provider" mapstructure:"provider"`
	AccountSID string `json:"account_sid" mapstructure:"account_sid"`
	AuthToken  string `json:"auth_token" mapstructure:"auth_token"`
	FromNumber string `json:"from_number" mapstructure:"from_number"`
	WebhookURL string `json:"webhook_url" mapstructure:"webhook_url"`
	Enabled    bool   `json:"enabled" mapstructure:"enabled"`
}

type EmailProviderConfig struct {
	Provider  string `json:"provider" mapstructure:"provider"`
	SMTPHost  string `json:"smtp_host" mapstructure:"smtp_host"`
	SMTPPort  int    `json:"smtp_port" mapstructure:"smtp_port"`
	Username  string `json:"username" mapstructure:"username"`
	Password  string `json:"password" mapstructure:"password"`
	FromEmail string `json:"from_email" mapstructure:"from_email"`
	FromName  string `json:"from_name" mapstructure:"from_name"`
	EnableTLS bool   `json:"enable_tls" mapstructure:"enable_tls"`
	Enabled   bool   `json:"enabled" mapstructure:"enabled"`
}

type StorageProviderConfig struct {
	Provider  string `json:"provider" mapstructure:"provider"`
	Bucket    string `json:"bucket" mapstructure:"bucket"`
	Region    string `json:"region" mapstructure:"region"`
	AccessKey string `json:"access_key" mapstructure:"access_key"`
	SecretKey string `json:"secret_key" mapstructure:"secret_key"`
	Endpoint  string `json:"endpoint" mapstructure:"endpoint"`
	EnableSSL bool   `json:"enable_ssl" mapstructure:"enable_ssl"`
	Enabled   bool   `json:"enabled" mapstructure:"enabled"`
}

type CacheProviderConfig struct {
	Provider    string        `json:"provider" mapstructure:"provider"`
	Address     string        `json:"address" mapstructure:"address"`
	Password    string        `json:"password" mapstructure:"password"`
	Database    int           `json:"database" mapstructure:"database"`
	MaxRetries  int           `json:"max_retries" mapstructure:"max_retries"`
	PoolSize    int           `json:"pool_size" mapstructure:"pool_size"`
	IdleTimeout time.Duration `json:"idle_timeout" mapstructure:"idle_timeout"`
	Enabled     bool          `json:"enabled" mapstructure:"enabled"`
}

type QueueProviderConfig struct {
	Provider string `json:"provider" mapstructure:"provider"`
	URL      string `json:"url" mapstructure:"url"`
	Username string `json:"username" mapstructure:"username"`
	Password string `json:"password" mapstructure:"password"`
	VHost    string `json:"vhost" mapstructure:"vhost"`
	Exchange string `json:"exchange" mapstructure:"exchange"`
	Enabled  bool   `json:"enabled" mapstructure:"enabled"`
}

// ConfigManager manages the complete configuration lifecycle
type ConfigManager struct {
	config        *Config
	secretManager SecretManagerInterface
	logger        *zap.SugaredLogger
}

// SecretManagerInterface defines the interface for secret management
type SecretManagerInterface interface {
	DecryptSecret(encrypted string) (string, error)
	EncryptSecret(plaintext string) (string, error)
	IsEncrypted(value string) bool
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(logger *zap.SugaredLogger) *ConfigManager {
	return &ConfigManager{
		logger: logger,
	}
}

// Load loads and processes the complete configuration
func (cm *ConfigManager) Load() (*Config, error) {
	// Load configuration from various sources
	config, err := cm.loadConfiguration()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize secret manager if encryption key is available
	if config.Security.EncryptionKey != "" {
		secretManager, err := NewSecretManager(config.Security.EncryptionKey, cm.logger)
		if err != nil {
			cm.logger.Warnf("Failed to initialize secret manager: %v", err)
		} else {
			cm.secretManager = secretManager
		}
	}

	// Process secrets in configuration
	if cm.secretManager != nil {
		if err := cm.processSecrets(config); err != nil {
			return nil, fmt.Errorf("failed to process secrets: %w", err)
		}
	}

	// Validate final configuration
	if err := cm.validateConfiguration(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	cm.config = config
	cm.logger.Info("Configuration loaded and validated successfully")

	return config, nil
}

// loadConfiguration loads configuration from multiple sources
func (cm *ConfigManager) loadConfiguration() (*Config, error) {
	// Initialize viper
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("../config")
	viper.AddConfigPath("../../config")

	// Environment-specific configuration
	env := GetEnvironment()
	if env != "development" {
		viper.SetConfigName(env)
	}

	// Set defaults
	cm.setDefaults()

	// Enable environment variables
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		cm.logger.Warn("Configuration file not found, using defaults and environment variables")
	} else {
		cm.logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	}

	// Unmarshal configuration
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	return &config, nil
}

// processSecrets handles secret decryption in configuration
func (cm *ConfigManager) processSecrets(config *Config) error {
	// Database secrets
	if decrypted, err := cm.secretManager.DecryptSecret(config.Database.Password); err != nil {
		return fmt.Errorf("failed to decrypt database password: %w", err)
	} else {
		config.Database.Password = decrypted
	}

	if decrypted, err := cm.secretManager.DecryptSecret(config.Database.EncryptionKey); err != nil {
		return fmt.Errorf("failed to decrypt database encryption key: %w", err)
	} else {
		config.Database.EncryptionKey = decrypted
	}

	// Auth secrets
	if decrypted, err := cm.secretManager.DecryptSecret(config.Auth.JWTSecret); err != nil {
		return fmt.Errorf("failed to decrypt JWT secret: %w", err)
	} else {
		config.Auth.JWTSecret = decrypted
	}

	// External service secrets
	for name, provider := range config.External.LLMProviders {
		if decrypted, err := cm.secretManager.DecryptSecret(provider.APIKey); err != nil {
			cm.logger.Warnf("Failed to decrypt LLM provider %s API key: %v", name, err)
		} else {
			provider.APIKey = decrypted
			config.External.LLMProviders[name] = provider
		}
	}

	for name, provider := range config.External.SMSProviders {
		if decrypted, err := cm.secretManager.DecryptSecret(provider.AuthToken); err != nil {
			cm.logger.Warnf("Failed to decrypt SMS provider %s auth token: %v", name, err)
		} else {
			provider.AuthToken = decrypted
			config.External.SMSProviders[name] = provider
		}
	}

	// Email provider
	if decrypted, err := cm.secretManager.DecryptSecret(config.External.EmailProvider.Password); err != nil {
		cm.logger.Warnf("Failed to decrypt email provider password: %v", err)
	} else {
		config.External.EmailProvider.Password = decrypted
	}

	// Storage provider
	if decrypted, err := cm.secretManager.DecryptSecret(config.External.StorageProvider.AccessKey); err != nil {
		cm.logger.Warnf("Failed to decrypt storage provider access key: %v", err)
	} else {
		config.External.StorageProvider.AccessKey = decrypted
	}

	if decrypted, err := cm.secretManager.DecryptSecret(config.External.StorageProvider.SecretKey); err != nil {
		cm.logger.Warnf("Failed to decrypt storage provider secret key: %v", err)
	} else {
		config.External.StorageProvider.SecretKey = decrypted
	}

	// Cache provider
	if decrypted, err := cm.secretManager.DecryptSecret(config.External.CacheProvider.Password); err != nil {
		cm.logger.Warnf("Failed to decrypt cache provider password: %v", err)
	} else {
		config.External.CacheProvider.Password = decrypted
	}

	// Queue provider
	if decrypted, err := cm.secretManager.DecryptSecret(config.External.QueueProvider.Password); err != nil {
		cm.logger.Warnf("Failed to decrypt queue provider password: %v", err)
	} else {
		config.External.QueueProvider.Password = decrypted
	}

	return nil
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *Config {
	return cm.config
}

// GetSecretManager returns the secret manager
func (cm *ConfigManager) GetSecretManager() SecretManagerInterface {
	return cm.secretManager
}

// ReloadConfig reloads the configuration
func (cm *ConfigManager) ReloadConfig() error {
	newConfig, err := cm.Load()
	if err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}

	cm.config = newConfig
	cm.logger.Info("Configuration reloaded successfully")
	return nil
}

// GetEnvironment returns the current environment
func GetEnvironment() string {
	env := viper.GetString("ENVIRONMENT")
	if env == "" {
		env = "development"
	}
	return env
}

// Simple SecretManager implementation for config processing
type SimpleSecretManager struct {
	encryptionKey string
}

// NewSecretManager creates a simple secret manager for config processing
func NewSecretManager(encryptionKey string, logger *zap.SugaredLogger) (*SimpleSecretManager, error) {
	return &SimpleSecretManager{
		encryptionKey: encryptionKey,
	}, nil
}

// DecryptSecret decrypts a secret if it's encrypted
func (sm *SimpleSecretManager) DecryptSecret(encrypted string) (string, error) {
	if !sm.IsEncrypted(encrypted) {
		return encrypted, nil
	}
	// Implementation would decrypt here - for now return as-is
	return strings.TrimPrefix(encrypted, "enc:"), nil
}

// EncryptSecret encrypts a secret
func (sm *SimpleSecretManager) EncryptSecret(plaintext string) (string, error) {
	// Implementation would encrypt here - for now add prefix
	return "enc:" + plaintext, nil
}

// IsEncrypted checks if a value is encrypted
func (sm *SimpleSecretManager) IsEncrypted(value string) bool {
	return strings.HasPrefix(value, "enc:")
}
