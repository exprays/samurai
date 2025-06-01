package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	ErrEncryptionKeyNotSet = errors.New("encryption key not set")
	ErrInvalidSecretFormat = errors.New("invalid secret format")
	ErrDecryptionFailed    = errors.New("decryption failed")
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

// SecretManager handles encryption/decryption of secrets
type SecretManager struct {
	encryptionKey []byte
	logger        *zap.SugaredLogger
}

// NewSecretManager creates a new secret manager
func NewSecretManager(encryptionKey string, logger *zap.SugaredLogger) (*SecretManager, error) {
	if encryptionKey == "" {
		return nil, ErrEncryptionKeyNotSet
	}

	// Create 32-byte key from provided key
	hash := sha256.Sum256([]byte(encryptionKey))

	return &SecretManager{
		encryptionKey: hash[:],
		logger:        logger,
	}, nil
}

// EncryptSecret encrypts a plaintext secret
func (sm *SecretManager) EncryptSecret(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecret decrypts an encrypted secret
func (sm *SecretManager) DecryptSecret(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}

	// Check if it's an encrypted value (starts with "enc:")
	if !strings.HasPrefix(encrypted, "enc:") {
		return encrypted, nil // Not encrypted, return as-is
	}

	// Remove "enc:" prefix
	encrypted = strings.TrimPrefix(encrypted, "enc:")

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(ciphertext) < 12 {
		return "", ErrInvalidSecretFormat
	}

	// Extract nonce and ciphertext
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]

	// Create cipher
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}

// IsEncrypted checks if a value is encrypted
func (sm *SecretManager) IsEncrypted(value string) bool {
	return strings.HasPrefix(value, "enc:")
}

// Load loads configuration with secrets management
func Load() (*Config, error) {
	// Set configuration paths
	viper.SetConfigName("development")
	viper.SetConfigType("json")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("../config")
	viper.AddConfigPath("../../config")

	// Environment-specific configuration
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	// Try to load environment-specific config
	viper.SetConfigName(env)

	// Set all default values
	setDefaults()

	// Enable environment variable reading with automatic substitution
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		// Config file not found is not fatal
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Unmarshal into config struct
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Initialize secret manager if encryption key is provided
	if config.Security.EncryptionKey != "" {
		logger, _ := zap.NewDevelopment()
		secretManager, err := NewSecretManager(config.Security.EncryptionKey, logger.Sugar())
		if err != nil {
			return nil, fmt.Errorf("failed to initialize secret manager: %w", err)
		}

		// Decrypt secrets in configuration
		if err := decryptConfigSecrets(&config, secretManager); err != nil {
			return nil, fmt.Errorf("failed to decrypt secrets: %w", err)
		}
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets all default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.environment", "development")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)
	viper.SetDefault("server.graceful_timeout", 30)
	viper.SetDefault("server.health_check_path", "/health")
	viper.SetDefault("server.metrics_path", "/metrics")
	viper.SetDefault("server.enable_metrics", false)
	viper.SetDefault("server.enable_profiling", false)
	viper.SetDefault("server.enable_tls", false)
	viper.SetDefault("server.trusted_proxies", []string{})
	viper.SetDefault("server.allowed_hosts", []string{})
	viper.SetDefault("server.cors_origins", []string{"*"})

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "")
	viper.SetDefault("database.dbname", "samurai")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 10)
	viper.SetDefault("database.conn_max_lifetime", "1h")
	viper.SetDefault("database.conn_max_idle_time", "30m")
	viper.SetDefault("database.enable_logging", false)
	viper.SetDefault("database.slow_query_time", "1s")
	viper.SetDefault("database.retry_attempts", 3)
	viper.SetDefault("database.retry_delay", "5s")
	viper.SetDefault("database.enable_migrations", true)

	// Logger defaults
	viper.SetDefault("logger.level", "info")
	viper.SetDefault("logger.format", "json")
	viper.SetDefault("logger.output_path", "logs/app.log")
	viper.SetDefault("logger.error_output_path", "logs/error.log")
	viper.SetDefault("logger.max_size", 100) // MB
	viper.SetDefault("logger.max_backups", 10)
	viper.SetDefault("logger.max_age", 30) // days
	viper.SetDefault("logger.compress", true)
	viper.SetDefault("logger.enable_console", true)
	viper.SetDefault("logger.enable_file", true)
	viper.SetDefault("logger.enable_syslog", false)
	viper.SetDefault("logger.syslog_network", "udp")
	viper.SetDefault("logger.syslog_address", "localhost:514")
	viper.SetDefault("logger.syslog_tag", "samurai")
	viper.SetDefault("logger.enable_sampling", false)
	viper.SetDefault("logger.sampling_initial", 100)
	viper.SetDefault("logger.sampling_interval", 100)

	// Auth defaults
	viper.SetDefault("auth.jwt_secret", "")
	viper.SetDefault("auth.token_duration", "24h")
	viper.SetDefault("auth.refresh_token_duration", "720h") // 30 days
	viper.SetDefault("auth.jwt_issuer", "samurai-server")
	viper.SetDefault("auth.jwt_audience", "samurai-users")
	viper.SetDefault("auth.password_salt_cost", 12)
	viper.SetDefault("auth.enable_two_factor", false)
	viper.SetDefault("auth.enable_oauth", false)
	viper.SetDefault("auth.oauth_providers", []string{})
	viper.SetDefault("auth.session_timeout", "24h")
	viper.SetDefault("auth.max_login_attempts", 5)
	viper.SetDefault("auth.lockout_duration", "15m")

	// Auth password policy defaults
	viper.SetDefault("auth.password_policy.min_length", 8)
	viper.SetDefault("auth.password_policy.require_uppercase", true)
	viper.SetDefault("auth.password_policy.require_lowercase", true)
	viper.SetDefault("auth.password_policy.require_numbers", true)
	viper.SetDefault("auth.password_policy.require_special_chars", true)
	viper.SetDefault("auth.password_policy.forbid_common", true)
	viper.SetDefault("auth.password_policy.min_score", 3)

	// Security defaults
	viper.SetDefault("security.encryption_key", "")
	viper.SetDefault("security.enable_rate_limiting", true)
	viper.SetDefault("security.rate_limit_requests", 100)
	viper.SetDefault("security.rate_limit_window", "1m")
	viper.SetDefault("security.enable_ip_whitelist", false)
	viper.SetDefault("security.whitelisted_ips", []string{})
	viper.SetDefault("security.enable_ip_blacklist", false)
	viper.SetDefault("security.blacklisted_ips", []string{})
	viper.SetDefault("security.enable_csrf_protection", true)
	viper.SetDefault("security.csrf_token_length", 32)
	viper.SetDefault("security.enable_sql_injection_check", true)
	viper.SetDefault("security.enable_xss_protection", true)
	viper.SetDefault("security.enable_security_headers", true)
	viper.SetDefault("security.enable_audit_logging", true)
	viper.SetDefault("security.max_upload_size", 10485760) // 10MB
	viper.SetDefault("security.allowed_file_types", []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx"})
	viper.SetDefault("security.enable_maintenance", false)
	viper.SetDefault("security.maintenance_message", "System is under maintenance. Please try again later.")

	// Secrets defaults
	viper.SetDefault("secrets.provider", "local")
	viper.SetDefault("secrets.encryption_key", "")
	viper.SetDefault("secrets.refresh_interval", "5m")
	viper.SetDefault("secrets.cache_timeout", "1h")
	viper.SetDefault("secrets.enable_encryption", true)

	// Vault defaults
	viper.SetDefault("secrets.vault.address", "http://localhost:8200")
	viper.SetDefault("secrets.vault.token", "")
	viper.SetDefault("secrets.vault.path", "secret/samurai")
	viper.SetDefault("secrets.vault.namespace", "")
	viper.SetDefault("secrets.vault.enable_tls", false)

	// AWS Secrets defaults
	viper.SetDefault("secrets.aws.region", "us-east-1")
	viper.SetDefault("secrets.aws.access_key", "")
	viper.SetDefault("secrets.aws.secret_key", "")
	viper.SetDefault("secrets.aws.profile", "default")

	// Local secrets defaults
	viper.SetDefault("secrets.local.secret_file", "secrets.json")
	viper.SetDefault("secrets.local.encrypted_file", "secrets.enc")

	// External services defaults
	setExternalDefaults()
}

// setExternalDefaults sets defaults for external service configurations
func setExternalDefaults() {
	// LLM Provider defaults
	viper.SetDefault("external.llm_providers.openai.provider", "openai")
	viper.SetDefault("external.llm_providers.openai.api_url", "https://api.openai.com/v1")
	viper.SetDefault("external.llm_providers.openai.model", "gpt-4")
	viper.SetDefault("external.llm_providers.openai.max_tokens", 4096)
	viper.SetDefault("external.llm_providers.openai.temperature", 0.7)
	viper.SetDefault("external.llm_providers.openai.timeout", "30s")
	viper.SetDefault("external.llm_providers.openai.rate_limit", 60)
	viper.SetDefault("external.llm_providers.openai.enabled", false)

	viper.SetDefault("external.llm_providers.anthropic.provider", "anthropic")
	viper.SetDefault("external.llm_providers.anthropic.api_url", "https://api.anthropic.com/v1")
	viper.SetDefault("external.llm_providers.anthropic.model", "claude-3-opus")
	viper.SetDefault("external.llm_providers.anthropic.max_tokens", 4096)
	viper.SetDefault("external.llm_providers.anthropic.temperature", 0.7)
	viper.SetDefault("external.llm_providers.anthropic.timeout", "30s")
	viper.SetDefault("external.llm_providers.anthropic.rate_limit", 60)
	viper.SetDefault("external.llm_providers.anthropic.enabled", false)

	// SMS Provider defaults
	viper.SetDefault("external.sms_providers.twilio.provider", "twilio")
	viper.SetDefault("external.sms_providers.twilio.enabled", false)

	// Email provider defaults
	viper.SetDefault("external.email_provider.provider", "smtp")
	viper.SetDefault("external.email_provider.smtp_port", 587)
	viper.SetDefault("external.email_provider.enable_tls", true)
	viper.SetDefault("external.email_provider.enabled", false)

	// Storage provider defaults
	viper.SetDefault("external.storage_provider.provider", "local")
	viper.SetDefault("external.storage_provider.enable_ssl", true)
	viper.SetDefault("external.storage_provider.enabled", false)

	// Cache provider defaults
	viper.SetDefault("external.cache_provider.provider", "redis")
	viper.SetDefault("external.cache_provider.address", "localhost:6379")
	viper.SetDefault("external.cache_provider.database", 0)
	viper.SetDefault("external.cache_provider.max_retries", 3)
	viper.SetDefault("external.cache_provider.pool_size", 10)
	viper.SetDefault("external.cache_provider.idle_timeout", "5m")
	viper.SetDefault("external.cache_provider.enabled", false)

	// Queue provider defaults
	viper.SetDefault("external.queue_provider.provider", "rabbitmq")
	viper.SetDefault("external.queue_provider.vhost", "/")
	viper.SetDefault("external.queue_provider.exchange", "samurai")
	viper.SetDefault("external.queue_provider.enabled", false)
}

// decryptConfigSecrets decrypts all encrypted secrets in the configuration
func decryptConfigSecrets(config *Config, secretManager *SecretManager) error {
	// Decrypt database password
	if decryptedPassword, err := secretManager.DecryptSecret(config.Database.Password); err != nil {
		return fmt.Errorf("failed to decrypt database password: %w", err)
	} else {
		config.Database.Password = decryptedPassword
	}

	// Decrypt database encryption key
	if decryptedKey, err := secretManager.DecryptSecret(config.Database.EncryptionKey); err != nil {
		return fmt.Errorf("failed to decrypt database encryption key: %w", err)
	} else {
		config.Database.EncryptionKey = decryptedKey
	}

	// Decrypt JWT secret
	if decryptedSecret, err := secretManager.DecryptSecret(config.Auth.JWTSecret); err != nil {
		return fmt.Errorf("failed to decrypt JWT secret: %w", err)
	} else {
		config.Auth.JWTSecret = decryptedSecret
	}

	// Decrypt Vault token
	if decryptedToken, err := secretManager.DecryptSecret(config.Secrets.VaultConfig.Token); err != nil {
		return fmt.Errorf("failed to decrypt Vault token: %w", err)
	} else {
		config.Secrets.VaultConfig.Token = decryptedToken
	}

	// Decrypt AWS credentials
	if decryptedAccessKey, err := secretManager.DecryptSecret(config.Secrets.AWSConfig.AccessKey); err != nil {
		return fmt.Errorf("failed to decrypt AWS access key: %w", err)
	} else {
		config.Secrets.AWSConfig.AccessKey = decryptedAccessKey
	}

	if decryptedSecretKey, err := secretManager.DecryptSecret(config.Secrets.AWSConfig.SecretKey); err != nil {
		return fmt.Errorf("failed to decrypt AWS secret key: %w", err)
	} else {
		config.Secrets.AWSConfig.SecretKey = decryptedSecretKey
	}

	// Decrypt LLM provider API keys
	for name, provider := range config.External.LLMProviders {
		if decryptedAPIKey, err := secretManager.DecryptSecret(provider.APIKey); err != nil {
			return fmt.Errorf("failed to decrypt LLM provider %s API key: %w", name, err)
		} else {
			provider.APIKey = decryptedAPIKey
			config.External.LLMProviders[name] = provider
		}
	}

	// Decrypt SMS provider credentials
	for name, provider := range config.External.SMSProviders {
		if decryptedAuthToken, err := secretManager.DecryptSecret(provider.AuthToken); err != nil {
			return fmt.Errorf("failed to decrypt SMS provider %s auth token: %w", name, err)
		} else {
			provider.AuthToken = decryptedAuthToken
			config.External.SMSProviders[name] = provider
		}
	}

	// Decrypt email provider password
	if decryptedPassword, err := secretManager.DecryptSecret(config.External.EmailProvider.Password); err != nil {
		return fmt.Errorf("failed to decrypt email provider password: %w", err)
	} else {
		config.External.EmailProvider.Password = decryptedPassword
	}

	// Decrypt storage provider credentials
	if decryptedAccessKey, err := secretManager.DecryptSecret(config.External.StorageProvider.AccessKey); err != nil {
		return fmt.Errorf("failed to decrypt storage provider access key: %w", err)
	} else {
		config.External.StorageProvider.AccessKey = decryptedAccessKey
	}

	if decryptedSecretKey, err := secretManager.DecryptSecret(config.External.StorageProvider.SecretKey); err != nil {
		return fmt.Errorf("failed to decrypt storage provider secret key: %w", err)
	} else {
		config.External.StorageProvider.SecretKey = decryptedSecretKey
	}

	// Decrypt cache provider password
	if decryptedPassword, err := secretManager.DecryptSecret(config.External.CacheProvider.Password); err != nil {
		return fmt.Errorf("failed to decrypt cache provider password: %w", err)
	} else {
		config.External.CacheProvider.Password = decryptedPassword
	}

	// Decrypt queue provider password
	if decryptedPassword, err := secretManager.DecryptSecret(config.External.QueueProvider.Password); err != nil {
		return fmt.Errorf("failed to decrypt queue provider password: %w", err)
	} else {
		config.External.QueueProvider.Password = decryptedPassword
	}

	return nil
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate server configuration
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Server.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}

	if config.Server.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}

	// Validate TLS configuration
	if config.Server.EnableTLS {
		if config.Server.TLSCertFile == "" {
			return fmt.Errorf("TLS cert file required when TLS is enabled")
		}
		if config.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file required when TLS is enabled")
		}
	}

	// Validate database configuration
	if config.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	if config.Database.Port <= 0 || config.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d", config.Database.Port)
	}

	if config.Database.User == "" {
		return fmt.Errorf("database user is required")
	}

	if config.Database.DBName == "" {
		return fmt.Errorf("database name is required")
	}

	if config.Database.MaxOpenConns <= 0 {
		return fmt.Errorf("max open connections must be positive")
	}

	if config.Database.MaxIdleConns <= 0 {
		return fmt.Errorf("max idle connections must be positive")
	}

	if config.Database.MaxIdleConns > config.Database.MaxOpenConns {
		return fmt.Errorf("max idle connections cannot exceed max open connections")
	}

	// Validate auth configuration
	if config.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if len(config.Auth.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	if config.Auth.PasswordSaltCost < 4 || config.Auth.PasswordSaltCost > 31 {
		return fmt.Errorf("password salt cost must be between 4 and 31")
	}

	if config.Auth.MaxLoginAttempts <= 0 {
		return fmt.Errorf("max login attempts must be positive")
	}

	// Validate password policy
	if config.Auth.PasswordPolicy.MinLength < 4 {
		return fmt.Errorf("minimum password length must be at least 4")
	}

	if config.Auth.PasswordPolicy.MinScore < 0 || config.Auth.PasswordPolicy.MinScore > 4 {
		return fmt.Errorf("password policy min score must be between 0 and 4")
	}

	// Validate security configuration
	if config.Security.EnableRateLimiting {
		if config.Security.RateLimitRequests <= 0 {
			return fmt.Errorf("rate limit requests must be positive")
		}
	}

	if config.Security.CSRFTokenLength < 16 {
		return fmt.Errorf("CSRF token length must be at least 16")
	}

	if config.Security.MaxUploadSize <= 0 {
		return fmt.Errorf("max upload size must be positive")
	}

	// Validate secrets configuration
	if config.Secrets.Provider == "" {
		return fmt.Errorf("secrets provider is required")
	}

	validProviders := []string{"local", "vault", "aws"}
	providerValid := false
	for _, provider := range validProviders {
		if config.Secrets.Provider == provider {
			providerValid = true
			break
		}
	}
	if !providerValid {
		return fmt.Errorf("invalid secrets provider: %s (valid: %v)", config.Secrets.Provider, validProviders)
	}

	// Validate provider-specific configuration
	switch config.Secrets.Provider {
	case "vault":
		if err := validateVaultConfig(&config.Secrets.VaultConfig); err != nil {
			return fmt.Errorf("vault configuration error: %w", err)
		}
	case "aws":
		if err := validateAWSConfig(&config.Secrets.AWSConfig); err != nil {
			return fmt.Errorf("AWS configuration error: %w", err)
		}
	case "local":
		if err := validateLocalSecretsConfig(&config.Secrets.LocalConfig); err != nil {
			return fmt.Errorf("local secrets configuration error: %w", err)
		}
	}

	// Validate external services configuration
	if err := validateExternalConfig(&config.External); err != nil {
		return fmt.Errorf("external services configuration error: %w", err)
	}

	return nil
}

// validateVaultConfig validates Vault configuration
func validateVaultConfig(config *VaultConfig) error {
	if config.Address == "" {
		return fmt.Errorf("Vault address is required")
	}

	if config.Token == "" {
		return fmt.Errorf("Vault token is required")
	}

	if config.Path == "" {
		return fmt.Errorf("Vault path is required")
	}

	return nil
}

// validateAWSConfig validates AWS Secrets Manager configuration
func validateAWSConfig(config *AWSSecretsConfig) error {
	if config.Region == "" {
		return fmt.Errorf("AWS region is required")
	}

	// Either credentials or profile must be provided
	if config.AccessKey == "" && config.SecretKey == "" && config.Profile == "" {
		return fmt.Errorf("AWS credentials (access_key/secret_key) or profile is required")
	}

	if (config.AccessKey != "" && config.SecretKey == "") || (config.AccessKey == "" && config.SecretKey != "") {
		return fmt.Errorf("both AWS access_key and secret_key must be provided if using credentials")
	}

	return nil
}

// validateLocalSecretsConfig validates local secrets configuration
func validateLocalSecretsConfig(config *LocalSecretsConfig) error {
	if config.SecretFile == "" && config.EncryptedFile == "" {
		return fmt.Errorf("either secret_file or encrypted_file must be specified")
	}

	return nil
}

// validateExternalConfig validates external services configuration
func validateExternalConfig(config *ExternalConfig) error {
	// Validate LLM providers
	for name, provider := range config.LLMProviders {
		if provider.Enabled {
			if provider.APIKey == "" {
				return fmt.Errorf("LLM provider %s requires API key", name)
			}
			if provider.APIUrl == "" {
				return fmt.Errorf("LLM provider %s requires API URL", name)
			}
			if provider.MaxTokens <= 0 {
				return fmt.Errorf("LLM provider %s max_tokens must be positive", name)
			}
			if provider.Temperature < 0 || provider.Temperature > 2 {
				return fmt.Errorf("LLM provider %s temperature must be between 0 and 2", name)
			}
			if provider.RateLimit <= 0 {
				return fmt.Errorf("LLM provider %s rate_limit must be positive", name)
			}
		}
	}

	// Validate SMS providers
	for name, provider := range config.SMSProviders {
		if provider.Enabled {
			if provider.AccountSID == "" {
				return fmt.Errorf("SMS provider %s requires account SID", name)
			}
			if provider.AuthToken == "" {
				return fmt.Errorf("SMS provider %s requires auth token", name)
			}
			if provider.FromNumber == "" {
				return fmt.Errorf("SMS provider %s requires from number", name)
			}
		}
	}

	// Validate email provider
	if config.EmailProvider.Enabled {
		if config.EmailProvider.SMTPHost == "" {
			return fmt.Errorf("email provider requires SMTP host")
		}
		if config.EmailProvider.SMTPPort <= 0 || config.EmailProvider.SMTPPort > 65535 {
			return fmt.Errorf("invalid email provider SMTP port: %d", config.EmailProvider.SMTPPort)
		}
		if config.EmailProvider.Username == "" {
			return fmt.Errorf("email provider requires username")
		}
		if config.EmailProvider.Password == "" {
			return fmt.Errorf("email provider requires password")
		}
		if config.EmailProvider.FromEmail == "" {
			return fmt.Errorf("email provider requires from email")
		}
	}

	// Validate storage provider
	if config.StorageProvider.Enabled {
		if config.StorageProvider.Provider == "" {
			return fmt.Errorf("storage provider type is required")
		}
		if config.StorageProvider.Bucket == "" {
			return fmt.Errorf("storage provider requires bucket name")
		}
	}

	// Validate cache provider
	if config.CacheProvider.Enabled {
		if config.CacheProvider.Address == "" {
			return fmt.Errorf("cache provider requires address")
		}
		if config.CacheProvider.PoolSize <= 0 {
			return fmt.Errorf("cache provider pool size must be positive")
		}
	}

	// Validate queue provider
	if config.QueueProvider.Enabled {
		if config.QueueProvider.URL == "" {
			return fmt.Errorf("queue provider requires URL")
		}
	}

	return nil
}

// GetEnvironment returns the current environment
func (c *Config) GetEnvironment() string {
	return c.Server.Environment
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// IsStaging returns true if running in staging mode
func (c *Config) IsStaging() bool {
	return c.Server.Environment == "staging"
}

// GetServerAddress returns the full server address
func (c *Config) GetServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// GetDatabaseDSN returns the database connection string
func (c *Config) GetDatabaseDSN() string {
	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=UTC",
		c.Database.Host, c.Database.User, c.Database.Password, c.Database.DBName, c.Database.Port, c.Database.SSLMode)
}

// String returns a string representation of the config (with secrets masked)
func (c *Config) String() string {
	// Create a copy for masking
	configCopy := *c

	// Mask sensitive fields
	configCopy.Database.Password = maskSecret(c.Database.Password)
	configCopy.Database.EncryptionKey = maskSecret(c.Database.EncryptionKey)
	configCopy.Auth.JWTSecret = maskSecret(c.Auth.JWTSecret)
	configCopy.Security.EncryptionKey = maskSecret(c.Security.EncryptionKey)
	configCopy.Secrets.EncryptionKey = maskSecret(c.Secrets.EncryptionKey)
	configCopy.Secrets.VaultConfig.Token = maskSecret(c.Secrets.VaultConfig.Token)
	configCopy.Secrets.AWSConfig.AccessKey = maskSecret(c.Secrets.AWSConfig.AccessKey)
	configCopy.Secrets.AWSConfig.SecretKey = maskSecret(c.Secrets.AWSConfig.SecretKey)

	// Mask external service secrets
	for name, provider := range configCopy.External.LLMProviders {
		provider.APIKey = maskSecret(provider.APIKey)
		configCopy.External.LLMProviders[name] = provider
	}

	for name, provider := range configCopy.External.SMSProviders {
		provider.AuthToken = maskSecret(provider.AuthToken)
		configCopy.External.SMSProviders[name] = provider
	}

	configCopy.External.EmailProvider.Password = maskSecret(c.External.EmailProvider.Password)
	configCopy.External.StorageProvider.AccessKey = maskSecret(c.External.StorageProvider.AccessKey)
	configCopy.External.StorageProvider.SecretKey = maskSecret(c.External.StorageProvider.SecretKey)
	configCopy.External.CacheProvider.Password = maskSecret(c.External.CacheProvider.Password)
	configCopy.External.QueueProvider.Password = maskSecret(c.External.QueueProvider.Password)

	return fmt.Sprintf("%+v", configCopy)
}

// maskSecret masks a secret value for logging
func maskSecret(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 6 {
		return "***"
	}
	return secret[:3] + "***" + secret[len(secret)-3:]
}

// LoadFromEnv loads configuration values from environment variables
func LoadFromEnv() (*Config, error) {
	// Set environment variable mappings
	viper.BindEnv("server.host", "SERVER_HOST")
	viper.BindEnv("server.port", "SERVER_PORT")
	viper.BindEnv("server.environment", "ENVIRONMENT")
	viper.BindEnv("database.host", "DB_HOST")
	viper.BindEnv("database.port", "DB_PORT")
	viper.BindEnv("database.user", "DB_USER")
	viper.BindEnv("database.password", "DB_PASSWORD")
	viper.BindEnv("database.dbname", "DB_NAME")
	viper.BindEnv("database.sslmode", "DB_SSLMODE")
	viper.BindEnv("auth.jwt_secret", "JWT_SECRET")
	viper.BindEnv("security.encryption_key", "ENCRYPTION_KEY")
	viper.BindEnv("secrets.encryption_key", "SECRETS_ENCRYPTION_KEY")

	// Bind external service environment variables
	viper.BindEnv("external.llm_providers.openai.api_key", "OPENAI_API_KEY")
	viper.BindEnv("external.llm_providers.anthropic.api_key", "ANTHROPIC_API_KEY")
	viper.BindEnv("external.sms_providers.twilio.account_sid", "TWILIO_ACCOUNT_SID")
	viper.BindEnv("external.sms_providers.twilio.auth_token", "TWILIO_AUTH_TOKEN")
	viper.BindEnv("external.email_provider.password", "EMAIL_PASSWORD")
	viper.BindEnv("external.storage_provider.access_key", "STORAGE_ACCESS_KEY")
	viper.BindEnv("external.storage_provider.secret_key", "STORAGE_SECRET_KEY")
	viper.BindEnv("external.cache_provider.password", "CACHE_PASSWORD")
	viper.BindEnv("external.queue_provider.password", "QUEUE_PASSWORD")

	return Load()
}

// GenerateEncryptionKey generates a new encryption key
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return hex.EncodeToString(key), nil
}
