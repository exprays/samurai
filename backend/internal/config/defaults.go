package config

import (
	"github.com/spf13/viper"
)

// setDefaults sets all default configuration values
func (cm *ConfigManager) setDefaults() {
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
	viper.SetDefault("database.user", "mcpuser")
	viper.SetDefault("database.password", "mcppassword")
	viper.SetDefault("database.dbname", "mcpserver")
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
	viper.SetDefault("logger.max_size", 100)
	viper.SetDefault("logger.max_backups", 10)
	viper.SetDefault("logger.max_age", 30)
	viper.SetDefault("logger.compress", true)
	viper.SetDefault("logger.enable_console", true)
	viper.SetDefault("logger.enable_file", true)
	viper.SetDefault("logger.enable_syslog", false)

	// Auth defaults
	viper.SetDefault("auth.jwt_secret", "default-jwt-secret-change-in-production")
	viper.SetDefault("auth.token_duration", "1h")
	viper.SetDefault("auth.refresh_token_duration", "720h")
	viper.SetDefault("auth.jwt_issuer", "samurai-server")
	viper.SetDefault("auth.jwt_audience", "samurai-users")
	viper.SetDefault("auth.password_salt_cost", 12)
	viper.SetDefault("auth.enable_two_factor", false)
	viper.SetDefault("auth.enable_oauth", false)
	viper.SetDefault("auth.session_timeout", "24h")
	viper.SetDefault("auth.max_login_attempts", 5)
	viper.SetDefault("auth.lockout_duration", "15m")

	// Security defaults
	viper.SetDefault("security.enable_rate_limiting", true)
	viper.SetDefault("security.rate_limit_requests", 100)
	viper.SetDefault("security.rate_limit_window", "1m")
	viper.SetDefault("security.enable_csrf_protection", true)
	viper.SetDefault("security.csrf_token_length", 32)
	viper.SetDefault("security.enable_security_headers", true)
	viper.SetDefault("security.enable_audit_logging", true)
	viper.SetDefault("security.max_upload_size", 10485760)

	// Secrets defaults
	viper.SetDefault("secrets.provider", "local")
	viper.SetDefault("secrets.refresh_interval", "5m")
	viper.SetDefault("secrets.cache_timeout", "1h")
	viper.SetDefault("secrets.enable_encryption", true)
	viper.SetDefault("secrets.local.secret_file", "config/secrets.json")
	viper.SetDefault("secrets.local.encrypted_file", "config/secrets.enc")

	// External services defaults
	cm.setExternalDefaults()
}

// setExternalDefaults sets defaults for external service configurations
func (cm *ConfigManager) setExternalDefaults() {
	// LLM Provider defaults
	viper.SetDefault("external.llm_providers.openai.provider", "openai")
	viper.SetDefault("external.llm_providers.openai.api_url", "https://api.openai.com/v1")
	viper.SetDefault("external.llm_providers.openai.model", "gpt-4")
	viper.SetDefault("external.llm_providers.openai.max_tokens", 4096)
	viper.SetDefault("external.llm_providers.openai.temperature", 0.7)
	viper.SetDefault("external.llm_providers.openai.timeout", "30s")
	viper.SetDefault("external.llm_providers.openai.rate_limit", 60)
	viper.SetDefault("external.llm_providers.openai.enabled", false)

	// SMS Provider defaults
	viper.SetDefault("external.sms_providers.twilio.provider", "twilio")
	viper.SetDefault("external.sms_providers.twilio.enabled", false)

	// Email provider defaults
	viper.SetDefault("external.email_provider.provider", "smtp")
	viper.SetDefault("external.email_provider.smtp_port", 587)
	viper.SetDefault("external.email_provider.enable_tls", true)
	viper.SetDefault("external.email_provider.enabled", false)

	// Cache provider defaults
	viper.SetDefault("external.cache_provider.provider", "redis")
	viper.SetDefault("external.cache_provider.address", "localhost:6379")
	viper.SetDefault("external.cache_provider.database", 0)
	viper.SetDefault("external.cache_provider.enabled", false)

	// Queue provider defaults
	viper.SetDefault("external.queue_provider.provider", "rabbitmq")
	viper.SetDefault("external.queue_provider.enabled", false)
}
