package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	Security  SecurityConfig  `mapstructure:"security"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
	CORS      CORSConfig      `mapstructure:"cors"`
}

type ServerConfig struct {
	Port        int    `mapstructure:"port" validate:"required,min=1,max=65535"`
	Host        string `mapstructure:"host" validate:"required"`
	Environment string `mapstructure:"environment" validate:"required,oneof=development staging production"`
}

type DatabaseConfig struct {
	Host         string `mapstructure:"host" validate:"required"`
	Port         int    `mapstructure:"port" validate:"required,min=1,max=65535"`
	User         string `mapstructure:"user" validate:"required"`
	Password     string `mapstructure:"password" validate:"required"`
	Name         string `mapstructure:"name" validate:"required"`
	SSLMode      string `mapstructure:"ssl_mode" validate:"required,oneof=disable require verify-ca verify-full"`
	MaxOpenConns int    `mapstructure:"max_open_conns" validate:"min=1"`
	MaxIdleConns int    `mapstructure:"max_idle_conns" validate:"min=1"`
}

type JWTConfig struct {
	Secret             string        `mapstructure:"secret" validate:"required,min=32"`
	AccessTokenExpiry  time.Duration `mapstructure:"access_token_expiry" validate:"required"`
	RefreshTokenExpiry time.Duration `mapstructure:"refresh_token_expiry" validate:"required"`
	Issuer             string        `mapstructure:"issuer" validate:"required"`
}

type SecurityConfig struct {
	BcryptCost        int `mapstructure:"bcrypt_cost" validate:"min=10,max=15"`
	PasswordMinLength int `mapstructure:"password_min_length" validate:"min=8"`
}

type RateLimitConfig struct {
	Requests int           `mapstructure:"requests" validate:"min=1"`
	Window   time.Duration `mapstructure:"window" validate:"required"`
	Burst    int           `mapstructure:"burst" validate:"min=1"`
}

type LoggingConfig struct {
	Level    string `mapstructure:"level" validate:"required,oneof=debug info warn error"`
	Format   string `mapstructure:"format" validate:"required,oneof=json console"`
	FilePath string `mapstructure:"file_path"`
}

type MetricsConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Port    int  `mapstructure:"port" validate:"min=1,max=65535"`
}

type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	// Environment variable bindings
	viper.SetEnvPrefix("SAMURAI")
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.environment", "development")

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)

	// JWT defaults
	viper.SetDefault("jwt.access_token_expiry", "15m")
	viper.SetDefault("jwt.refresh_token_expiry", "7d")
	viper.SetDefault("jwt.issuer", "samurai-mcp-server")

	// Security defaults
	viper.SetDefault("security.bcrypt_cost", 12)
	viper.SetDefault("security.password_min_length", 8)

	// Rate limit defaults
	viper.SetDefault("rate_limit.requests", 100)
	viper.SetDefault("rate_limit.window", "1h")
	viper.SetDefault("rate_limit.burst", 10)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.file_path", "logs/app.log")

	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.port", 9090)

	// CORS defaults
	viper.SetDefault("cors.allowed_origins", []string{"http://localhost:3000"})
	viper.SetDefault("cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("cors.allowed_headers", []string{"Content-Type", "Authorization", "X-Requested-With"})
}
