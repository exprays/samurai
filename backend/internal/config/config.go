package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Logger   LoggerConfig   `mapstructure:"logger"`
	Auth     AuthConfig     `mapstructure:"auth"`
}

type ServerConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	Environment  string `mapstructure:"environment"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
}

type DatabaseConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	DBName       string `mapstructure:"dbname"`
	SSLMode      string `mapstructure:"sslmode"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
}

type LoggerConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	OutputPath string `mapstructure:"output_path"`
}

type AuthConfig struct {
	JWTSecret     string `mapstructure:"jwt_secret"`
	TokenDuration int    `mapstructure:"token_duration"`
}

func Load() (*Config, error) {
	// Set defaults first
	setDefaults()

	// Enable environment variable override
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Try to read config file (optional)
	viper.SetConfigName("development")
	viper.SetConfigType("json")
	viper.AddConfigPath("../config")    // From backend/ directory
	viper.AddConfigPath("../../config") // From backend/cmd/server/ directory
	viper.AddConfigPath("./config")     // From root directory
	viper.AddConfigPath(".")

	// Reading config file is optional - we can work with just env vars
	if err := viper.ReadInConfig(); err != nil {
		// Config file not found is OK, we'll use defaults + env vars
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.environment", "development")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "mcpuser")
	viper.SetDefault("database.password", "mcppassword")
	viper.SetDefault("database.dbname", "mcpserver")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)

	viper.SetDefault("logger.level", "info")
	viper.SetDefault("logger.format", "json")
	viper.SetDefault("logger.output_path", "stdout")

	viper.SetDefault("auth.jwt_secret", "change-me-in-production")
	viper.SetDefault("auth.token_duration", 24) // hours
}
