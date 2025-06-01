package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `json:"server" mapstructure:"server"`
	Database DatabaseConfig `json:"database" mapstructure:"database"`
	Logger   LoggerConfig   `json:"logger" mapstructure:"logger"`
	Auth     AuthConfig     `json:"auth" mapstructure:"auth"`
}

type ServerConfig struct {
	Host         string `json:"host" mapstructure:"host"`
	Port         int    `json:"port" mapstructure:"port"`
	Environment  string `json:"environment" mapstructure:"environment"`
	ReadTimeout  int    `json:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout int    `json:"write_timeout" mapstructure:"write_timeout"`
}

type DatabaseConfig struct {
	Host         string `json:"host" mapstructure:"host"`
	Port         int    `json:"port" mapstructure:"port"`
	User         string `json:"user" mapstructure:"user"`
	Password     string `json:"password" mapstructure:"password"`
	DBName       string `json:"dbname" mapstructure:"dbname"`
	SSLMode      string `json:"sslmode" mapstructure:"sslmode"`
	MaxOpenConns int    `json:"max_open_conns" mapstructure:"max_open_conns"`
	MaxIdleConns int    `json:"max_idle_conns" mapstructure:"max_idle_conns"`
}

type LoggerConfig struct {
	Level      string `json:"level" mapstructure:"level"`
	Format     string `json:"format" mapstructure:"format"`
	OutputPath string `json:"output_path" mapstructure:"output_path"`
}

// Add AuthConfig struct
type AuthConfig struct {
	JWTSecret     string `json:"jwt_secret" mapstructure:"jwt_secret"`
	TokenDuration int    `json:"token_duration" mapstructure:"token_duration"`
}

func Load() (*Config, error) {
	viper.SetConfigName("development")
	viper.SetConfigType("json")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("../config")
	viper.AddConfigPath("../../config")

	// Set default values
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.environment", "development")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)

	viper.SetDefault("logger.level", "info")
	viper.SetDefault("logger.format", "json")
	viper.SetDefault("logger.output_path", "logs/app.log")

	// Auth defaults
	viper.SetDefault("auth.jwt_secret", "change-me-in-production")
	viper.SetDefault("auth.token_duration", 24)

	// Enable environment variable reading
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}
