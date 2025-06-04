package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"
)

func main() {
	var (
		action      = flag.String("action", "", "Action to perform: validate, show, encrypt, decrypt")
		environment = flag.String("env", "development", "Environment to use")
		key         = flag.String("key", "", "Configuration key for encrypt/decrypt operations")
		value       = flag.String("value", "", "Value for encrypt operations")
		format      = flag.String("format", "json", "Output format: json, text")
	)
	flag.Parse()

	if *action == "" {
		fmt.Println("Usage: config -action=<action> [options]")
		fmt.Println("Actions: validate, show, encrypt, decrypt")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Initialize logger
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Set environment
	if *environment != "" {
		os.Setenv("ENVIRONMENT", *environment)
	}

	switch *action {
	case "validate":
		if err := validateConfig(sugar); err != nil {
			fmt.Printf("Configuration validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration is valid")

	case "show":
		if err := showConfig(sugar, *format); err != nil {
			fmt.Printf("Failed to show configuration: %v\n", err)
			os.Exit(1)
		}

	case "encrypt":
		if *key == "" || *value == "" {
			fmt.Println("Both -key and -value are required for encrypt action")
			os.Exit(1)
		}
		if err := encryptValue(sugar, *key, *value); err != nil {
			fmt.Printf("Failed to encrypt value: %v\n", err)
			os.Exit(1)
		}

	case "decrypt":
		if *key == "" {
			fmt.Println("-key is required for decrypt action")
			os.Exit(1)
		}
		if err := decryptValue(sugar, *key); err != nil {
			fmt.Printf("Failed to decrypt value: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown action: %s\n", *action)
		os.Exit(1)
	}
}

// Mock config structure for demonstration
type MockConfig struct {
	Server struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"server"`
	Database struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		DBName string `json:"dbname"`
	} `json:"database"`
	Environment string `json:"environment"`
}

func validateConfig(logger *zap.SugaredLogger) error {
	// Since we can't access internal config, do basic validation
	logger.Info("Validating configuration...")

	// Check for required environment variables
	requiredEnvs := []string{"DATABASE_HOST", "DATABASE_PORT", "JWT_SECRET"}
	for _, env := range requiredEnvs {
		if os.Getenv(env) == "" {
			return fmt.Errorf("required environment variable %s is not set", env)
		}
	}

	return nil
}

func showConfig(_ *zap.SugaredLogger, format string) error {
	// Create mock config from environment variables
	cfg := MockConfig{
		Environment: getEnvOrDefault("ENVIRONMENT", "development"),
	}
	cfg.Server.Host = getEnvOrDefault("SERVER_HOST", "localhost")
	cfg.Server.Port = 8080
	cfg.Database.Host = getEnvOrDefault("DATABASE_HOST", "localhost")
	cfg.Database.Port = 5432
	cfg.Database.DBName = getEnvOrDefault("DATABASE_NAME", "samurai_db")

	switch format {
	case "json":
		jsonData, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(jsonData))
	default:
		fmt.Printf("Configuration for environment: %s\n", cfg.Environment)
		fmt.Printf("Server: %s:%d\n", cfg.Server.Host, cfg.Server.Port)
		fmt.Printf("Database: %s:%d/%s\n", cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)
	}

	return nil
}

func encryptValue(logger *zap.SugaredLogger, key, value string) error {
	// Mock encryption - in real implementation would use the secret manager
	logger.Infof("Encrypting value for key: %s", key)

	// Simple base64 encoding as mock encryption
	encrypted := base64.StdEncoding.EncodeToString([]byte(value))

	fmt.Printf("Encrypted value for key '%s': enc:%s\n", key, encrypted)
	fmt.Printf("Note: This is a mock encryption. Use the backend secret manager for real encryption.\n")
	return nil
}

func decryptValue(logger *zap.SugaredLogger, key string) error {
	logger.Infof("Decrypt functionality for key: %s", key)
	fmt.Printf("Decrypt functionality for key '%s' - would decrypt from configuration\n", key)
	fmt.Printf("Note: This requires integration with the backend secret manager.\n")
	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
