package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// CLIManager provides command-line utilities for secret management
type CLIManager struct {
	secretManager *SecretManager
	logger        *zap.SugaredLogger
}

// NewCLIManager creates a new CLI manager
func NewCLIManager(secretManager *SecretManager, logger *zap.SugaredLogger) *CLIManager {
	return &CLIManager{
		secretManager: secretManager,
		logger:        logger,
	}
}

// SecretCommand represents a CLI command for secret operations
type SecretCommand struct {
	Action      string            `json:"action"`
	Key         string            `json:"key,omitempty"`
	Value       string            `json:"value,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Description string            `json:"description,omitempty"`
	Format      string            `json:"format,omitempty"`
	File        string            `json:"file,omitempty"`
	Encrypted   bool              `json:"encrypted,omitempty"`
}

// ExecuteCommand executes a secret management command
func (cm *CLIManager) ExecuteCommand(ctx context.Context, cmd *SecretCommand) error {
	switch strings.ToLower(cmd.Action) {
	case "get":
		return cm.getSecret(ctx, cmd)
	case "set":
		return cm.setSecret(ctx, cmd)
	case "delete":
		return cm.deleteSecret(ctx, cmd)
	case "list":
		return cm.listSecrets(ctx, cmd)
	case "export":
		return cm.exportSecrets(ctx, cmd)
	case "import":
		return cm.importSecrets(ctx, cmd)
	case "health":
		return cm.healthCheck(ctx, cmd)
	case "stats":
		return cm.getStats(ctx, cmd)
	default:
		return fmt.Errorf("unknown command: %s", cmd.Action)
	}
}

// getSecret retrieves and displays a secret
func (cm *CLIManager) getSecret(ctx context.Context, cmd *SecretCommand) error {
	if cmd.Key == "" {
		return fmt.Errorf("key is required for get command")
	}

	value, err := cm.secretManager.GetSecret(ctx, cmd.Key)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	switch strings.ToLower(cmd.Format) {
	case "json":
		result := map[string]string{
			"key":   cmd.Key,
			"value": value,
		}
		return cm.printJSON(result)
	default:
		fmt.Printf("Secret: %s\nValue: %s\n", cmd.Key, value)
	}

	return nil
}

// setSecret stores a secret
func (cm *CLIManager) setSecret(ctx context.Context, cmd *SecretCommand) error {
	if cmd.Key == "" {
		return fmt.Errorf("key is required for set command")
	}

	value := cmd.Value
	if value == "" {
		// Read from stdin if no value provided
		fmt.Print("Enter secret value: ")
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		value = strings.TrimSpace(string(stdin))
	}

	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	err := cm.secretManager.SetSecret(ctx, cmd.Key, value)
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	fmt.Printf("Secret '%s' set successfully\n", cmd.Key)
	return nil
}

// deleteSecret removes a secret
func (cm *CLIManager) deleteSecret(ctx context.Context, cmd *SecretCommand) error {
	if cmd.Key == "" {
		return fmt.Errorf("key is required for delete command")
	}

	err := cm.secretManager.DeleteSecret(ctx, cmd.Key)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("Secret '%s' deleted successfully\n", cmd.Key)
	return nil
}

// listSecrets displays all secret keys
func (cm *CLIManager) listSecrets(ctx context.Context, cmd *SecretCommand) error {
	keys, err := cm.secretManager.ListSecrets(ctx)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	switch strings.ToLower(cmd.Format) {
	case "json":
		result := map[string]interface{}{
			"secrets": keys,
			"count":   len(keys),
		}
		return cm.printJSON(result)
	default:
		fmt.Printf("Total secrets: %d\n", len(keys))
		for i, key := range keys {
			fmt.Printf("%d. %s\n", i+1, key)
		}
	}

	return nil
}

// exportSecrets exports all secrets to a file
func (cm *CLIManager) exportSecrets(ctx context.Context, cmd *SecretCommand) error {
	if cmd.File == "" {
		return fmt.Errorf("file is required for export command")
	}

	// Get all secret keys
	keys, err := cm.secretManager.ListSecrets(ctx)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	// Export secrets
	secrets := make(map[string]interface{})
	metadata := map[string]interface{}{
		"exported_at":   time.Now().Format(time.RFC3339),
		"total_secrets": len(keys),
		"encrypted":     cmd.Encrypted,
	}

	secretData := make(map[string]string)
	for _, key := range keys {
		value, err := cm.secretManager.GetSecret(ctx, key)
		if err != nil {
			cm.logger.Warnf("Failed to export secret %s: %v", key, err)
			continue
		}
		secretData[key] = value
	}

	secrets["metadata"] = metadata
	secrets["secrets"] = secretData

	// Marshal to JSON
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	// Write to file
	err = os.WriteFile(cmd.File, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	fmt.Printf("Exported %d secrets to %s\n", len(secretData), cmd.File)
	return nil
}

// importSecrets imports secrets from a file
func (cm *CLIManager) importSecrets(ctx context.Context, cmd *SecretCommand) error {
	if cmd.File == "" {
		return fmt.Errorf("file is required for import command")
	}

	// Read file
	data, err := os.ReadFile(cmd.File)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	// Parse JSON
	var importData struct {
		Metadata map[string]interface{} `json:"metadata"`
		Secrets  map[string]string      `json:"secrets"`
	}

	err = json.Unmarshal(data, &importData)
	if err != nil {
		return fmt.Errorf("failed to parse import file: %w", err)
	}

	// Import secrets
	successCount := 0
	errorCount := 0

	for key, value := range importData.Secrets {
		err := cm.secretManager.SetSecret(ctx, key, value)
		if err != nil {
			cm.logger.Errorf("Failed to import secret %s: %v", key, err)
			errorCount++
		} else {
			successCount++
		}
	}

	fmt.Printf("Import completed: %d successful, %d errors\n", successCount, errorCount)
	return nil
}

// healthCheck verifies secret manager health
func (cm *CLIManager) healthCheck(ctx context.Context, cmd *SecretCommand) error {
	err := cm.secretManager.HealthCheck(ctx)
	if err != nil {
		switch strings.ToLower(cmd.Format) {
		case "json":
			result := map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
			return cm.printJSON(result)
		default:
			fmt.Printf("Health check FAILED: %v\n", err)
		}
		return err
	}

	switch strings.ToLower(cmd.Format) {
	case "json":
		result := map[string]interface{}{
			"status": "healthy",
		}
		return cm.printJSON(result)
	default:
		fmt.Println("Health check PASSED")
	}

	return nil
}

// getStats displays secret manager statistics
func (cm *CLIManager) getStats(ctx context.Context, cmd *SecretCommand) error {
	// Get cache stats
	cacheStats := cm.secretManager.GetCacheStats()

	// Get secret count
	keys, err := cm.secretManager.ListSecrets(ctx)
	if err != nil {
		return fmt.Errorf("failed to get secret count: %w", err)
	}

	stats := map[string]interface{}{
		"total_secrets": len(keys),
		"cache_stats":   cacheStats,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	switch strings.ToLower(cmd.Format) {
	case "json":
		return cm.printJSON(stats)
	default:
		fmt.Printf("Secret Manager Statistics\n")
		fmt.Printf("========================\n")
		fmt.Printf("Total Secrets: %d\n", len(keys))
		fmt.Printf("Cache Statistics:\n")
		for key, value := range cacheStats {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	return nil
}

// printJSON prints data as formatted JSON
func (cm *CLIManager) printJSON(data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

// InteractiveMode starts an interactive CLI session
func (cm *CLIManager) InteractiveMode(ctx context.Context) error {
	fmt.Println("Samurai Secret Manager - Interactive Mode")
	fmt.Println("Type 'help' for available commands, 'exit' to quit")

	for {
		fmt.Print("secrets> ")

		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if input == "exit" || input == "quit" {
			break
		}

		if input == "help" {
			cm.printHelp()
			continue
		}

		// Parse command
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		cmd := &SecretCommand{
			Action: parts[0],
			Format: "text",
		}

		// Parse arguments
		for i := 1; i < len(parts); i++ {
			switch {
			case strings.HasPrefix(parts[i], "--key="):
				cmd.Key = strings.TrimPrefix(parts[i], "--key=")
			case strings.HasPrefix(parts[i], "--value="):
				cmd.Value = strings.TrimPrefix(parts[i], "--value=")
			case strings.HasPrefix(parts[i], "--file="):
				cmd.File = strings.TrimPrefix(parts[i], "--file=")
			case strings.HasPrefix(parts[i], "--format="):
				cmd.Format = strings.TrimPrefix(parts[i], "--format=")
			case parts[i] == "--encrypted":
				cmd.Encrypted = true
			}
		}

		// Execute command
		if err := cm.ExecuteCommand(ctx, cmd); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	fmt.Println("Goodbye!")
	return nil
}

// printHelp displays help information
func (cm *CLIManager) printHelp() {
	fmt.Printf(`
Available Commands:
==================
get --key=<key>                    Get a secret value
set --key=<key> --value=<value>    Set a secret value
delete --key=<key>                 Delete a secret
list [--format=json]               List all secret keys
export --file=<file>               Export all secrets to file
import --file=<file>               Import secrets from file
health [--format=json]             Check provider health
stats [--format=json]              Show statistics
help                               Show this help
exit                               Exit interactive mode

Options:
========
--key=<key>        Secret key name
--value=<value>    Secret value (if not provided, will prompt)
--file=<file>      File path for import/export
--format=json      Output format (text or json)
--encrypted        Use encryption for export/import

Examples:
=========
get --key=api_key
set --key=db_password --value=secret123
list --format=json
export --file=backup.json
health

`)
}
