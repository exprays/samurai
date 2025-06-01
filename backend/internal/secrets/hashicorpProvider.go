package secrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// VaultProvider manages secrets in HashiCorp Vault
type VaultProvider struct {
	client   *api.Client
	basePath string
	logger   *zap.SugaredLogger
}

// NewVaultProvider creates a new Vault secret provider
func NewVaultProvider(address, token, basePath, namespace string, enableTLS bool, caCert, clientCert, clientKey string, logger *zap.SugaredLogger) (*VaultProvider, error) {
	config := api.DefaultConfig()
	config.Address = address

	// Configure TLS if enabled
	if enableTLS {
		tlsConfig := &api.TLSConfig{
			CACert:     caCert,
			ClientCert: clientCert,
			ClientKey:  clientKey,
		}
		if err := config.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to configure Vault TLS: %w", err)
		}
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set token
	client.SetToken(token)

	// Set namespace if provided
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	// Verify connection
	_, err = client.Sys().Health()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Vault: %w", err)
	}

	provider := &VaultProvider{
		client:   client,
		basePath: strings.TrimSuffix(basePath, "/"),
		logger:   logger,
	}

	logger.Infof("Connected to Vault at %s", address)
	return provider, nil
}

// GetSecret retrieves a secret from Vault
func (vp *VaultProvider) GetSecret(ctx context.Context, key string) (string, error) {
	path := vp.buildPath(key)

	secret, err := vp.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	if secret == nil {
		return "", fmt.Errorf("secret not found: %s", key)
	}

	// Handle different Vault KV versions
	var data map[string]interface{}
	if secret.Data["data"] != nil {
		// KV v2
		data = secret.Data["data"].(map[string]interface{})
	} else {
		// KV v1
		data = secret.Data
	}

	value, exists := data["value"]
	if !exists {
		return "", fmt.Errorf("value field not found in secret: %s", key)
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret value is not a string: %s", key)
	}

	return valueStr, nil
}

// SetSecret stores a secret in Vault
func (vp *VaultProvider) SetSecret(ctx context.Context, key, value string) error {
	path := vp.buildPath(key)

	data := map[string]interface{}{
		"value": value,
		"metadata": map[string]interface{}{
			"created_at": time.Now().Format(time.RFC3339),
			"updated_at": time.Now().Format(time.RFC3339),
		},
	}

	// Handle KV v2 format
	payload := map[string]interface{}{
		"data": data,
	}

	_, err := vp.client.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		return fmt.Errorf("failed to write secret to Vault: %w", err)
	}

	vp.logger.Debugf("Secret written to Vault: %s", key)
	return nil
}

// DeleteSecret removes a secret from Vault
func (vp *VaultProvider) DeleteSecret(ctx context.Context, key string) error {
	path := vp.buildPath(key)

	_, err := vp.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete secret from Vault: %w", err)
	}

	vp.logger.Debugf("Secret deleted from Vault: %s", key)
	return nil
}

// ListSecrets returns all secret keys from Vault
func (vp *VaultProvider) ListSecrets(ctx context.Context) ([]string, error) {
	// For KV v2, we need to list from the metadata path
	listPath := vp.basePath + "/metadata/"
	if !strings.Contains(vp.basePath, "/data/") {
		listPath = vp.basePath + "/"
	}

	secret, err := vp.client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, exists := secret.Data["keys"]
	if !exists {
		return []string{}, nil
	}

	keyList, ok := keys.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected format for secret keys")
	}

	result := make([]string, 0, len(keyList))
	for _, key := range keyList {
		if keyStr, ok := key.(string); ok {
			result = append(result, keyStr)
		}
	}

	return result, nil
}

// HealthCheck verifies Vault connectivity
func (vp *VaultProvider) HealthCheck(ctx context.Context) error {
	// Check Vault health
	health, err := vp.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	if !health.Initialized {
		return fmt.Errorf("vault is not initialized")
	}

	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	// Test read/write permissions
	testKey := "__health_check__"
	testValue := "health_check_value"

	if err := vp.SetSecret(ctx, testKey, testValue); err != nil {
		return fmt.Errorf("vault write test failed: %w", err)
	}

	retrievedValue, err := vp.GetSecret(ctx, testKey)
	if err != nil {
		return fmt.Errorf("vault read test failed: %w", err)
	}

	if retrievedValue != testValue {
		return fmt.Errorf("vault read/write test value mismatch")
	}

	// Clean up
	if err := vp.DeleteSecret(ctx, testKey); err != nil {
		vp.logger.Warnf("Failed to clean up Vault health check secret: %v", err)
	}

	return nil
}

// Close cleans up Vault client resources
func (vp *VaultProvider) Close() error {
	// Vault client doesn't need explicit cleanup
	vp.logger.Debug("Vault provider closed")
	return nil
}

// buildPath constructs the full Vault path for a secret
func (vp *VaultProvider) buildPath(key string) string {
	// Handle KV v2 paths (add /data/ if not present)
	if strings.Contains(vp.basePath, "/metadata/") {
		// Convert metadata path to data path for read/write operations
		basePath := strings.Replace(vp.basePath, "/metadata/", "/data/", 1)
		return basePath + "/" + key
	} else if !strings.Contains(vp.basePath, "/data/") {
		// Assume KV v2 and add /data/
		return vp.basePath + "/data/" + key
	}

	return vp.basePath + "/" + key
}

// GetSecretVersions returns all versions of a secret (KV v2 only)
func (vp *VaultProvider) GetSecretVersions(ctx context.Context, key string) ([]int, error) {
	metadataPath := strings.Replace(vp.buildPath(key), "/data/", "/metadata/", 1)

	secret, err := vp.client.Logical().ReadWithContext(ctx, metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret metadata: %w", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	versions, exists := secret.Data["versions"]
	if !exists {
		return []int{}, nil
	}

	versionMap, ok := versions.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected format for secret versions")
	}

	result := make([]int, 0, len(versionMap))
	for versionStr := range versionMap {
		if version := parseInt(versionStr); version > 0 {
			result = append(result, version)
		}
	}

	return result, nil
}

// GetSecretVersion retrieves a specific version of a secret (KV v2 only)
func (vp *VaultProvider) GetSecretVersion(ctx context.Context, key string, version int) (string, error) {
	path := vp.buildPath(key)

	params := map[string][]string{
		"version": {fmt.Sprintf("%d", version)},
	}

	secret, err := vp.client.Logical().ReadWithDataWithContext(ctx, path, params)
	if err != nil {
		return "", fmt.Errorf("failed to read secret version: %w", err)
	}

	if secret == nil {
		return "", fmt.Errorf("secret version not found: %s (version %d)", key, version)
	}

	data := secret.Data["data"].(map[string]interface{})
	value, exists := data["value"]
	if !exists {
		return "", fmt.Errorf("value field not found in secret version: %s (version %d)", key, version)
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret value is not a string: %s (version %d)", key, version)
	}

	return valueStr, nil
}

// parseInt safely converts string to int
func parseInt(s string) int {
	if s == "" {
		return 0
	}

	var result int
	for _, char := range s {
		if char >= '0' && char <= '9' {
			result = result*10 + int(char-'0')
		} else {
			return 0 // Invalid character
		}
	}
	return result
}

// RenewToken renews the Vault token if it's renewable
func (vp *VaultProvider) RenewToken(ctx context.Context) error {
	secret, err := vp.client.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("failed to renew Vault token: %w", err)
	}

	if secret.Auth != nil {
		vp.logger.Infof("Vault token renewed, TTL: %d seconds", secret.Auth.LeaseDuration)
	}

	return nil
}

// GetTokenInfo returns information about the current token
func (vp *VaultProvider) GetTokenInfo(ctx context.Context) (map[string]interface{}, error) {
	secret, err := vp.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup Vault token: %w", err)
	}

	return secret.Data, nil
}
