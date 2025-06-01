package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LocalProvider manages secrets in local files
type LocalProvider struct {
	secretFile    string
	encryptedFile string
	encryptionKey []byte
	secrets       map[string]SecretValue
	mutex         sync.RWMutex
	logger        *zap.SugaredLogger
	autoSave      bool
	saveInterval  time.Duration
	stopChan      chan struct{}
}

// NewLocalProvider creates a new local file secret provider
func NewLocalProvider(secretFile, encryptedFile, encryptionKey string, logger *zap.SugaredLogger) (*LocalProvider, error) {
	var keyBytes []byte
	if encryptionKey != "" {
		hash := sha256.Sum256([]byte(encryptionKey))
		keyBytes = hash[:]
	}

	provider := &LocalProvider{
		secretFile:    secretFile,
		encryptedFile: encryptedFile,
		encryptionKey: keyBytes,
		secrets:       make(map[string]SecretValue),
		logger:        logger,
		autoSave:      true,
		saveInterval:  time.Minute * 5,
		stopChan:      make(chan struct{}),
	}

	// Load existing secrets
	if err := provider.loadSecrets(); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	// Start auto-save goroutine
	if provider.autoSave {
		go provider.autoSaveLoop()
	}

	return provider, nil
}

// GetSecret retrieves a secret by key
func (lp *LocalProvider) GetSecret(ctx context.Context, key string) (string, error) {
	lp.mutex.RLock()
	defer lp.mutex.RUnlock()

	secret, exists := lp.secrets[key]
	if !exists {
		return "", fmt.Errorf("secret not found: %s", key)
	}

	return secret.Value, nil
}

// SetSecret stores a secret
func (lp *LocalProvider) SetSecret(ctx context.Context, key, value string) error {
	lp.mutex.Lock()
	defer lp.mutex.Unlock()

	now := time.Now()
	metadata := SecretMetadata{
		Key:       key,
		CreatedAt: now,
		UpdatedAt: now,
		Version:   "1",
		Tags:      make(map[string]string),
	}

	// If secret exists, preserve creation time and increment version
	if existing, exists := lp.secrets[key]; exists {
		metadata.CreatedAt = existing.Metadata.CreatedAt
		// Simple version increment (in real implementation, use semantic versioning)
		metadata.Version = fmt.Sprintf("%d", len(existing.Metadata.Version)+1)
	}

	lp.secrets[key] = SecretValue{
		Value:    value,
		Metadata: metadata,
	}

	lp.logger.Debugf("Secret set: %s", key)

	// Save immediately for important changes
	return lp.saveSecrets()
}

// DeleteSecret removes a secret
func (lp *LocalProvider) DeleteSecret(ctx context.Context, key string) error {
	lp.mutex.Lock()
	defer lp.mutex.Unlock()

	if _, exists := lp.secrets[key]; !exists {
		return fmt.Errorf("secret not found: %s", key)
	}

	delete(lp.secrets, key)
	lp.logger.Debugf("Secret deleted: %s", key)

	return lp.saveSecrets()
}

// ListSecrets returns all secret keys
func (lp *LocalProvider) ListSecrets(ctx context.Context) ([]string, error) {
	lp.mutex.RLock()
	defer lp.mutex.RUnlock()

	keys := make([]string, 0, len(lp.secrets))
	for key := range lp.secrets {
		keys = append(keys, key)
	}

	return keys, nil
}

// HealthCheck verifies the provider is accessible
func (lp *LocalProvider) HealthCheck(ctx context.Context) error {
	// Check if we can read and write to the secret file
	tempKey := "__health_check__"
	tempValue := "health_check_value"

	if err := lp.SetSecret(ctx, tempKey, tempValue); err != nil {
		return fmt.Errorf("health check write failed: %w", err)
	}

	retrievedValue, err := lp.GetSecret(ctx, tempKey)
	if err != nil {
		return fmt.Errorf("health check read failed: %w", err)
	}

	if retrievedValue != tempValue {
		return fmt.Errorf("health check value mismatch")
	}

	// Clean up
	if err := lp.DeleteSecret(ctx, tempKey); err != nil {
		lp.logger.Warnf("Failed to clean up health check secret: %v", err)
	}

	return nil
}

// Close cleans up provider resources
func (lp *LocalProvider) Close() error {
	close(lp.stopChan)
	return lp.saveSecrets()
}

// loadSecrets loads secrets from file
func (lp *LocalProvider) loadSecrets() error {
	var filename string
	var encrypted bool

	// Determine which file to use
	if lp.encryptedFile != "" && lp.encryptionKey != nil {
		filename = lp.encryptedFile
		encrypted = true
	} else if lp.secretFile != "" {
		filename = lp.secretFile
		encrypted = false
	} else {
		// No file specified, start with empty secrets
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		lp.logger.Infof("Secret file does not exist, starting with empty secrets: %s", filename)
		return nil
	}

	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read secret file: %w", err)
	}

	if len(data) == 0 {
		return nil
	}

	// Decrypt if necessary
	if encrypted {
		decryptedData, err := lp.decrypt(data)
		if err != nil {
			return fmt.Errorf("failed to decrypt secrets: %w", err)
		}
		data = decryptedData
	}

	// Parse JSON
	if err := json.Unmarshal(data, &lp.secrets); err != nil {
		return fmt.Errorf("failed to parse secrets JSON: %w", err)
	}

	lp.logger.Infof("Loaded %d secrets from %s", len(lp.secrets), filename)
	return nil
}

// saveSecrets saves secrets to file
func (lp *LocalProvider) saveSecrets() error {
	// Marshal to JSON
	data, err := json.MarshalIndent(lp.secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	// Save encrypted version if encryption is enabled
	if lp.encryptedFile != "" && lp.encryptionKey != nil {
		encryptedData, err := lp.encrypt(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt secrets: %w", err)
		}

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(lp.encryptedFile), 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		if err := os.WriteFile(lp.encryptedFile, encryptedData, 0600); err != nil {
			return fmt.Errorf("failed to write encrypted secrets: %w", err)
		}

		lp.logger.Debugf("Saved encrypted secrets to %s", lp.encryptedFile)
	}

	// Save plain text version if specified (for development)
	if lp.secretFile != "" {
		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(lp.secretFile), 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		if err := os.WriteFile(lp.secretFile, data, 0600); err != nil {
			return fmt.Errorf("failed to write secrets: %w", err)
		}

		lp.logger.Debugf("Saved secrets to %s", lp.secretFile)
	}

	return nil
}

// encrypt encrypts data using AES-GCM
func (lp *LocalProvider) encrypt(data []byte) ([]byte, error) {
	if lp.encryptionKey == nil {
		return nil, fmt.Errorf("encryption key not set")
	}

	block, err := aes.NewCipher(lp.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Encode to base64
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)

	return encoded, nil
}

// decrypt decrypts data using AES-GCM
func (lp *LocalProvider) decrypt(data []byte) ([]byte, error) {
	if lp.encryptionKey == nil {
		return nil, fmt.Errorf("encryption key not set")
	}

	// Decode from base64
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	decoded = decoded[:n]

	if len(decoded) < 12 {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	// Extract nonce and ciphertext
	nonce := decoded[:12]
	ciphertext := decoded[12:]

	// Create cipher
	block, err := aes.NewCipher(lp.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// autoSaveLoop periodically saves secrets
func (lp *LocalProvider) autoSaveLoop() {
	ticker := time.NewTicker(lp.saveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lp.mutex.RLock()
			secretCount := len(lp.secrets)
			lp.mutex.RUnlock()

			if secretCount > 0 {
				if err := lp.saveSecrets(); err != nil {
					lp.logger.Errorf("Auto-save failed: %v", err)
				} else {
					lp.logger.Debugf("Auto-saved %d secrets", secretCount)
				}
			}

		case <-lp.stopChan:
			lp.logger.Debug("Auto-save loop stopped")
			return
		}
	}
}

// GetSecretMetadata returns metadata for a secret
func (lp *LocalProvider) GetSecretMetadata(ctx context.Context, key string) (*SecretMetadata, error) {
	lp.mutex.RLock()
	defer lp.mutex.RUnlock()

	secret, exists := lp.secrets[key]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	return &secret.Metadata, nil
}

// SetSecretWithMetadata stores a secret with custom metadata
func (lp *LocalProvider) SetSecretWithMetadata(ctx context.Context, key, value string, tags map[string]string, description string) error {
	lp.mutex.Lock()
	defer lp.mutex.Unlock()

	now := time.Now()
	metadata := SecretMetadata{
		Key:         key,
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     "1",
		Tags:        tags,
		Description: description,
	}

	// If secret exists, preserve creation time and increment version
	if existing, exists := lp.secrets[key]; exists {
		metadata.CreatedAt = existing.Metadata.CreatedAt
		metadata.Version = fmt.Sprintf("%d", len(existing.Metadata.Version)+1)
	}

	lp.secrets[key] = SecretValue{
		Value:    value,
		Metadata: metadata,
	}

	lp.logger.Debugf("Secret set with metadata: %s", key)
	return lp.saveSecrets()
}

// ExportSecrets exports all secrets to a map (values encrypted)
func (lp *LocalProvider) ExportSecrets(ctx context.Context) (map[string]string, error) {
	lp.mutex.RLock()
	defer lp.mutex.RUnlock()

	exported := make(map[string]string)
	for key, secret := range lp.secrets {
		// Encrypt the value for export
		if lp.encryptionKey != nil {
			encryptedValue, err := lp.encrypt([]byte(secret.Value))
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt secret %s for export: %w", key, err)
			}
			exported[key] = base64.StdEncoding.EncodeToString(encryptedValue)
		} else {
			exported[key] = secret.Value
		}
	}

	return exported, nil
}

// ImportSecrets imports secrets from a map
func (lp *LocalProvider) ImportSecrets(ctx context.Context, secrets map[string]string, encrypted bool) error {
	lp.mutex.Lock()
	defer lp.mutex.Unlock()

	for key, value := range secrets {
		finalValue := value

		// Decrypt if necessary
		if encrypted && lp.encryptionKey != nil {
			encryptedData, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return fmt.Errorf("failed to decode secret %s: %w", key, err)
			}

			decryptedData, err := lp.decrypt(encryptedData)
			if err != nil {
				return fmt.Errorf("failed to decrypt secret %s: %w", key, err)
			}

			finalValue = string(decryptedData)
		}

		now := time.Now()
		metadata := SecretMetadata{
			Key:       key,
			CreatedAt: now,
			UpdatedAt: now,
			Version:   "1",
			Tags:      make(map[string]string),
		}

		lp.secrets[key] = SecretValue{
			Value:    finalValue,
			Metadata: metadata,
		}
	}

	lp.logger.Infof("Imported %d secrets", len(secrets))
	return lp.saveSecrets()
}
