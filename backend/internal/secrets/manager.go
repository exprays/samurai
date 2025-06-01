package secrets

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// SecretProvider defines the interface for secret management providers
type SecretProvider interface {
	// GetSecret retrieves a secret by key
	GetSecret(ctx context.Context, key string) (string, error)

	// SetSecret stores a secret
	SetSecret(ctx context.Context, key, value string) error

	// DeleteSecret removes a secret
	DeleteSecret(ctx context.Context, key string) error

	// ListSecrets returns all secret keys (not values)
	ListSecrets(ctx context.Context) ([]string, error)

	// HealthCheck verifies the provider is accessible
	HealthCheck(ctx context.Context) error

	// Close cleans up provider resources
	Close() error
}

// SecretMetadata contains metadata about a secret
type SecretMetadata struct {
	Key         string            `json:"key"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Version     string            `json:"version"`
	Tags        map[string]string `json:"tags"`
	Description string            `json:"description"`
}

// SecretValue represents a secret with its metadata
type SecretValue struct {
	Value    string         `json:"value"`
	Metadata SecretMetadata `json:"metadata"`
}

// SecretManager manages multiple secret providers with caching
type SecretManager struct {
	provider     SecretProvider
	cache        map[string]*cachedSecret
	cacheTimeout time.Duration
	logger       *zap.SugaredLogger
}

type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// NewSecretManager creates a new secret manager
func NewSecretManager(provider SecretProvider, cacheTimeout time.Duration, logger *zap.SugaredLogger) *SecretManager {
	return &SecretManager{
		provider:     provider,
		cache:        make(map[string]*cachedSecret),
		cacheTimeout: cacheTimeout,
		logger:       logger,
	}
}

// GetSecret retrieves a secret with caching
func (sm *SecretManager) GetSecret(ctx context.Context, key string) (string, error) {
	// Check cache first
	if cached, exists := sm.cache[key]; exists {
		if time.Now().Before(cached.expiresAt) {
			sm.logger.Debugf("Cache hit for secret key: %s", key)
			return cached.value, nil
		}
		// Cache expired, remove it
		delete(sm.cache, key)
		sm.logger.Debugf("Cache expired for secret key: %s", key)
	}

	// Fetch from provider
	value, err := sm.provider.GetSecret(ctx, key)
	if err != nil {
		return "", err
	}

	// Cache the value
	sm.cache[key] = &cachedSecret{
		value:     value,
		expiresAt: time.Now().Add(sm.cacheTimeout),
	}

	sm.logger.Debugf("Secret retrieved and cached: %s", key)
	return value, nil
}

// SetSecret stores a secret and invalidates cache
func (sm *SecretManager) SetSecret(ctx context.Context, key, value string) error {
	err := sm.provider.SetSecret(ctx, key, value)
	if err != nil {
		return err
	}

	// Invalidate cache
	delete(sm.cache, key)
	sm.logger.Debugf("Secret set and cache invalidated: %s", key)
	return nil
}

// DeleteSecret removes a secret and invalidates cache
func (sm *SecretManager) DeleteSecret(ctx context.Context, key string) error {
	err := sm.provider.DeleteSecret(ctx, key)
	if err != nil {
		return err
	}

	// Invalidate cache
	delete(sm.cache, key)
	sm.logger.Debugf("Secret deleted and cache invalidated: %s", key)
	return nil
}

// ListSecrets returns all secret keys
func (sm *SecretManager) ListSecrets(ctx context.Context) ([]string, error) {
	return sm.provider.ListSecrets(ctx)
}

// HealthCheck verifies the provider is accessible
func (sm *SecretManager) HealthCheck(ctx context.Context) error {
	return sm.provider.HealthCheck(ctx)
}

// ClearCache clears all cached secrets
func (sm *SecretManager) ClearCache() {
	sm.cache = make(map[string]*cachedSecret)
	sm.logger.Info("Secret cache cleared")
}

// Close cleans up resources
func (sm *SecretManager) Close() error {
	sm.ClearCache()
	return sm.provider.Close()
}

// GetCacheStats returns cache statistics
func (sm *SecretManager) GetCacheStats() map[string]interface{} {
	totalSecrets := len(sm.cache)
	expiredSecrets := 0
	now := time.Now()

	for _, cached := range sm.cache {
		if now.After(cached.expiresAt) {
			expiredSecrets++
		}
	}

	return map[string]interface{}{
		"total_cached":   totalSecrets,
		"expired_cached": expiredSecrets,
		"cache_timeout":  sm.cacheTimeout.String(),
	}
}
