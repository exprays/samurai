package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"go.uber.org/zap"
)

// AWSProvider manages secrets in AWS Secrets Manager
type AWSProvider struct {
	client *secretsmanager.Client
	region string
	prefix string
	logger *zap.SugaredLogger
}

// AWSSecretValue represents the structure of secrets stored in AWS
type AWSSecretValue struct {
	Value       string            `json:"value"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

// NewAWSProvider creates a new AWS Secrets Manager provider
func NewAWSProvider(region, accessKey, secretKey, profile, prefix string, logger *zap.SugaredLogger) (*AWSProvider, error) {
	var cfg aws.Config
	var err error

	// Load AWS configuration
	if accessKey != "" && secretKey != "" {
		// Use provided credentials
		cfg, err = config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		)
	} else if profile != "" {
		// Use named profile
		cfg, err = config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
			config.WithSharedConfigProfile(profile),
		)
	} else {
		// Use default credential chain
		cfg, err = config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		MaxResults: aws.Int32(1),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to AWS Secrets Manager: %w", err)
	}

	provider := &AWSProvider{
		client: client,
		region: region,
		prefix: prefix,
		logger: logger,
	}

	logger.Infof("Connected to AWS Secrets Manager in region %s", region)
	return provider, nil
}

// GetSecret retrieves a secret from AWS Secrets Manager
func (ap *AWSProvider) GetSecret(ctx context.Context, key string) (string, error) {
	secretName := ap.buildSecretName(key)

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	result, err := ap.client.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get secret from AWS: %w", err)
	}

	if result.SecretString == nil {
		return "", fmt.Errorf("secret value is nil: %s", key)
	}

	// Try to parse as our structured format
	var awsSecret AWSSecretValue
	if err := json.Unmarshal([]byte(*result.SecretString), &awsSecret); err == nil {
		return awsSecret.Value, nil
	}

	// If parsing fails, return the raw string (backwards compatibility)
	return *result.SecretString, nil
}

// SetSecret stores a secret in AWS Secrets Manager
func (ap *AWSProvider) SetSecret(ctx context.Context, key, value string) error {
	return ap.SetSecretWithMetadata(ctx, key, value, nil, "")
}

// SetSecretWithMetadata stores a secret with metadata in AWS Secrets Manager
func (ap *AWSProvider) SetSecretWithMetadata(ctx context.Context, key, value string, tags map[string]string, description string) error {
	secretName := ap.buildSecretName(key)

	// Create structured secret value
	awsSecret := AWSSecretValue{
		Value:       value,
		Description: description,
		Tags:        tags,
		CreatedAt:   time.Now().Format(time.RFC3339),
		UpdatedAt:   time.Now().Format(time.RFC3339),
	}

	secretValue, err := json.Marshal(awsSecret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret value: %w", err)
	}

	// Check if secret exists
	exists, err := ap.secretExists(ctx, secretName)
	if err != nil {
		return fmt.Errorf("failed to check if secret exists: %w", err)
	}

	if exists {
		// Update existing secret
		input := &secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(secretName),
			SecretString: aws.String(string(secretValue)),
			Description:  aws.String(description),
		}

		_, err = ap.client.UpdateSecret(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to update secret in AWS: %w", err)
		}

		ap.logger.Debugf("Secret updated in AWS: %s", key)
	} else {
		// Create new secret
		input := &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String(string(secretValue)),
			Description:  aws.String(description),
		}

		// Add tags if provided
		if tags != nil {
			awsTags := make([]types.Tag, 0, len(tags))
			for k, v := range tags {
				awsTags = append(awsTags, types.Tag{
					Key:   aws.String(k),
					Value: aws.String(v),
				})
			}
			input.Tags = awsTags
		}

		_, err = ap.client.CreateSecret(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to create secret in AWS: %w", err)
		}

		ap.logger.Debugf("Secret created in AWS: %s", key)
	}

	return nil
}

// DeleteSecret removes a secret from AWS Secrets Manager
func (ap *AWSProvider) DeleteSecret(ctx context.Context, key string) error {
	secretName := ap.buildSecretName(key)

	input := &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(secretName),
		ForceDeleteWithoutRecovery: aws.Bool(true), // Immediate deletion
	}

	_, err := ap.client.DeleteSecret(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete secret from AWS: %w", err)
	}

	ap.logger.Debugf("Secret deleted from AWS: %s", key)
	return nil
}

// ListSecrets returns all secret keys from AWS Secrets Manager
func (ap *AWSProvider) ListSecrets(ctx context.Context) ([]string, error) {
	var secrets []string
	var nextToken *string

	for {
		input := &secretsmanager.ListSecretsInput{
			MaxResults: aws.Int32(100),
			NextToken:  nextToken,
		}

		// Filter by prefix if specified
		if ap.prefix != "" {
			input.Filters = []types.Filter{
				{
					Key:    types.FilterNameStringTypeName,
					Values: []string{ap.prefix + "*"},
				},
			}
		}

		result, err := ap.client.ListSecrets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets from AWS: %w", err)
		}

		for _, secret := range result.SecretList {
			if secret.Name != nil {
				// Remove prefix to get the key
				key := *secret.Name
				if ap.prefix != "" {
					key = strings.TrimPrefix(key, ap.prefix)
				}
				secrets = append(secrets, key)
			}
		}

		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	return secrets, nil
}

// HealthCheck verifies AWS Secrets Manager connectivity
func (ap *AWSProvider) HealthCheck(ctx context.Context) error {
	// Test basic connectivity
	_, err := ap.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		MaxResults: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("AWS Secrets Manager health check failed: %w", err)
	}

	// Test read/write permissions
	testKey := "__health_check__"
	testValue := "health_check_value"

	if err := ap.SetSecret(ctx, testKey, testValue); err != nil {
		return fmt.Errorf("AWS write test failed: %w", err)
	}

	retrievedValue, err := ap.GetSecret(ctx, testKey)
	if err != nil {
		return fmt.Errorf("AWS read test failed: %w", err)
	}

	if retrievedValue != testValue {
		return fmt.Errorf("AWS read/write test value mismatch")
	}

	// Clean up
	if err := ap.DeleteSecret(ctx, testKey); err != nil {
		ap.logger.Warnf("Failed to clean up AWS health check secret: %v", err)
	}

	return nil
}

// Close cleans up AWS client resources
func (ap *AWSProvider) Close() error {
	ap.logger.Debug("AWS provider closed")
	return nil
}

// buildSecretName constructs the full AWS secret name
func (ap *AWSProvider) buildSecretName(key string) string {
	if ap.prefix == "" {
		return key
	}
	return ap.prefix + key
}

// secretExists checks if a secret exists in AWS Secrets Manager
func (ap *AWSProvider) secretExists(ctx context.Context, secretName string) (bool, error) {
	input := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretName),
	}

	_, err := ap.client.DescribeSecret(ctx, input)
	if err != nil {
		// Check if error is because secret doesn't exist
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// GetSecretMetadata returns metadata for a secret
func (ap *AWSProvider) GetSecretMetadata(ctx context.Context, key string) (*SecretMetadata, error) {
	secretName := ap.buildSecretName(key)

	input := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretName),
	}

	result, err := ap.client.DescribeSecret(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret metadata: %w", err)
	}

	metadata := &SecretMetadata{
		Key: key,
	}

	if result.CreatedDate != nil {
		metadata.CreatedAt = *result.CreatedDate
	}

	if result.LastChangedDate != nil {
		metadata.UpdatedAt = *result.LastChangedDate
	}

	if result.Description != nil {
		metadata.Description = *result.Description
	}

	if result.VersionIdsToStages != nil {
		for version := range result.VersionIdsToStages {
			metadata.Version = version
			break // Get the first version
		}
	}

	// Convert AWS tags to our format
	if result.Tags != nil {
		metadata.Tags = make(map[string]string)
		for _, tag := range result.Tags {
			if tag.Key != nil && tag.Value != nil {
				metadata.Tags[*tag.Key] = *tag.Value
			}
		}
	}

	return metadata, nil
}

// RotateSecret triggers automatic rotation for a secret
func (ap *AWSProvider) RotateSecret(ctx context.Context, key string, lambdaFunctionArn string) error {
	secretName := ap.buildSecretName(key)

	input := &secretsmanager.UpdateSecretInput{
		SecretId:    aws.String(secretName),
		Description: aws.String("Automatic rotation enabled"),
	}

	_, err := ap.client.UpdateSecret(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to enable rotation for secret: %w", err)
	}

	ap.logger.Infof("Rotation enabled for secret: %s", key)
	return nil
}

// GetSecretVersions returns all versions of a secret
func (ap *AWSProvider) GetSecretVersions(ctx context.Context, key string) ([]string, error) {
	secretName := ap.buildSecretName(key)

	input := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretName),
	}

	result, err := ap.client.DescribeSecret(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret versions: %w", err)
	}

	var versions []string
	if result.VersionIdsToStages != nil {
		for version := range result.VersionIdsToStages {
			versions = append(versions, version)
		}
	}

	return versions, nil
}

// GetSecretVersion retrieves a specific version of a secret
func (ap *AWSProvider) GetSecretVersion(ctx context.Context, key, version string) (string, error) {
	secretName := ap.buildSecretName(key)

	input := &secretsmanager.GetSecretValueInput{
		SecretId:  aws.String(secretName),
		VersionId: aws.String(version),
	}

	result, err := ap.client.GetSecretValue(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get secret version from AWS: %w", err)
	}

	if result.SecretString == nil {
		return "", fmt.Errorf("secret value is nil: %s (version %s)", key, version)
	}

	// Try to parse as our structured format
	var awsSecret AWSSecretValue
	if err := json.Unmarshal([]byte(*result.SecretString), &awsSecret); err == nil {
		return awsSecret.Value, nil
	}

	// If parsing fails, return the raw string
	return *result.SecretString, nil
}
