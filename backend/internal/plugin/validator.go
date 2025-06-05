package plugin

import (
	"fmt"

	"samurai/backend/internal/plugin/interfaces"

	"go.uber.org/zap"
)

// ConfigValidator validates plugin configurations against their schemas
type ConfigValidator struct {
	schemaValidator *SchemaValidator
	logger          *zap.SugaredLogger
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(logger *zap.SugaredLogger) *ConfigValidator {
	return &ConfigValidator{
		schemaValidator: NewSchemaValidator(logger),
		logger:          logger.Named("config-validator"),
	}
}

// ValidateConfig validates a plugin configuration against its schema
func (v *ConfigValidator) ValidateConfig(config *interfaces.PluginConfig, schema map[string]interface{}) error {
	if schema == nil {
		v.logger.Debug("No schema provided for validation")
		return nil // No schema to validate against
	}

	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Use the schema validator for comprehensive validation
	result := v.schemaValidator.ValidatePluginConfig(config, schema)

	if !result.Valid {
		// Convert validation errors to a single error message
		var errorMessages []string
		for _, err := range result.Errors {
			errorMessages = append(errorMessages, err.Error())
		}
		return fmt.Errorf("configuration validation failed: %v", errorMessages)
	}

	// Additional plugin-specific validations
	if err := v.validatePluginSpecificConstraints(config); err != nil {
		return fmt.Errorf("plugin-specific validation failed: %w", err)
	}

	return nil
}

// ValidateManifest validates a plugin manifest
func (v *ConfigValidator) ValidateManifest(manifest *PluginManifest) error {
	if manifest.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	if manifest.Version == "" {
		return fmt.Errorf("plugin version is required")
	}

	if manifest.Type == "" {
		return fmt.Errorf("plugin type is required")
	}

	validTypes := map[interfaces.PluginType]bool{
		interfaces.PluginTypeMCP:     true,
		interfaces.PluginTypeService: true,
		interfaces.PluginTypeUtility: true,
	}

	if !validTypes[manifest.Type] {
		return fmt.Errorf("invalid plugin type: %s", manifest.Type)
	}

	if manifest.Binary == "" {
		return fmt.Errorf("plugin binary path is required")
	}

	if manifest.EntryPoint == "" {
		return fmt.Errorf("plugin entry point is required")
	}

	// Validate dependencies
	for _, dep := range manifest.Dependencies {
		if dep.Name == "" {
			return fmt.Errorf("dependency name is required")
		}
		if dep.Version == "" && dep.MinVersion == "" {
			return fmt.Errorf("dependency version or min_version is required")
		}
	}

	// Validate capabilities
	for _, cap := range manifest.Capabilities {
		if cap.Name == "" {
			return fmt.Errorf("capability name is required")
		}
		if cap.Type == "" {
			return fmt.Errorf("capability type is required")
		}
	}

	// Validate config schema if present
	if manifest.ConfigSchema != nil {
		if err := v.validateConfigSchema(manifest.ConfigSchema); err != nil {
			return fmt.Errorf("invalid config schema: %w", err)
		}
	}

	return nil
}

// validatePluginSpecificConstraints validates plugin-specific constraints
func (v *ConfigValidator) validatePluginSpecificConstraints(config *interfaces.PluginConfig) error {
	// Validate resource limits
	if config.Resources != nil {
		if config.Resources.MaxMemoryMB < 0 {
			return fmt.Errorf("max memory cannot be negative")
		}
		if config.Resources.MaxCPUPercent < 0 || config.Resources.MaxCPUPercent > 100 {
			return fmt.Errorf("max CPU percent must be between 0 and 100")
		}
		if config.Resources.MaxConcurrency < 0 {
			return fmt.Errorf("max concurrency cannot be negative")
		}
	}

	// Validate permissions
	for _, permission := range config.Permissions {
		if err := v.validatePermission(permission); err != nil {
			return fmt.Errorf("invalid permission '%s': %w", permission, err)
		}
	}

	return nil
}

// validatePermission validates a single permission string
func (v *ConfigValidator) validatePermission(permission string) error {
	validPermissions := map[string]bool{
		"read":        true,
		"write":       true,
		"execute":     true,
		"network":     true,
		"filesystem":  true,
		"environment": true,
		"system":      true,
		"database":    true,
		"secrets":     true,
		"admin":       true,
	}

	if !validPermissions[permission] {
		return fmt.Errorf("unknown permission: %s", permission)
	}

	return nil
}

// validateConfigSchema validates that a config schema is well-formed
func (v *ConfigValidator) validateConfigSchema(schema map[string]interface{}) error {
	// Basic schema structure validation
	if schemaType, exists := schema["type"]; exists {
		if typeStr, ok := schemaType.(string); ok {
			validTypes := map[string]bool{
				"object":  true,
				"array":   true,
				"string":  true,
				"number":  true,
				"integer": true,
				"boolean": true,
				"null":    true,
			}
			if !validTypes[typeStr] {
				return fmt.Errorf("invalid schema type: %s", typeStr)
			}
		}
	}

	// Validate properties if it's an object schema
	if properties, exists := schema["properties"]; exists {
		if propMap, ok := properties.(map[string]interface{}); ok {
			for propName, propSchema := range propMap {
				if propSchemaMap, ok := propSchema.(map[string]interface{}); ok {
					if err := v.validateConfigSchema(propSchemaMap); err != nil {
						return fmt.Errorf("invalid schema for property '%s': %w", propName, err)
					}
				}
			}
		}
	}

	return nil
}

// GetValidationResult returns detailed validation results
func (v *ConfigValidator) GetValidationResult(config *interfaces.PluginConfig, schema map[string]interface{}) *ValidationResult {
	if schema == nil {
		return &ValidationResult{
			Valid:  true,
			Errors: []ValidationError{},
		}
	}

	return v.schemaValidator.ValidatePluginConfig(config, schema)
}
