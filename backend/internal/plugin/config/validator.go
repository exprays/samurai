package config

import (
	"fmt"
	"regexp"
	"samurai/backend/internal/plugin/interfaces"

	"go.uber.org/zap"
)

// ConfigValidator validates plugin configurations
type ConfigValidator struct {
	logger *zap.SugaredLogger
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(logger *zap.SugaredLogger) *ConfigValidator {
	return &ConfigValidator{
		logger: logger.Named("config-validator"),
	}
}

// ValidateConfig validates a plugin configuration against its schema
func (cv *ConfigValidator) ValidateConfig(config *interfaces.PluginConfig, schema map[string]interface{}) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	if schema == nil {
		cv.logger.Debug("No schema provided, skipping validation")
		return nil
	}

	// Validate basic structure
	if err := cv.validateBasicStructure(config); err != nil {
		return fmt.Errorf("basic structure validation failed: %w", err)
	}

	// Validate settings against schema
	if err := cv.validateSettings(config.Settings, schema); err != nil {
		return fmt.Errorf("settings validation failed: %w", err)
	}

	// Validate resource limits
	if err := cv.validateResourceLimits(config.Resources); err != nil {
		return fmt.Errorf("resource limits validation failed: %w", err)
	}

	// Validate permissions
	if err := cv.validatePermissions(config.Permissions); err != nil {
		return fmt.Errorf("permissions validation failed: %w", err)
	}

	return nil
}

// validateBasicStructure validates the basic structure of the configuration
func (cv *ConfigValidator) validateBasicStructure(config *interfaces.PluginConfig) error {
	if config.Settings == nil {
		config.Settings = make(map[string]interface{})
	}

	return nil
}

// validateSettings validates configuration settings against schema
func (cv *ConfigValidator) validateSettings(settings map[string]interface{}, schema map[string]interface{}) error {
	// Get properties from schema
	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		return nil // No properties defined
	}

	// Get required fields
	required := make(map[string]bool)
	if reqArray, ok := schema["required"].([]interface{}); ok {
		for _, field := range reqArray {
			if fieldName, ok := field.(string); ok {
				required[fieldName] = true
			}
		}
	}

	// Check required fields
	for fieldName := range required {
		if _, exists := settings[fieldName]; !exists {
			return fmt.Errorf("required field '%s' is missing", fieldName)
		}
	}

	// Validate each setting
	for settingName, settingValue := range settings {
		if propSchema, exists := properties[settingName]; exists {
			if propMap, ok := propSchema.(map[string]interface{}); ok {
				if err := cv.validateSettingValue(settingName, settingValue, propMap); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateSettingValue validates a single setting value
func (cv *ConfigValidator) validateSettingValue(name string, value interface{}, schema map[string]interface{}) error {
	// Get expected type
	expectedType, ok := schema["type"].(string)
	if !ok {
		return nil // No type constraint
	}

	// Validate type
	if err := cv.validateType(name, value, expectedType); err != nil {
		return err
	}

	// Type-specific validations
	switch expectedType {
	case "string":
		return cv.validateStringConstraints(name, value.(string), schema)
	case "integer", "number":
		return cv.validateNumberConstraints(name, value, schema)
	case "array":
		if array, ok := value.([]interface{}); ok {
			return cv.validateArrayConstraints(name, array, schema)
		}
	case "object":
		if obj, ok := value.(map[string]interface{}); ok {
			return cv.validateObjectConstraints(name, obj, schema)
		}
	}

	return nil
}

// validateType validates the type of a value
func (cv *ConfigValidator) validateType(name string, value interface{}, expectedType string) error {
	switch expectedType {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("field '%s': expected string, got %T", name, value)
		}
	case "integer":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			// Valid integer types
		case float64:
			// Check if it's actually an integer
			if f := value.(float64); f != float64(int64(f)) {
				return fmt.Errorf("field '%s': expected integer, got float", name)
			}
		default:
			return fmt.Errorf("field '%s': expected integer, got %T", name, value)
		}
	case "number":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			// Valid number types
		default:
			return fmt.Errorf("field '%s': expected number, got %T", name, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("field '%s': expected boolean, got %T", name, value)
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Errorf("field '%s': expected array, got %T", name, value)
		}
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("field '%s': expected object, got %T", name, value)
		}
	}

	return nil
}

// validateStringConstraints validates string-specific constraints
func (cv *ConfigValidator) validateStringConstraints(name, value string, schema map[string]interface{}) error {
	// Min length
	if minLen, exists := schema["minLength"]; exists {
		if min, ok := minLen.(float64); ok && len(value) < int(min) {
			return fmt.Errorf("field '%s': string length %d is less than minimum %d", name, len(value), int(min))
		}
	}

	// Max length
	if maxLen, exists := schema["maxLength"]; exists {
		if max, ok := maxLen.(float64); ok && len(value) > int(max) {
			return fmt.Errorf("field '%s': string length %d exceeds maximum %d", name, len(value), int(max))
		}
	}

	// Pattern
	if pattern, exists := schema["pattern"]; exists {
		if patternStr, ok := pattern.(string); ok {
			regex, err := regexp.Compile(patternStr)
			if err != nil {
				return fmt.Errorf("field '%s': invalid regex pattern: %s", name, err)
			}
			if !regex.MatchString(value) {
				return fmt.Errorf("field '%s': value does not match pattern %s", name, patternStr)
			}
		}
	}

	// Enum
	if enum, exists := schema["enum"]; exists {
		if enumArray, ok := enum.([]interface{}); ok {
			valid := false
			for _, enumValue := range enumArray {
				if enumStr, ok := enumValue.(string); ok && enumStr == value {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("field '%s': value '%s' is not in allowed enum values", name, value)
			}
		}
	}

	return nil
}

// validateNumberConstraints validates number-specific constraints
func (cv *ConfigValidator) validateNumberConstraints(name string, value interface{}, schema map[string]interface{}) error {
	var num float64
	switch v := value.(type) {
	case int:
		num = float64(v)
	case int64:
		num = float64(v)
	case float64:
		num = v
	case float32:
		num = float64(v)
	default:
		return fmt.Errorf("field '%s': unsupported number type %T", name, value)
	}

	// Minimum
	if min, exists := schema["minimum"]; exists {
		if minVal, ok := min.(float64); ok && num < minVal {
			return fmt.Errorf("field '%s': value %g is less than minimum %g", name, num, minVal)
		}
	}

	// Maximum
	if max, exists := schema["maximum"]; exists {
		if maxVal, ok := max.(float64); ok && num > maxVal {
			return fmt.Errorf("field '%s': value %g exceeds maximum %g", name, num, maxVal)
		}
	}

	// Exclusive minimum
	if exMin, exists := schema["exclusiveMinimum"]; exists {
		if minVal, ok := exMin.(float64); ok && num <= minVal {
			return fmt.Errorf("field '%s': value %g must be greater than %g", name, num, minVal)
		}
	}

	// Exclusive maximum
	if exMax, exists := schema["exclusiveMaximum"]; exists {
		if maxVal, ok := exMax.(float64); ok && num >= maxVal {
			return fmt.Errorf("field '%s': value %g must be less than %g", name, num, maxVal)
		}
	}

	return nil
}

// validateArrayConstraints validates array-specific constraints
func (cv *ConfigValidator) validateArrayConstraints(name string, value []interface{}, schema map[string]interface{}) error {
	// Min items
	if minItems, exists := schema["minItems"]; exists {
		if min, ok := minItems.(float64); ok && len(value) < int(min) {
			return fmt.Errorf("field '%s': array length %d is less than minimum %d", name, len(value), int(min))
		}
	}

	// Max items
	if maxItems, exists := schema["maxItems"]; exists {
		if max, ok := maxItems.(float64); ok && len(value) > int(max) {
			return fmt.Errorf("field '%s': array length %d exceeds maximum %d", name, len(value), int(max))
		}
	}

	// Unique items
	if uniqueItems, exists := schema["uniqueItems"]; exists {
		if unique, ok := uniqueItems.(bool); ok && unique {
			seen := make(map[string]bool)
			for i, item := range value {
				itemStr := fmt.Sprintf("%v", item)
				if seen[itemStr] {
					return fmt.Errorf("field '%s': duplicate item at index %d", name, i)
				}
				seen[itemStr] = true
			}
		}
	}

	return nil
}

// validateObjectConstraints validates object-specific constraints
func (cv *ConfigValidator) validateObjectConstraints(name string, value map[string]interface{}, schema map[string]interface{}) error {
	// Min properties
	if minProps, exists := schema["minProperties"]; exists {
		if min, ok := minProps.(float64); ok && len(value) < int(min) {
			return fmt.Errorf("field '%s': object has %d properties, minimum is %d", name, len(value), int(min))
		}
	}

	// Max properties
	if maxProps, exists := schema["maxProperties"]; exists {
		if max, ok := maxProps.(float64); ok && len(value) > int(max) {
			return fmt.Errorf("field '%s': object has %d properties, maximum is %d", name, len(value), int(max))
		}
	}

	return nil
}

// validateResourceLimits validates resource limit constraints
func (cv *ConfigValidator) validateResourceLimits(resources *interfaces.ResourceLimits) error {
	if resources == nil {
		return nil
	}

	if resources.MaxMemoryMB < 0 {
		return fmt.Errorf("max memory cannot be negative")
	}

	if resources.MaxCPUPercent < 0 || resources.MaxCPUPercent > 100 {
		return fmt.Errorf("max CPU percent must be between 0 and 100")
	}

	if resources.MaxConcurrency < 0 {
		return fmt.Errorf("max concurrency cannot be negative")
	}

	if resources.MaxExecutionTime < 0 {
		return fmt.Errorf("max execution time cannot be negative")
	}

	return nil
}

// validatePermissions validates permission values
func (cv *ConfigValidator) validatePermissions(permissions []string) error {
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

	for _, permission := range permissions {
		if !validPermissions[permission] {
			return fmt.Errorf("unknown permission: %s", permission)
		}
	}

	return nil
}
