package plugin

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"samurai/backend/internal/plugin/interfaces"

	"go.uber.org/zap"
)

// SchemaValidator provides comprehensive JSON schema validation for plugin configurations
type SchemaValidator struct {
	logger *zap.SugaredLogger
}

// NewSchemaValidator creates a new schema validator
func NewSchemaValidator(logger *zap.SugaredLogger) *SchemaValidator {
	return &SchemaValidator{
		logger: logger.Named("schema-validator"),
	}
}

// ValidationError represents a schema validation error
type ValidationError struct {
	Path    string      `json:"path"`
	Message string      `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

func (e ValidationError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("validation error at '%s': %s", e.Path, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// ValidationResult contains the results of schema validation
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}

// ValidatePluginConfig validates a plugin configuration against its schema
func (v *SchemaValidator) ValidatePluginConfig(config *interfaces.PluginConfig, schema map[string]interface{}) *ValidationResult {
	result := &ValidationResult{
		Valid:  true,
		Errors: []ValidationError{},
	}

	if schema == nil {
		v.logger.Debug("No schema provided for validation")
		return result
	}

	if config == nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Message: "configuration cannot be nil",
		})
		return result
	}

	// Validate the settings object against the schema
	errors := v.validateValue(config.Settings, schema, "")
	result.Errors = append(result.Errors, errors...)
	result.Valid = len(result.Errors) == 0

	return result
}

// ValidateConfigSettings validates configuration settings against a schema
func (v *SchemaValidator) ValidateConfigSettings(settings map[string]interface{}, schema map[string]interface{}) *ValidationResult {
	result := &ValidationResult{
		Valid:  true,
		Errors: []ValidationError{},
	}

	if schema == nil {
		return result
	}

	errors := v.validateValue(settings, schema, "")
	result.Errors = append(result.Errors, errors...)
	result.Valid = len(result.Errors) == 0

	return result
}

// validateValue validates a value against a schema
func (v *SchemaValidator) validateValue(value interface{}, schema map[string]interface{}, path string) []ValidationError {
	var errors []ValidationError

	// Check if value is required but missing
	if value == nil {
		if required, exists := schema["required"]; exists {
			if req, ok := required.(bool); ok && req {
				errors = append(errors, ValidationError{
					Path:    path,
					Message: "required value is missing",
				})
			}
		}
		return errors
	}

	// Get schema type
	schemaType, typeExists := schema["type"].(string)
	if !typeExists {
		// If no type specified, try to infer from value
		schemaType = v.inferType(value)
	}

	// Validate based on type
	switch schemaType {
	case "object":
		errors = append(errors, v.validateObject(value, schema, path)...)
	case "array":
		errors = append(errors, v.validateArray(value, schema, path)...)
	case "string":
		errors = append(errors, v.validateString(value, schema, path)...)
	case "number", "integer":
		errors = append(errors, v.validateNumber(value, schema, path)...)
	case "boolean":
		errors = append(errors, v.validateBoolean(value, schema, path)...)
	case "null":
		errors = append(errors, v.validateNull(value, schema, path)...)
	default:
		errors = append(errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("unsupported schema type: %s", schemaType),
			Value:   value,
		})
	}

	// Check enum constraint
	if enum, exists := schema["enum"]; exists {
		if enumArray, ok := enum.([]interface{}); ok {
			errors = append(errors, v.validateEnum(value, enumArray, path)...)
		}
	}

	// Check const constraint
	if constValue, exists := schema["const"]; exists {
		if !v.deepEqual(value, constValue) {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value must be equal to %v", constValue),
				Value:   value,
			})
		}
	}

	return errors
}

// validateObject validates an object against an object schema
func (v *SchemaValidator) validateObject(value interface{}, schema map[string]interface{}, path string) []ValidationError {
	var errors []ValidationError

	obj, ok := value.(map[string]interface{})
	if !ok {
		errors = append(errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("expected object, got %T", value),
			Value:   value,
		})
		return errors
	}

	// Check properties
	if properties, exists := schema["properties"]; exists {
		if propMap, ok := properties.(map[string]interface{}); ok {
			// Validate each property
			for propName, propSchema := range propMap {
				propPath := v.buildPath(path, propName)
				propValue, propExists := obj[propName]

				if propSchema, ok := propSchema.(map[string]interface{}); ok {
					if propExists {
						errors = append(errors, v.validateValue(propValue, propSchema, propPath)...)
					} else {
						// Check if property is required
						if required, reqExists := propSchema["required"]; reqExists {
							if req, ok := required.(bool); ok && req {
								errors = append(errors, ValidationError{
									Path:    propPath,
									Message: "required property is missing",
								})
							}
						}
					}
				}
			}
		}
	}

	// Check required properties (alternative format)
	if required, exists := schema["required"]; exists {
		if reqArray, ok := required.([]interface{}); ok {
			for _, reqField := range reqArray {
				if fieldName, ok := reqField.(string); ok {
					if _, exists := obj[fieldName]; !exists {
						errors = append(errors, ValidationError{
							Path:    v.buildPath(path, fieldName),
							Message: "required property is missing",
						})
					}
				}
			}
		}
	}

	// Check additionalProperties
	if additionalProps, exists := schema["additionalProperties"]; exists {
		if additional, ok := additionalProps.(bool); ok && !additional {
			// Additional properties not allowed
			properties, _ := schema["properties"].(map[string]interface{})
			for propName := range obj {
				if properties == nil {
					errors = append(errors, ValidationError{
						Path:    v.buildPath(path, propName),
						Message: "additional property not allowed",
						Value:   obj[propName],
					})
				} else if _, allowed := properties[propName]; !allowed {
					errors = append(errors, ValidationError{
						Path:    v.buildPath(path, propName),
						Message: "additional property not allowed",
						Value:   obj[propName],
					})
				}
			}
		}
	}

	// Check object constraints
	if minProps, exists := schema["minProperties"]; exists {
		if min, ok := minProps.(float64); ok && len(obj) < int(min) {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("object must have at least %d properties, has %d", int(min), len(obj)),
				Value:   len(obj),
			})
		}
	}

	if maxProps, exists := schema["maxProperties"]; exists {
		if max, ok := maxProps.(float64); ok && len(obj) > int(max) {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("object must have at most %d properties, has %d", int(max), len(obj)),
				Value:   len(obj),
			})
		}
	}

	return errors
}

// validateArray validates an array against an array schema
func (v *SchemaValidator) validateArray(value interface{}, schema map[string]interface{}, path string) []ValidationError {
	var errors []ValidationError

	array, ok := value.([]interface{})
	if !ok {
		errors = append(errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("expected array, got %T", value),
			Value:   value,
		})
		return errors
	}

	// Validate array length constraints
	if minItems, exists := schema["minItems"]; exists {
		if min, ok := minItems.(float64); ok && len(array) < int(min) {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("array must have at least %d items, has %d", int(min), len(array)),
				Value:   len(array),
			})
		}
	}

	if maxItems, exists := schema["maxItems"]; exists {
		if max, ok := maxItems.(float64); ok && len(array) > int(max) {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("array must have at most %d items, has %d", int(max), len(array)),
				Value:   len(array),
			})
		}
	}

	// Validate uniqueness
	if uniqueItems, exists := schema["uniqueItems"]; exists {
		if unique, ok := uniqueItems.(bool); ok && unique {
			seen := make(map[string]bool)
			for i, item := range array {
				itemStr := fmt.Sprintf("%v", item)
				if seen[itemStr] {
					errors = append(errors, ValidationError{
						Path:    fmt.Sprintf("%s[%d]", path, i),
						Message: "array items must be unique",
						Value:   item,
					})
				}
				seen[itemStr] = true
			}
		}
	}

	// Validate items schema
	if items, exists := schema["items"]; exists {
		if itemSchema, ok := items.(map[string]interface{}); ok {
			// Single schema for all items
			for i, item := range array {
				itemPath := fmt.Sprintf("%s[%d]", path, i)
				errors = append(errors, v.validateValue(item, itemSchema, itemPath)...)
			}
		} else if itemSchemas, ok := items.([]interface{}); ok {
			// Array of schemas (tuple validation)
			for i, item := range array {
				if i < len(itemSchemas) {
					if itemSchema, ok := itemSchemas[i].(map[string]interface{}); ok {
						itemPath := fmt.Sprintf("%s[%d]", path, i)
						errors = append(errors, v.validateValue(item, itemSchema, itemPath)...)
					}
				}
			}
		}
	}

	return errors
}

// validateString validates a string against a string schema
func (v *SchemaValidator) validateString(value interface{}, schema map[string]interface{}, path string) []ValidationError {
	var errors []ValidationError

	str, ok := value.(string)
	if !ok {
		errors = append(errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("expected string, got %T", value),
			Value:   value,
		})
		return errors
	}

	// Length constraints
	if minLength, exists := schema["minLength"]; exists {
		if min, ok := minLength.(float64); ok && len(str) < int(min) {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("string length %d is less than minimum %d", len(str), int(min)),
				Value:   len(str),
			})
		}
	}

	if maxLength, exists := schema["maxLength"]; exists {
		if max, ok := maxLength.(float64); ok && len(str) > int(max) {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("string length %d exceeds maximum %d", len(str), int(max)),
				Value:   len(str),
			})
		}
	}

	// Pattern constraint
	if pattern, exists := schema["pattern"]; exists {
		if patternStr, ok := pattern.(string); ok {
			regex, err := regexp.Compile(patternStr)
			if err != nil {
				errors = append(errors, ValidationError{
					Path:    path,
					Message: fmt.Sprintf("invalid regex pattern: %s", err.Error()),
				})
			} else if !regex.MatchString(str) {
				errors = append(errors, ValidationError{
					Path:    path,
					Message: fmt.Sprintf("string does not match pattern: %s", patternStr),
					Value:   str,
				})
			}
		}
	}

	// Format constraint
	if format, exists := schema["format"]; exists {
		if formatStr, ok := format.(string); ok {
			if err := v.validateStringFormat(str, formatStr); err != nil {
				errors = append(errors, ValidationError{
					Path:    path,
					Message: fmt.Sprintf("string format validation failed: %s", err.Error()),
					Value:   str,
				})
			}
		}
	}

	return errors
}

// validateNumber validates a number against a number schema
func (v *SchemaValidator) validateNumber(value interface{}, schema map[string]interface{}, path string) []ValidationError {
	var errors []ValidationError

	var num float64
	var ok bool

	switch v := value.(type) {
	case float64:
		num, ok = v, true
	case float32:
		num, ok = float64(v), true
	case int:
		num, ok = float64(v), true
	case int32:
		num, ok = float64(v), true
	case int64:
		num, ok = float64(v), true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			num, ok = f, true
		}
	}

	if !ok {
		errors = append(errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("expected number, got %T", value),
			Value:   value,
		})
		return errors
	}

	// Type-specific validation for integer
	if schemaType, exists := schema["type"]; exists {
		if schemaType == "integer" {
			if num != float64(int64(num)) {
				errors = append(errors, ValidationError{
					Path:    path,
					Message: "expected integer, got float",
					Value:   num,
				})
			}
		}
	}

	// Range constraints
	if minimum, exists := schema["minimum"]; exists {
		if min, ok := minimum.(float64); ok && num < min {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value %g is less than minimum %g", num, min),
				Value:   num,
			})
		}
	}

	if maximum, exists := schema["maximum"]; exists {
		if max, ok := maximum.(float64); ok && num > max {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value %g exceeds maximum %g", num, max),
				Value:   num,
			})
		}
	}

	if exclusiveMinimum, exists := schema["exclusiveMinimum"]; exists {
		if min, ok := exclusiveMinimum.(float64); ok && num <= min {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value %g must be greater than %g", num, min),
				Value:   num,
			})
		}
	}

	if exclusiveMaximum, exists := schema["exclusiveMaximum"]; exists {
		if max, ok := exclusiveMaximum.(float64); ok && num >= max {
			errors = append(errors, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("value %g must be less than %g", num, max),
				Value:   num,
			})
		}
	}

	// Multiple of constraint
	if multipleOf, exists := schema["multipleOf"]; exists {
		if multiple, ok := multipleOf.(float64); ok && multiple > 0 {
			if remainder := num - (multiple * float64(int(num/multiple))); remainder != 0 {
				errors = append(errors, ValidationError{
					Path:    path,
					Message: fmt.Sprintf("value %g is not a multiple of %g", num, multiple),
					Value:   num,
				})
			}
		}
	}

	return errors
}

// validateBoolean validates a boolean against a boolean schema
func (v *SchemaValidator) validateBoolean(value interface{}, schema map[string]interface{}, path string) []ValidationError {
	var errors []ValidationError

	if _, ok := value.(bool); !ok {
		errors = append(errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("expected boolean, got %T", value),
			Value:   value,
		})
	}

	return errors
}

// validateNull validates a null value
func (v *SchemaValidator) validateNull(value interface{}, schema map[string]interface{}, path string) []ValidationError {
	var errors []ValidationError

	if value != nil {
		errors = append(errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("expected null, got %T", value),
			Value:   value,
		})
	}

	return errors
}

// validateEnum validates a value against an enum constraint
func (v *SchemaValidator) validateEnum(value interface{}, enum []interface{}, path string) []ValidationError {
	var errors []ValidationError

	for _, enumValue := range enum {
		if v.deepEqual(value, enumValue) {
			return errors // Valid enum value
		}
	}

	errors = append(errors, ValidationError{
		Path:    path,
		Message: "value is not one of the allowed enum values",
		Value:   value,
	})

	return errors
}

// validateStringFormat validates string formats (email, uri, etc.)
func (v *SchemaValidator) validateStringFormat(value string, format string) error {
	switch format {
	case "email":
		return v.validateEmail(value)
	case "uri", "url":
		return v.validateURI(value)
	case "uuid":
		return v.validateUUID(value)
	case "date":
		return v.validateDate(value)
	case "date-time":
		return v.validateDateTime(value)
	case "ipv4":
		return v.validateIPv4(value)
	case "ipv6":
		return v.validateIPv6(value)
	default:
		// Unknown format, skip validation
		return nil
	}
}

// validateEmail validates email format
func (v *SchemaValidator) validateEmail(email string) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// validateURI validates URI format
func (v *SchemaValidator) validateURI(uri string) error {
	// Simplified URI validation
	if !strings.Contains(uri, "://") {
		return fmt.Errorf("invalid URI format")
	}
	return nil
}

// validateUUID validates UUID format
func (v *SchemaValidator) validateUUID(uuid string) error {
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if !uuidRegex.MatchString(uuid) {
		return fmt.Errorf("invalid UUID format")
	}
	return nil
}

// validateDate validates date format (YYYY-MM-DD)
func (v *SchemaValidator) validateDate(date string) error {
	dateRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	if !dateRegex.MatchString(date) {
		return fmt.Errorf("invalid date format, expected YYYY-MM-DD")
	}
	return nil
}

// validateDateTime validates date-time format (RFC3339)
func (v *SchemaValidator) validateDateTime(dateTime string) error {
	// Simplified RFC3339 validation
	dateTimeRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	if !dateTimeRegex.MatchString(dateTime) {
		return fmt.Errorf("invalid date-time format, expected RFC3339")
	}
	return nil
}

// validateIPv4 validates IPv4 address format
func (v *SchemaValidator) validateIPv4(ip string) error {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid IPv4 format")
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return fmt.Errorf("invalid IPv4 format")
		}
	}
	return nil
}

// validateIPv6 validates IPv6 address format
func (v *SchemaValidator) validateIPv6(ip string) error {
	// Simplified IPv6 validation
	if len(ip) == 0 {
		return fmt.Errorf("invalid IPv6 format")
	}

	// Basic validation for IPv6 format
	if strings.Count(ip, ":") < 2 {
		return fmt.Errorf("invalid IPv6 format")
	}

	return nil
}

// Helper functions

// inferType infers the JSON schema type from a Go value
func (v *SchemaValidator) inferType(value interface{}) string {
	if value == nil {
		return "null"
	}

	switch value.(type) {
	case bool:
		return "boolean"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "integer"
	case float32, float64:
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return "unknown"
	}
}

// buildPath builds a JSON path string
func (v *SchemaValidator) buildPath(parentPath, key string) string {
	if parentPath == "" {
		return key
	}
	return parentPath + "." + key
}

// deepEqual performs deep equality comparison
func (v *SchemaValidator) deepEqual(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}
