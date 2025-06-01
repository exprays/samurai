package config

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

func validateConfig(config *Config) error {
	if err := validate.Struct(config); err != nil {
		var validationErrors []string
		for _, err := range err.(validator.ValidationErrors) {
			validationErrors = append(validationErrors, fmt.Sprintf(
				"field '%s' failed validation: %s",
				err.Field(),
				err.Tag(),
			))
		}
		return fmt.Errorf("validation errors: %s", strings.Join(validationErrors, ", "))
	}

	// Custom validations
	if config.Security.BcryptCost < 10 || config.Security.BcryptCost > 15 {
		return fmt.Errorf("bcrypt cost must be between 10 and 15")
	}

	if len(config.JWT.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	return nil
}

func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

func (c *Config) GetDSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
		c.Database.SSLMode,
	)
}
