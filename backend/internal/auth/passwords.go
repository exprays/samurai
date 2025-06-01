package auth

import (
	"crypto/rand"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

type PasswordValidator struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSpecial   bool
}

func NewPasswordValidator(minLength int) *PasswordValidator {
	return &PasswordValidator{
		MinLength:        minLength,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSpecial:   true,
	}
}

func (pv *PasswordValidator) Validate(password string) error {
	if len(password) < pv.MinLength {
		return errors.New("password must be at least " + string(rune(pv.MinLength)) + " characters long")
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	var validationErrors []string

	if pv.RequireUppercase && !hasUpper {
		validationErrors = append(validationErrors, "password must contain at least one uppercase letter")
	}
	if pv.RequireLowercase && !hasLower {
		validationErrors = append(validationErrors, "password must contain at least one lowercase letter")
	}
	if pv.RequireNumbers && !hasNumber {
		validationErrors = append(validationErrors, "password must contain at least one number")
	}
	if pv.RequireSpecial && !hasSpecial {
		validationErrors = append(validationErrors, "password must contain at least one special character")
	}

	// Check for common patterns
	if pv.hasCommonPatterns(password) {
		validationErrors = append(validationErrors, "password contains common patterns and is not secure")
	}

	if len(validationErrors) > 0 {
		return errors.New(validationErrors[0]) // Return first error
	}

	return nil
}

func (pv *PasswordValidator) hasCommonPatterns(password string) bool {
	lowercasePassword := strings.ToLower(password)

	// Common patterns to avoid
	commonPatterns := []string{
		"password", "123456", "qwerty", "abc123", "admin", "user",
		"login", "welcome", "letmein", "monkey", "dragon",
	}

	for _, pattern := range commonPatterns {
		if strings.Contains(lowercasePassword, pattern) {
			return true
		}
	}

	// Check for keyboard patterns
	keyboardPatterns := []string{
		"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
	}

	for _, pattern := range keyboardPatterns {
		if strings.Contains(lowercasePassword, pattern) {
			return true
		}
	}

	// Check for repeated characters
	repeated := regexp.MustCompile(`(.)\1{2,}`)
	if repeated.MatchString(password) {
		return true
	}

	return false
}

func HashPassword(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

	if length < 1 {
		return "", errors.New("password length must be at least 1")
	}

	password := make([]byte, length)
	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}
