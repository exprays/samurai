// Password hashing and verification

package auth

import (
	"crypto/rand"
	"errors"
	"regexp"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordTooShort    = errors.New("password must be at least 8 characters long")
	ErrPasswordTooLong     = errors.New("password must be less than 128 characters long")
	ErrPasswordMismatch    = errors.New("password does not match")
	ErrPasswordTooWeak     = errors.New("password is too weak")
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoNumber    = errors.New("password must contain at least one number")
	ErrPasswordNoSpecial   = errors.New("password must contain at least one special character")
	ErrPasswordCommon      = errors.New("password is too common")
)

type PasswordService struct {
	cost int
}

type PasswordStrength struct {
	Score      int      `json:"score"` // 0-5 strength score
	IsValid    bool     `json:"is_valid"`
	Feedback   []string `json:"feedback"`
	HasUpper   bool     `json:"has_upper"`
	HasLower   bool     `json:"has_lower"`
	HasNumber  bool     `json:"has_number"`
	HasSpecial bool     `json:"has_special"`
	Length     int      `json:"length"`
}

func NewPasswordService() *PasswordService {
	return &PasswordService{
		cost: bcrypt.DefaultCost, // Cost of 10 is reasonable for most applications
	}
}

// HashPassword hashes a plain text password using bcrypt
func (p *PasswordService) HashPassword(password string) (string, error) {
	// Validate password before hashing
	if err := p.ValidatePasswordStrength(password); err != nil {
		return "", err
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against its hash
func (p *PasswordService) VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrPasswordMismatch
		}
		return err
	}
	return nil
}

// ValidatePasswordStrength validates password strength with comprehensive rules
func (p *PasswordService) ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}

	if len(password) > 128 {
		return ErrPasswordTooLong
	}

	strength := p.AnalyzePasswordStrength(password)

	if !strength.IsValid {
		if !strength.HasUpper {
			return ErrPasswordNoUppercase
		}
		if !strength.HasLower {
			return ErrPasswordNoLowercase
		}
		if !strength.HasNumber {
			return ErrPasswordNoNumber
		}
		if !strength.HasSpecial {
			return ErrPasswordNoSpecial
		}
		if strength.Score < 3 {
			return ErrPasswordTooWeak
		}
	}

	// Check against common passwords
	if p.isCommonPassword(password) {
		return ErrPasswordCommon
	}

	return nil
}

// AnalyzePasswordStrength provides detailed password strength analysis
func (p *PasswordService) AnalyzePasswordStrength(password string) *PasswordStrength {
	strength := &PasswordStrength{
		Length:   len(password),
		Feedback: make([]string, 0),
	}

	// Check character types
	for _, char := range password {
		if unicode.IsUpper(char) {
			strength.HasUpper = true
		}
		if unicode.IsLower(char) {
			strength.HasLower = true
		}
		if unicode.IsNumber(char) {
			strength.HasNumber = true
		}
		if unicode.IsPunct(char) || unicode.IsSymbol(char) {
			strength.HasSpecial = true
		}
	}

	// Calculate score based on criteria
	score := 0

	// Length scoring
	if strength.Length >= 8 {
		score++
	}
	if strength.Length >= 12 {
		score++
	}

	// Character type scoring
	if strength.HasUpper {
		score++
	} else {
		strength.Feedback = append(strength.Feedback, "Add uppercase letters")
	}

	if strength.HasLower {
		score++
	} else {
		strength.Feedback = append(strength.Feedback, "Add lowercase letters")
	}

	if strength.HasNumber {
		score++
	} else {
		strength.Feedback = append(strength.Feedback, "Add numbers")
	}

	if strength.HasSpecial {
		score++
	} else {
		strength.Feedback = append(strength.Feedback, "Add special characters (!@#$%^&*)")
	}

	// Additional complexity checks
	if p.hasRepeatingPatterns(password) {
		score--
		strength.Feedback = append(strength.Feedback, "Avoid repeating patterns")
	}

	if p.hasSequentialPatterns(password) {
		score--
		strength.Feedback = append(strength.Feedback, "Avoid sequential patterns")
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 5 {
		score = 5
	}

	strength.Score = score

	// Password is valid if it meets minimum requirements
	strength.IsValid = strength.Length >= 8 &&
		strength.HasUpper &&
		strength.HasLower &&
		strength.HasNumber &&
		strength.HasSpecial &&
		score >= 3

	if strength.IsValid && len(strength.Feedback) == 0 {
		strength.Feedback = append(strength.Feedback, "Strong password")
	}

	return strength
}

// hasRepeatingPatterns checks for repeating character patterns
func (p *PasswordService) hasRepeatingPatterns(password string) bool {
	// Check for 3+ consecutive identical characters
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i+1] == password[i+2] {
			return true
		}
	}
	return false
}

// hasSequentialPatterns checks for sequential patterns
func (p *PasswordService) hasSequentialPatterns(password string) bool {
	sequences := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"qwertyuiop",
		"asdfghjkl",
		"zxcvbnm",
	}

	password = regexp.MustCompile(`\s+`).ReplaceAllString(password, "")

	for _, seq := range sequences {
		for i := 0; i <= len(seq)-4; i++ {
			if len(password) >= 4 {
				substring := seq[i : i+4]
				if regexp.MustCompile(substring).MatchString(password) {
					return true
				}
				// Check reverse sequence
				runes := []rune(substring)
				for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
					runes[i], runes[j] = runes[j], runes[i]
				}
				reversed := string(runes)
				if regexp.MustCompile(reversed).MatchString(password) {
					return true
				}
			}
		}
	}
	return false
}

// isCommonPassword checks against a list of common passwords
func (p *PasswordService) isCommonPassword(password string) bool {
	// List of most common passwords - in production, this should be a larger list
	// or loaded from a file/database
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "qwerty",
		"letmein", "welcome", "monkey", "1234567890", "abc123",
		"Password1", "password1", "123456789", "welcome123",
		"admin123", "root", "test", "guest", "user", "demo",
		"changeme", "default", "temp", "temporary", "sample",
	}

	lowerPassword := regexp.MustCompile(`\s+`).ReplaceAllString(password, "")
	lowerPassword = regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(lowerPassword, "")

	for _, common := range commonPasswords {
		if regexp.MustCompile(`(?i)` + regexp.QuoteMeta(common)).MatchString(lowerPassword) {
			return true
		}
	}
	return false
}

// GenerateSecurePassword generates a cryptographically secure password
func (p *PasswordService) GenerateSecurePassword(length int) (string, error) {
	if length < 8 {
		length = 12
	}
	if length > 128 {
		length = 128
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"

	password := make([]byte, length)

	// Ensure we have at least one character from each required type
	charTypes := []string{
		"abcdefghijklmnopqrstuvwxyz", // lowercase
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ", // uppercase
		"0123456789",                 // numbers
		"!@#$%^&*()_+-=[]{}|;:,.<>?", // special characters
	}

	// Fill first 4 positions with required character types
	for i := 0; i < 4 && i < length; i++ {
		typeChars := charTypes[i]
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", err
		}
		password[i] = typeChars[randomBytes[0]%byte(len(typeChars))]
	}

	// Fill remaining positions with random characters from full charset
	for i := 4; i < length; i++ {
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", err
		}
		password[i] = charset[randomBytes[0]%byte(len(charset))]
	}

	// Shuffle the password to avoid predictable patterns
	for i := len(password) - 1; i > 0; i-- {
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", err
		}
		j := int(randomBytes[0]) % (i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password), nil
}

// ValidatePasswordPolicy validates password against configurable policy
func (p *PasswordService) ValidatePasswordPolicy(password string, policy *PasswordPolicy) error {
	if policy == nil {
		return p.ValidatePasswordStrength(password) // Use default policy
	}

	if len(password) < policy.MinLength {
		return ErrPasswordTooShort
	}

	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		return ErrPasswordTooLong
	}

	strength := p.AnalyzePasswordStrength(password)

	if policy.RequireUppercase && !strength.HasUpper {
		return ErrPasswordNoUppercase
	}

	if policy.RequireLowercase && !strength.HasLower {
		return ErrPasswordNoLowercase
	}

	if policy.RequireNumbers && !strength.HasNumber {
		return ErrPasswordNoNumber
	}

	if policy.RequireSpecialChars && !strength.HasSpecial {
		return ErrPasswordNoSpecial
	}

	if policy.MinScore > 0 && strength.Score < policy.MinScore {
		return ErrPasswordTooWeak
	}

	if policy.ForbidCommon && p.isCommonPassword(password) {
		return ErrPasswordCommon
	}

	return nil
}
