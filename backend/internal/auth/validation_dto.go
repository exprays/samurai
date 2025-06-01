package auth

// PasswordStrengthRequest represents password strength check request
type PasswordStrengthRequest struct {
    Password string `json:"password" binding:"required"`
}

// PasswordStrengthResponse represents password strength check response
type PasswordStrengthResponse struct {
    Strength *PasswordStrength `json:"strength"`
    IsValid  bool              `json:"is_valid"`
    Policy   *PasswordPolicy   `json:"policy"`
}

// GeneratePasswordRequest represents password generation request
type GeneratePasswordRequest struct {
    Length int `json:"length" binding:"min=8,max=128"`
}

// GeneratePasswordResponse represents password generation response
type GeneratePasswordResponse struct {
    Password string            `json:"password"`
    Strength *PasswordStrength `json:"strength"`
}