// Data Transfer Objects for authentication

package auth

import "github.com/google/uuid"

// RegisterRequest represents user registration request
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required,min=3,max=50"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required,min=1,max=100"`
	LastName  string `json:"last_name" binding:"required,min=1,max=100"`
}

// LoginRequest represents user login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// AuthResponse represents authentication response with token
type AuthResponse struct {
	Token     string   `json:"token"`
	TokenType string   `json:"token_type"`
	ExpiresIn int      `json:"expires_in"`
	User      UserInfo `json:"user"`
}

// UserInfo represents user information in responses
type UserInfo struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt string    `json:"created_at"`
}

// ErrorResponse represents error response
type ErrorResponse struct {
	Error   string            `json:"error"`
	Message string            `json:"message,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}
