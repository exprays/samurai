package auth

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Context keys for storing user information
const (
	UserIDKey    = "user_id"
	UserEmailKey = "user_email"
	UserRoleKey  = "user_role"
	ClaimsKey    = "jwt_claims"
)

// GetUserIDFromContext extracts user ID from Gin context
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	if userID, exists := c.Get(UserIDKey); exists {
		if id, ok := userID.(uuid.UUID); ok {
			return id, true
		}
	}
	return uuid.Nil, false
}

// GetUserEmailFromContext extracts user email from Gin context
func GetUserEmailFromContext(c *gin.Context) (string, bool) {
	if email, exists := c.Get(UserEmailKey); exists {
		if emailStr, ok := email.(string); ok {
			return emailStr, true
		}
	}
	return "", false
}

// GetUserRoleFromContext extracts user role from Gin context
func GetUserRoleFromContext(c *gin.Context) (string, bool) {
	if role, exists := c.Get(UserRoleKey); exists {
		if roleStr, ok := role.(string); ok {
			return roleStr, true
		}
	}
	return "", false
}

// GetClaimsFromContext extracts JWT claims from Gin context
func GetClaimsFromContext(c *gin.Context) (*JWTClaims, bool) {
	if claims, exists := c.Get(ClaimsKey); exists {
		if jwtClaims, ok := claims.(*JWTClaims); ok {
			return jwtClaims, true
		}
	}
	return nil, false
}

// SetUserInContext sets user information in Gin context
func SetUserInContext(c *gin.Context, claims *JWTClaims) {
	c.Set(UserIDKey, claims.UserID)
	c.Set(UserEmailKey, claims.Email)
	c.Set(UserRoleKey, claims.Role)
	c.Set(ClaimsKey, claims)
}

// GetUserIDFromStandardContext extracts user ID from standard context
func GetUserIDFromStandardContext(ctx context.Context) (uuid.UUID, bool) {
	if userID := ctx.Value(UserIDKey); userID != nil {
		if id, ok := userID.(uuid.UUID); ok {
			return id, true
		}
	}
	return uuid.Nil, false
}
