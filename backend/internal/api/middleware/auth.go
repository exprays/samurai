package middleware

import (
	"net/http"
	"strings"

	"samurai/backend/internal/auth"

	"github.com/gin-gonic/gin"
)

// AuthRequired middleware validates JWT tokens and sets user context
func AuthRequired(authManager *auth.AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := authManager.GetLogger()

		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Warnf("Missing authorization header from IP: %s", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Check for Bearer token format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			logger.Warnf("Invalid authorization header format from IP: %s", c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid authorization header format. Expected: Bearer <token>",
			})
			c.Abort()
			return
		}

		tokenString := tokenParts[1]
		jwtService := authManager.GetJWTService()

		// Validate token
		claims, err := jwtService.ValidateToken(tokenString)
		if err != nil {
			var message string
			var errorCode string

			switch err {
			case auth.ErrTokenExpired:
				message = "Token has expired"
				errorCode = "token_expired"
			case auth.ErrTokenInvalid:
				message = "Invalid token"
				errorCode = "token_invalid"
			case auth.ErrTokenMalformed:
				message = "Malformed token"
				errorCode = "token_malformed"
			default:
				message = "Token validation failed"
				errorCode = "token_validation_failed"
			}

			logger.Warnf("Token validation failed for IP %s: %s", c.ClientIP(), err.Error())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   errorCode,
				"message": message,
			})
			c.Abort()
			return
		}

		// Verify user is still active
		rbac := authManager.GetRBAC()
		user, err := rbac.GetUserWithRole(claims.UserID)
		if err != nil {
			logger.Errorf("Error retrieving user %s: %v", claims.UserID, err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "user_not_found",
				"message": "User account not found",
			})
			c.Abort()
			return
		}

		if !user.IsActive {
			logger.Warnf("Inactive user %s attempted access from IP: %s", user.Email, c.ClientIP())
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "account_disabled",
				"message": "User account has been disabled",
			})
			c.Abort()
			return
		}

		// Set user information in context
		auth.SetUserInContext(c, claims)

		// Add additional context for logging
		c.Set("user_email", user.Email)
		c.Set("user_role", user.GetRoleName())

		logger.Debugf("User %s authenticated successfully from IP: %s", user.Email, c.ClientIP())
		c.Next()
	}
}

// OptionalAuth middleware validates JWT tokens if present but doesn't require them
func OptionalAuth(authManager *auth.AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Check for Bearer token format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := tokenParts[1]
		jwtService := authManager.GetJWTService()

		// Validate token
		claims, err := jwtService.ValidateToken(tokenString)
		if err != nil {
			// For optional auth, we don't fail on invalid tokens
			c.Next()
			return
		}

		// Verify user is still active
		rbac := authManager.GetRBAC()
		user, err := rbac.GetUserWithRole(claims.UserID)
		if err != nil || !user.IsActive {
			c.Next()
			return
		}

		// Set user information in context
		auth.SetUserInContext(c, claims)
		c.Set("user_email", user.Email)
		c.Set("user_role", user.GetRoleName())

		c.Next()
	}
}

// TokenRefresh middleware handles token refresh
func TokenRefresh(authManager *auth.AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid_request",
				"message": "Invalid request body",
			})
			return
		}

		jwtService := authManager.GetJWTService()
		logger := authManager.GetLogger()

		// Refresh the token
		newToken, err := jwtService.RefreshToken(req.RefreshToken)
		if err != nil {
			var message string
			var errorCode string

			switch err {
			case auth.ErrTokenInvalid:
				message = "Invalid refresh token"
				errorCode = "invalid_refresh_token"
			case auth.ErrTokenMalformed:
				message = "Malformed refresh token"
				errorCode = "malformed_refresh_token"
			default:
				message = "Token refresh failed"
				errorCode = "refresh_failed"
			}

			logger.Warnf("Token refresh failed from IP %s: %s", c.ClientIP(), err.Error())
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   errorCode,
				"message": message,
			})
			return
		}

		logger.Infof("Token refreshed successfully from IP: %s", c.ClientIP())
		c.JSON(http.StatusOK, gin.H{
			"token":      newToken,
			"token_type": "Bearer",
			"expires_in": 24 * 3600, // 24 hours
		})
	}
}
