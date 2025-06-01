package middleware

import (
	"net/http"
	"strings"

	"samurai/backend/internal/auth"

	"github.com/gin-gonic/gin"
)

// AuthRequired middleware validates JWT tokens
func AuthRequired(authManager *auth.AuthManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Check for Bearer token format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
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
			switch err {
			case auth.ErrTokenExpired:
				message = "Token has expired"
			case auth.ErrTokenInvalid:
				message = "Invalid token"
			case auth.ErrTokenMalformed:
				message = "Malformed token"
			default:
				message = "Token validation failed"
			}

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": message,
			})
			c.Abort()
			return
		}

		// Set user information in context
		auth.SetUserInContext(c, claims)

		c.Next()
	}
}
