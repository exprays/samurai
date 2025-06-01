package middleware

import (
	"net/http"
	"strings"

	"samurai/backend/internal/auth"

	"github.com/gin-gonic/gin"
)

// RequirePermission middleware checks if user has specific permission
func RequirePermission(authManager *auth.AuthManager, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check if user is authenticated
		userID, exists := auth.GetUserIDFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Check permission
		rbac := authManager.GetRBAC()
		hasPermission, err := rbac.CheckPermission(userID, permission)
		if err != nil {
			authManager.GetLogger().Errorf("Error checking permission: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Permission check failed",
			})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":    "Insufficient permissions",
				"required": permission,
				"message":  "You don't have permission to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware checks if user has specific role
func RequireRole(authManager *auth.AuthManager, roleName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check if user is authenticated
		userID, exists := auth.GetUserIDFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Get user with role
		rbac := authManager.GetRBAC()
		user, err := rbac.GetUserWithRole(userID)
		if err != nil {
			authManager.GetLogger().Errorf("Error getting user role: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Role check failed",
			})
			c.Abort()
			return
		}

		if !user.HasRole(roleName) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":    "Insufficient role",
				"required": roleName,
				"current":  user.GetRoleName(),
				"message":  "You don't have the required role to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole middleware checks if user has any of the specified roles
func RequireAnyRole(authManager *auth.AuthManager, roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check if user is authenticated
		userID, exists := auth.GetUserIDFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Get user with role
		rbac := authManager.GetRBAC()
		user, err := rbac.GetUserWithRole(userID)
		if err != nil {
			authManager.GetLogger().Errorf("Error getting user role: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Role check failed",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, role := range roles {
			if user.HasRole(role) {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":    "Insufficient role",
				"required": strings.Join(roles, " or "),
				"current":  user.GetRoleName(),
				"message":  "You don't have any of the required roles to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission middleware checks if user has any of the specified permissions
func RequireAnyPermission(authManager *auth.AuthManager, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check if user is authenticated
		userID, exists := auth.GetUserIDFromContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Check if user has any of the required permissions
		rbac := authManager.GetRBAC()
		hasPermission := false

		for _, permission := range permissions {
			allowed, err := rbac.CheckPermission(userID, permission)
			if err != nil {
				authManager.GetLogger().Errorf("Error checking permission %s: %v", permission, err)
				continue
			}
			if allowed {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error":    "Insufficient permissions",
				"required": strings.Join(permissions, " or "),
				"message":  "You don't have any of the required permissions to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
