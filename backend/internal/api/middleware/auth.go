package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement JWT token validation
		// For now, just return unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authentication required - TODO",
		})
		c.Abort()
	}
}
