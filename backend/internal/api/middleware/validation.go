package middleware

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RequestValidator middleware for input validation and sanitization
func RequestValidator(logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate Content-Type for POST/PUT requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			contentType := c.GetHeader("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				logger.Warnf("Invalid content type %s from IP: %s", contentType, c.ClientIP())
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "invalid_content_type",
					"message": "Content-Type must be application/json",
				})
				c.Abort()
				return
			}
		}

		// Validate request size (prevent large payload attacks)
		if c.Request.ContentLength > 10*1024*1024 { // 10MB limit
			logger.Warnf("Request too large (%d bytes) from IP: %s", c.Request.ContentLength, c.ClientIP())
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "request_too_large",
				"message": "Request body too large",
			})
			c.Abort()
			return
		}

		// Validate User-Agent (basic bot detection)
		userAgent := c.GetHeader("User-Agent")
		if userAgent == "" {
			logger.Warnf("Missing User-Agent from IP: %s", c.ClientIP())
		}

		c.Next()
	}
}

// SQLInjectionProtection middleware to detect SQL injection attempts
func SQLInjectionProtection(logger *zap.SugaredLogger) gin.HandlerFunc {
	// Common SQL injection patterns
	sqlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)\s`),
		regexp.MustCompile(`(?i)(script|javascript|vbscript|onload|onerror)`),
		regexp.MustCompile(`(?i)(<|>|'|"|;|--|\||&)`),
	}

	return func(c *gin.Context) {
		// Check query parameters
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				for _, pattern := range sqlPatterns {
					if pattern.MatchString(value) {
						logger.Warnf("Potential SQL injection detected in query param %s from IP: %s", key, c.ClientIP())
						c.JSON(http.StatusBadRequest, gin.H{
							"error":   "invalid_input",
							"message": "Invalid characters detected in request",
						})
						c.Abort()
						return
					}
				}
			}
		}

		// Check path parameters
		path := c.Request.URL.Path
		for _, pattern := range sqlPatterns {
			if pattern.MatchString(path) {
				logger.Warnf("Potential SQL injection detected in path from IP: %s", c.ClientIP())
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "invalid_path",
					"message": "Invalid characters detected in request path",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// XSSProtection middleware to prevent XSS attacks
func XSSProtection(logger *zap.SugaredLogger) gin.HandlerFunc {
	xssPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
		regexp.MustCompile(`(?i)<iframe[^>]*>.*?</iframe>`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)vbscript:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
	}

	return func(c *gin.Context) {
		// Check query parameters
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				for _, pattern := range xssPatterns {
					if pattern.MatchString(value) {
						logger.Warnf("Potential XSS attack detected in query param %s from IP: %s", key, c.ClientIP())
						c.JSON(http.StatusBadRequest, gin.H{
							"error":   "invalid_input",
							"message": "Invalid content detected in request",
						})
						c.Abort()
						return
					}
				}
			}
		}

		c.Next()
	}
}

// HeaderValidation middleware to validate and set security headers
func HeaderValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Remove sensitive headers
		c.Header("Server", "")
		c.Header("X-Powered-By", "")

		c.Next()
	}
}
