package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SecurityMonitoring middleware for detecting suspicious activities
func SecurityMonitoring(logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Monitor for suspicious patterns
		ip := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")
		path := c.Request.URL.Path
		method := c.Request.Method

		// Log suspicious user agents
		suspiciousUA := []string{
			"sqlmap", "nikto", "nmap", "masscan", "zap", "burp",
			"scanner", "bot", "crawler", "spider",
		}

		for _, suspicious := range suspiciousUA {
			if strings.Contains(strings.ToLower(userAgent), suspicious) {
				logger.Warnf("Suspicious User-Agent detected: %s from IP: %s", userAgent, ip)
				break
			}
		}

		// Monitor for path traversal attempts
		if strings.Contains(path, "..") || strings.Contains(path, "~") {
			logger.Warnf("Path traversal attempt detected: %s from IP: %s", path, ip)
		}

		// Monitor for admin endpoint access
		if strings.Contains(path, "/admin") {
			logger.Infof("Admin endpoint access: %s %s from IP: %s", method, path, ip)
		}

		// Process request
		c.Next()

		// Log response time and status
		duration := time.Since(startTime)
		status := c.Writer.Status()

		// Log slow requests
		if duration > 5*time.Second {
			logger.Warnf("Slow request detected: %s %s took %v from IP: %s", method, path, duration, ip)
		}

		// Log error responses
		if status >= 400 {
			logger.Infof("Error response: %s %s returned %d from IP: %s", method, path, status, ip)
		}
	}
}

// IPWhitelist middleware for restricting access to specific IPs
func IPWhitelist(allowedIPs []string, logger *zap.SugaredLogger) gin.HandlerFunc {
	if len(allowedIPs) == 0 {
		// If no IPs specified, allow all
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		allowed := false

		for _, ip := range allowedIPs {
			if clientIP == ip || ip == "*" {
				allowed = true
				break
			}

			// Support CIDR notation (basic check)
			if strings.Contains(ip, "/") && strings.HasPrefix(clientIP, strings.Split(ip, "/")[0][:3]) {
				allowed = true
				break
			}
		}

		if !allowed {
			logger.Warnf("IP not in whitelist: %s", clientIP)
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "access_denied",
				"message": "Access denied from this IP address",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// MaintenanceMode middleware for putting the API in maintenance mode
func MaintenanceMode(isEnabled bool, logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isEnabled {
			// Allow health checks during maintenance
			if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/health/ready" {
				c.Next()
				return
			}

			logger.Infof("Maintenance mode: blocked request %s %s from IP: %s",
				c.Request.Method, c.Request.URL.Path, c.ClientIP())

			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "maintenance_mode",
				"message": "API is temporarily unavailable for maintenance",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIVersioning middleware for handling API versioning
func APIVersioning(supportedVersions []string, defaultVersion string, logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for version in header
		version := c.GetHeader("API-Version")
		if version == "" {
			// Check for version in query parameter
			version = c.Query("version")
		}
		if version == "" {
			// Use default version
			version = defaultVersion
		}

		// Validate version
		validVersion := false
		for _, v := range supportedVersions {
			if version == v {
				validVersion = true
				break
			}
		}

		if !validVersion {
			logger.Warnf("Unsupported API version requested: %s from IP: %s", version, c.ClientIP())
			c.JSON(http.StatusBadRequest, gin.H{
				"error":              "unsupported_version",
				"message":            "Unsupported API version",
				"supported_versions": supportedVersions,
			})
			c.Abort()
			return
		}

		// Set version in context
		c.Set("api_version", version)
		c.Header("API-Version", version)

		c.Next()
	}
}
