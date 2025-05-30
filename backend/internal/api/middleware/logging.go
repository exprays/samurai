package middleware

import (
	"samurai/backend/internal/utils"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Logger(logger *zap.SugaredLogger) gin.HandlerFunc {
	// Create separate access logger for HTTP requests
	accessLogger, err := utils.NewAccessLogger()
	if err != nil {
		logger.Errorf("Failed to create access logger: %v", err)
		accessLogger = logger // Fallback to main logger
	}

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get client IP
		clientIP := c.ClientIP()

		// Get status code
		statusCode := c.Writer.Status()

		// Get user agent
		userAgent := c.Request.UserAgent()

		// Get error message if any
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		// Format path with query
		if raw != "" {
			path = path + "?" + raw
		}

		// Log all requests to access log file only
		accessLogger.Infow("HTTP Request",
			"client_ip", clientIP,
			"timestamp", time.Now().Format(time.RFC3339),
			"method", c.Request.Method,
			"path", path,
			"protocol", c.Request.Proto,
			"status_code", statusCode,
			"latency", latency.String(),
			"user_agent", userAgent,
			"error_message", errorMessage,
		)

		// Log errors and slow requests to main log file
		if statusCode >= 400 || latency > 5*time.Second {
			if statusCode >= 500 {
				logger.Errorw("HTTP Error",
					"method", c.Request.Method,
					"path", path,
					"status", statusCode,
					"latency", latency.String(),
					"error", errorMessage,
				)
			} else if statusCode >= 400 {
				logger.Warnw("HTTP Client Error",
					"method", c.Request.Method,
					"path", path,
					"status", statusCode,
					"latency", latency.String(),
				)
			} else {
				logger.Warnw("Slow HTTP Request",
					"method", c.Request.Method,
					"path", path,
					"status", statusCode,
					"latency", latency.String(),
				)
			}
		}
	}
}
