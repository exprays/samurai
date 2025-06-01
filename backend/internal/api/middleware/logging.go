package middleware

import (
	"bytes"
	"io"
	"samurai/backend/internal/utils"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// responseWriter wrapper to capture response body
type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r responseWriter) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

// Logger middleware with enhanced logging capabilities
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

// DetailedLogger middleware for debugging (captures request/response bodies)
func DetailedLogger(logger *zap.SugaredLogger, enableRequestBody bool, enableResponseBody bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		var requestBody []byte
		if enableRequestBody && c.Request.Body != nil {
			requestBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		}

		var respWriter *responseWriter
		if enableResponseBody {
			respWriter = &responseWriter{
				ResponseWriter: c.Writer,
				body:           bytes.NewBufferString(""),
			}
			c.Writer = respWriter
		}

		// Process request
		c.Next()

		duration := time.Since(startTime)

		// Prepare log fields
		fields := []interface{}{
			"timestamp", startTime.Format(time.RFC3339),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"query", c.Request.URL.RawQuery,
			"status", c.Writer.Status(),
			"latency", duration,
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"content_length", c.Request.ContentLength,
		}

		// Add user context if available
		if userEmail, exists := c.Get("user_email"); exists {
			fields = append(fields, "user_email", userEmail)
		}
		if userRole, exists := c.Get("user_role"); exists {
			fields = append(fields, "user_role", userRole)
		}

		// Add request body if enabled
		if enableRequestBody && len(requestBody) > 0 && len(requestBody) < 1024 {
			fields = append(fields, "request_body", string(requestBody))
		}

		// Add response body if enabled
		if enableResponseBody && respWriter != nil {
			responseBody := respWriter.body.String()
			if len(responseBody) > 0 && len(responseBody) < 1024 {
				fields = append(fields, "response_body", responseBody)
			}
		}

		// Log errors
		if len(c.Errors) > 0 {
			fields = append(fields, "errors", c.Errors.String())
		}

		logger.Infow("Detailed request log", fields...)
	}
}

// AuditLogger middleware for security-sensitive operations
func AuditLogger(logger *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only log sensitive operations
		sensitiveOperations := []string{
			"/api/v1/auth/login",
			"/api/v1/auth/register",
			"/api/v1/users",
			"/api/v1/roles",
			"/api/v1/config",
		}

		path := c.Request.URL.Path
		isSensitive := false

		for _, sensitiveOp := range sensitiveOperations {
			if path == sensitiveOp || (len(path) > len(sensitiveOp) && path[:len(sensitiveOp)] == sensitiveOp) {
				isSensitive = true
				break
			}
		}

		if !isSensitive {
			c.Next()
			return
		}

		startTime := time.Now()
		c.Next()

		// Audit log entry
		fields := []interface{}{
			"audit_timestamp", startTime.Format(time.RFC3339),
			"operation", c.Request.Method + " " + path,
			"status", c.Writer.Status(),
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		}

		// Add user context
		if userEmail, exists := c.Get("user_email"); exists {
			fields = append(fields, "user_email", userEmail)
		}
		if userRole, exists := c.Get("user_role"); exists {
			fields = append(fields, "user_role", userRole)
		}

		logger.Infow("Security audit log", fields...)
	}
}
