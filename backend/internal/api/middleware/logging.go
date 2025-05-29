package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

/*
 Logger is a middleware function for Gin that logs HTTP requests.
 It uses a zap logger to log details about the request such as client IP, timestamp etc.
 The log format is customizable and can be adjusted as needed.
*/

func Logger(logger *zap.SugaredLogger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logger.Infow("HTTP Request",
			"client_ip", param.ClientIP,
			"timestamp", param.TimeStamp.Format(time.RFC3339),
			"method", param.Method,
			"path", param.Path,
			"protocol", param.Request.Proto,
			"status_code", param.StatusCode,
			"latency", param.Latency,
			"user_agent", param.Request.UserAgent(),
			"error_message", param.ErrorMessage,
		)
		return ""
	})
}

func Recovery(logger *zap.SugaredLogger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		logger.Errorw("Panic recovered",
			"error", recovered,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
		)
		c.AbortWithStatus(500)
	})
}
