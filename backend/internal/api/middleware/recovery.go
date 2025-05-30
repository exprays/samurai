package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Recovery(logger *zap.SugaredLogger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		// Check for a broken connection, as it is not really a condition that warrants a panic stack trace.
		var brokenPipe bool
		if ne, ok := recovered.(*net.OpError); ok {
			if se, ok := ne.Err.(*os.SyscallError); ok {
				if strings.Contains(strings.ToLower(se.Error()), "broken pipe") ||
					strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
					brokenPipe = true
				}
			}
		}

		httpRequest, _ := httputil.DumpRequest(c.Request, false)
		if brokenPipe {
			logger.Errorw("Broken pipe error",
				"url", c.Request.URL.Path,
				"error", recovered,
				"request", string(httpRequest),
			)
			// If the connection is dead, we can't write a status to it.
			c.Error(fmt.Errorf("%s", recovered))
			c.Abort()
			return
		}

		logger.Errorw("Recovery from panic",
			"url", c.Request.URL.Path,
			"error", recovered,
			"request", string(httpRequest),
			"stack", string(debug.Stack()),
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "Something went wrong",
		})
		c.Abort()
	})
}
