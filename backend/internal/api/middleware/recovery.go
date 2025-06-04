package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RecoveryLogger handles recovery logging to both file and structured logger
type RecoveryLogger struct {
	logger  *zap.SugaredLogger
	logFile *os.File
}

// NewRecoveryLogger creates a new recovery logger
func NewRecoveryLogger(logger *zap.SugaredLogger, logFilePath string) (*RecoveryLogger, error) {
	// Get the absolute path relative to project root
	// When running from backend/cmd/server, we need to go up 2 levels to reach project root
	projectRoot, err := getProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine project root: %w", err)
	}

	// Construct the full path to the log file in the root logs directory
	fullLogPath := filepath.Join(projectRoot, logFilePath)

	// Create the directory if it doesn't exist
	dir := filepath.Dir(fullLogPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	// Open or create the log file
	logFile, err := os.OpenFile(fullLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open recovery log file %s: %w", fullLogPath, err)
	}

	logger.Infof("Recovery logger initialized with log file: %s", fullLogPath)

	return &RecoveryLogger{
		logger:  logger,
		logFile: logFile,
	}, nil
}

// getProjectRoot determines the project root directory
func getProjectRoot() (string, error) {
	// Get the current working directory
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Check if we're running from backend directory (look for go.mod in parent)
	if filepath.Base(wd) == "backend" {
		// We're in the backend directory, go up one level
		return filepath.Dir(wd), nil
	}

	// Check if we're running from backend/cmd/server
	if strings.Contains(wd, filepath.Join("backend", "cmd")) {
		// Find the backend directory and go up one level from there
		parts := strings.Split(wd, string(filepath.Separator))
		for i, part := range parts {
			if part == "backend" && i > 0 {
				// Reconstruct path up to the parent of backend
				rootParts := parts[:i]
				return filepath.Join(rootParts...), nil
			}
		}
	}

	// If we can't determine from path, look for go.mod file
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Default to current working directory if all else fails
	return wd, nil
}

// Close closes the recovery log file
func (r *RecoveryLogger) Close() error {
	if r.logFile != nil {
		return r.logFile.Close()
	}
	return nil
}

// writeToFile writes recovery information to the log file
func (r *RecoveryLogger) writeToFile(logType, method, path, ip, userAgent, error, stack string) {
	if r.logFile == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logEntry := fmt.Sprintf("[%s] %s RECOVERY: %s %s from %s\nError: %s\nUser-Agent: %s\nStack Trace:\n%s\n---\n\n",
		timestamp, logType, method, path, ip, error, userAgent, stack)

	r.logFile.WriteString(logEntry)
}

// Recovery returns a gin middleware that recovers from panics and logs them to file
func Recovery(logger *zap.SugaredLogger) gin.HandlerFunc {
	// Create recovery logger with file output in root logs directory
	recoveryLogger, err := NewRecoveryLogger(logger, "logs/recovery.log")
	if err != nil {
		logger.Fatalf("Failed to create recovery logger: %v", err)
	}

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
		errorString := fmt.Sprintf("%v", recovered)
		stackTrace := string(debug.Stack())

		// Get user ID if available
		var userID string
		if uid, exists := c.Get("user_id"); exists {
			userID = fmt.Sprintf("%v", uid)
		}

		if brokenPipe {
			// Log broken pipe to file only (no CLI output)
			recoveryLogger.writeToFile("BROKEN_PIPE", c.Request.Method, c.Request.URL.Path,
				c.ClientIP(), c.Request.UserAgent(), errorString, "Connection broken")

			// Log structured info to app.log only (no CLI output)
			recoveryLogger.logger.Errorw("Broken pipe error",
				"url", c.Request.URL.Path,
				"error", recovered,
				"method", c.Request.Method,
				"ip", c.ClientIP(),
				"user_agent", c.Request.UserAgent(),
				"user_id", userID,
				"timestamp", time.Now().UTC(),
			)

			// Don't output to CLI - just abort
			c.Abort()
			return
		}

		// Log full recovery info to file only (no CLI output)
		recoveryLogger.writeToFile("PANIC", c.Request.Method, c.Request.URL.Path,
			c.ClientIP(), c.Request.UserAgent(), errorString, stackTrace)

		// Log structured recovery info to app.log only (no CLI output)
		recoveryLogger.logger.Errorw("Recovery from panic",
			"url", c.Request.URL.Path,
			"error", recovered,
			"method", c.Request.Method,
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"user_id", userID,
			"path", c.Request.URL.Path,
			"timestamp", time.Now().UTC(),
			"stack_trace", stackTrace,
			"request_dump", string(httpRequest),
		)

		// Return clean error response (no stack trace to client)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "Something went wrong",
		})
		c.Abort()
	})
}

// RecoveryWithCustomLogger allows passing a custom recovery logger
func RecoveryWithCustomLogger(recoveryLogger *RecoveryLogger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		// Check for a broken connection
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
		errorString := fmt.Sprintf("%v", recovered)
		stackTrace := string(debug.Stack())

		// Get user ID if available
		var userID string
		if uid, exists := c.Get("user_id"); exists {
			userID = fmt.Sprintf("%v", uid)
		}

		if brokenPipe {
			// Log broken pipe to file only
			recoveryLogger.writeToFile("BROKEN_PIPE", c.Request.Method, c.Request.URL.Path,
				c.ClientIP(), c.Request.UserAgent(), errorString, "Connection broken")

			// Log structured info
			recoveryLogger.logger.Errorw("Broken pipe error",
				"url", c.Request.URL.Path,
				"error", recovered,
				"method", c.Request.Method,
				"ip", c.ClientIP(),
				"user_agent", c.Request.UserAgent(),
				"user_id", userID,
				"timestamp", time.Now().UTC(),
			)

			c.Abort()
			return
		}

		// Log full recovery info to file only
		recoveryLogger.writeToFile("PANIC", c.Request.Method, c.Request.URL.Path,
			c.ClientIP(), c.Request.UserAgent(), errorString, stackTrace)

		// Log structured recovery info
		recoveryLogger.logger.Errorw("Recovery from panic",
			"url", c.Request.URL.Path,
			"error", recovered,
			"method", c.Request.Method,
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"user_id", userID,
			"path", c.Request.URL.Path,
			"timestamp", time.Now().UTC(),
			"stack_trace", stackTrace,
			"request_dump", string(httpRequest),
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal server error",
			"message": "Something went wrong",
		})
		c.Abort()
	})
}
