package handlers

import (
	"net/http"

	"samurai/backend/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type HealthHandler struct {
	db     *database.Database
	logger *zap.SugaredLogger
}

func NewHealthHandler(db *database.Database, logger *zap.SugaredLogger) *HealthHandler {
	return &HealthHandler{
		db:     db,
		logger: logger,
	}
}

func (h *HealthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "mcp-super-server",
		"version": "0.1.0",
	})
}

func (h *HealthHandler) Ready(c *gin.Context) {
	// Check database connection
	sqlDB, err := h.db.DB.DB()
	if err != nil {
		h.logger.Error("Database connection check failed", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "error",
			"error":  "database connection failed",
		})
		return
	}

	if err := sqlDB.Ping(); err != nil {
		h.logger.Error("Database ping failed", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "error",
			"error":  "database ping failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ready",
		"database": "connected",
	})
}
