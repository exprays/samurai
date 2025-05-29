package handlers

import (
	"net/http"

	"samurai/backend/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type AuthHandler struct {
	db     *database.Database
	logger *zap.SugaredLogger
}

func NewAuthHandler(db *database.Database, logger *zap.SugaredLogger) *AuthHandler {
	return &AuthHandler{
		db:     db,
		logger: logger,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	// TODO: Implement user registration
	c.JSON(http.StatusOK, gin.H{
		"message": "Register endpoint - TODO",
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	// TODO: Implement user login
	c.JSON(http.StatusOK, gin.H{
		"message": "Login endpoint - TODO",
	})
}

func (h *AuthHandler) Profile(c *gin.Context) {
	// TODO: Implement user profile
	c.JSON(http.StatusOK, gin.H{
		"message": "Profile endpoint - TODO",
	})
}
