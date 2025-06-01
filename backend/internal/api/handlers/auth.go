package handlers

import (
	"samurai/backend/internal/auth"
	"samurai/backend/internal/database"

	"go.uber.org/zap"
)

type AuthHandler struct {
	db          *database.Database
	authManager *auth.AuthManager
	logger      *zap.SugaredLogger
}

func NewAuthHandler(db *database.Database, authManager *auth.AuthManager, logger *zap.SugaredLogger) *AuthHandler {
	return &AuthHandler{
		db:          db,
		authManager: authManager,
		logger:      logger,
	}
}

// TODO: Implement Register, Login, Profile methods in Step 2
