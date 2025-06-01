package auth

import (
	"samurai/backend/internal/config"
	"samurai/backend/internal/database"

	"go.uber.org/zap"
)

type AuthManager struct {
	jwtService *JWTService
	db         *database.Database
	logger     *zap.SugaredLogger
}

func NewAuthManager(cfg *config.AuthConfig, db *database.Database, logger *zap.SugaredLogger) *AuthManager {
	jwtService := NewJWTService(cfg.JWTSecret, cfg.TokenDuration)

	return &AuthManager{
		jwtService: jwtService,
		db:         db,
		logger:     logger,
	}
}

func (a *AuthManager) GetJWTService() *JWTService {
	return a.jwtService
}

func (a *AuthManager) GetDatabase() *database.Database {
	return a.db
}

func (a *AuthManager) GetLogger() *zap.SugaredLogger {
	return a.logger
}
