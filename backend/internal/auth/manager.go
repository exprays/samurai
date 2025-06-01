package auth

import (
	"samurai/backend/internal/config"
	"samurai/backend/internal/database"

	"go.uber.org/zap"
)

type AuthManager struct {
	jwtService      *JWTService
	passwordService *PasswordService
	db              *database.Database
	logger          *zap.SugaredLogger
}

func NewAuthManager(cfg *config.AuthConfig, db *database.Database, logger *zap.SugaredLogger) *AuthManager {
	jwtService := NewJWTService(cfg.JWTSecret, cfg.TokenDuration)
	passwordService := NewPasswordService()

	return &AuthManager{
		jwtService:      jwtService,
		passwordService: passwordService,
		db:              db,
		logger:          logger,
	}
}

func (a *AuthManager) GetJWTService() *JWTService {
	return a.jwtService
}

func (a *AuthManager) GetPasswordService() *PasswordService {
	return a.passwordService
}

func (a *AuthManager) GetDatabase() *database.Database {
	return a.db
}

func (a *AuthManager) GetLogger() *zap.SugaredLogger {
	return a.logger
}
