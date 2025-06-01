package auth

import (
	"samurai/backend/internal/config"
	"samurai/backend/internal/database"

	"go.uber.org/zap"
)

type AuthManager struct {
	jwtService      *JWTService
	passwordService *PasswordService
	rbac            *RBAC
	db              *database.Database
	logger          *zap.SugaredLogger
}

func NewAuthManager(cfg *config.AuthConfig, db *database.Database, logger *zap.SugaredLogger) *AuthManager {
	jwtService := NewJWTService(cfg.JWTSecret, int(cfg.TokenDuration))
	passwordService := NewPasswordService()
	rbac := NewRBAC(db, logger)

	return &AuthManager{
		jwtService:      jwtService,
		passwordService: passwordService,
		rbac:            rbac,
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

func (a *AuthManager) GetRBAC() *RBAC {
	return a.rbac
}

func (a *AuthManager) GetDatabase() *database.Database {
	return a.db
}

func (a *AuthManager) GetLogger() *zap.SugaredLogger {
	return a.logger
}

// InitializeRBAC initializes the RBAC system with default roles and permissions
func (a *AuthManager) InitializeRBAC() error {
	return a.rbac.InitializeDefaultRoles()
}
