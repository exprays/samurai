package auth

import (
	"errors"
	"time"

	"samurai/backend/internal/database/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrUserExists         = errors.New("user with this email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotActive      = errors.New("user account is not active")
)

type AuthService struct {
	authManager *AuthManager
	policy      *PasswordPolicy
}

func NewAuthService(authManager *AuthManager) *AuthService {
	return &AuthService{
		authManager: authManager,
		policy:      DefaultPasswordPolicy(), // Use default policy
	}
}

// SetPasswordPolicy allows changing the password policy
func (s *AuthService) SetPasswordPolicy(policy *PasswordPolicy) {
	s.policy = policy
}

// Register creates a new user account with enhanced password validation and RBAC
func (s *AuthService) Register(req *RegisterRequest) (*AuthResponse, error) {
	db := s.authManager.GetDatabase()
	logger := s.authManager.GetLogger()
	passwordService := s.authManager.GetPasswordService()
	jwtService := s.authManager.GetJWTService()
	rbac := s.authManager.GetRBAC()

	// Check if user already exists
	var existingUser models.User
	err := db.DB.Where("email = ?", req.Email).First(&existingUser).Error
	if err == nil {
		return nil, ErrUserExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Errorf("Database error checking existing user: %v", err)
		return nil, err
	}

	// Validate password against policy
	if err := passwordService.ValidatePasswordPolicy(req.Password, s.policy); err != nil {
		logger.Infof("Password validation failed for user %s: %v", req.Email, err)
		return nil, err
	}

	// Hash password
	hashedPassword, err := passwordService.HashPassword(req.Password)
	if err != nil {
		logger.Errorf("Error hashing password: %v", err)
		return nil, err
	}

	logger.Debugf("Password hashed successfully, length: %d", len(hashedPassword))

	// Get default role ID
	defaultRoleID, err := rbac.GetDefaultRoleID()
	if err != nil {
		logger.Errorf("Error getting default role: %v", err)
		return nil, err
	}

	// Create user
	user := models.User{
		ID:           uuid.New(),
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		RoleID:       defaultRoleID,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.DB.Create(&user).Error; err != nil {
		logger.Errorf("Error creating user: %v", err)
		return nil, err
	}

	logger.Infof("User registered successfully: %s", user.Email)

	// Load user with role for JWT token
	userWithRole, err := rbac.GetUserWithRole(user.ID)
	if err != nil {
		logger.Errorf("Error loading user role: %v", err)
		return nil, err
	}

	// Generate JWT token
	token, err := jwtService.GenerateToken(user.ID, user.Email, user.Username, userWithRole.GetRoleName())
	if err != nil {
		logger.Errorf("Error generating token: %v", err)
		return nil, err
	}

	return &AuthResponse{
		Token:     token,
		TokenType: "Bearer",
		ExpiresIn: 24 * 3600, // 24 hours in seconds
		User: UserInfo{
			ID:        user.ID,
			Email:     user.Email,
			Username:  user.Username,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      userWithRole.GetRoleName(),
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
	}, nil
}

// Login authenticates a user and returns a token with role information
func (s *AuthService) Login(req *LoginRequest) (*AuthResponse, error) {
	db := s.authManager.GetDatabase()
	logger := s.authManager.GetLogger()
	passwordService := s.authManager.GetPasswordService()
	jwtService := s.authManager.GetJWTService()
	rbac := s.authManager.GetRBAC()

	// Find user by email with role
	var user models.User
	err := db.DB.Preload("Role").Where("email = ?", req.Email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		logger.Errorf("Database error finding user: %v", err)
		return nil, err
	}

	// Check if user is active
	if !user.IsActive {
		return nil, ErrUserNotActive
	}

	// Verify password
	if err := passwordService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		if errors.Is(err, ErrPasswordMismatch) {
			return nil, ErrInvalidCredentials
		}
		logger.Errorf("Error verifying password: %v", err)
		return nil, err
	}

	// Update last login time
	user.UpdatedAt = time.Now()
	if err := db.DB.Save(&user).Error; err != nil {
		logger.Warnf("Error updating user last login: %v", err)
		// Don't fail the login for this
	}

	logger.Infof("User logged in successfully: %s", user.Email)

	// Load full user with role and permissions
	userWithRole, err := rbac.GetUserWithRole(user.ID)
	if err != nil {
		logger.Errorf("Error loading user role: %v", err)
		return nil, err
	}

	// Generate JWT token
	token, err := jwtService.GenerateToken(user.ID, user.Email, user.Username, userWithRole.GetRoleName())
	if err != nil {
		logger.Errorf("Error generating token: %v", err)
		return nil, err
	}

	return &AuthResponse{
		Token:     token,
		TokenType: "Bearer",
		ExpiresIn: 24 * 3600, // 24 hours in seconds
		User: UserInfo{
			ID:        user.ID,
			Email:     user.Email,
			Username:  user.Username,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Role:      userWithRole.GetRoleName(),
			IsActive:  user.IsActive,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		},
	}, nil
}

// GetUserProfile returns user profile information with role and permissions
func (s *AuthService) GetUserProfile(userID uuid.UUID) (*UserInfo, error) {
	rbac := s.authManager.GetRBAC()
	logger := s.authManager.GetLogger()

	user, err := rbac.GetUserWithRole(userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUserNotFound
		}
		logger.Errorf("Database error finding user: %v", err)
		return nil, err
	}

	return &UserInfo{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.GetRoleName(),
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}, nil
}

// CheckPasswordStrength analyzes password strength
func (s *AuthService) CheckPasswordStrength(password string) *PasswordStrengthResponse {
	passwordService := s.authManager.GetPasswordService()
	strength := passwordService.AnalyzePasswordStrength(password)

	// Check if password meets current policy
	isValid := passwordService.ValidatePasswordPolicy(password, s.policy) == nil

	return &PasswordStrengthResponse{
		Strength: strength,
		IsValid:  isValid,
		Policy:   s.policy,
	}
}

// GenerateSecurePassword generates a secure password
func (s *AuthService) GenerateSecurePassword(length int) (*GeneratePasswordResponse, error) {
	passwordService := s.authManager.GetPasswordService()

	password, err := passwordService.GenerateSecurePassword(length)
	if err != nil {
		return nil, err
	}

	strength := passwordService.AnalyzePasswordStrength(password)

	return &GeneratePasswordResponse{
		Password: password,
		Strength: strength,
	}, nil
}
