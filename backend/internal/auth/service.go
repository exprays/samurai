package auth

import (
    "errors"
    "time"

    "samurai/backend/internal/database/models"

    "github.com/google/uuid"
    "gorm.io/gorm"
)

var (
    ErrUserExists        = errors.New("user with this email already exists")
    ErrUserNotFound      = errors.New("user not found")
    ErrInvalidCredentials = errors.New("invalid email or password")
    ErrUserNotActive     = errors.New("user account is not active")
)

type AuthService struct {
    authManager *AuthManager
}

func NewAuthService(authManager *AuthManager) *AuthService {
    return &AuthService{
        authManager: authManager,
    }
}

// Register creates a new user account
func (s *AuthService) Register(req *RegisterRequest) (*AuthResponse, error) {
    db := s.authManager.GetDatabase()
    logger := s.authManager.GetLogger()
    passwordService := s.authManager.GetPasswordService()
    jwtService := s.authManager.GetJWTService()

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

    // Validate password strength
    if err := passwordService.ValidatePasswordStrength(req.Password); err != nil {
        return nil, err
    }

    // Hash password
    hashedPassword, err := passwordService.HashPassword(req.Password)
    if err != nil {
        logger.Errorf("Error hashing password: %v", err)
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
        Role:         "user", // Default role
        IsActive:     true,
        CreatedAt:    time.Now(),
        UpdatedAt:    time.Now(),
    }

    if err := db.DB.Create(&user).Error; err != nil {
        logger.Errorf("Error creating user: %v", err)
        return nil, err
    }

    logger.Infof("User registered successfully: %s", user.Email)

    // Generate JWT token
    token, err := jwtService.GenerateToken(user.ID, user.Email, user.Username, user.Role)
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
            Role:      user.Role,
            IsActive:  user.IsActive,
            CreatedAt: user.CreatedAt.Format(time.RFC3339),
        },
    }, nil
}

// Login authenticates a user and returns a token
func (s *AuthService) Login(req *LoginRequest) (*AuthResponse, error) {
    db := s.authManager.GetDatabase()
    logger := s.authManager.GetLogger()
    passwordService := s.authManager.GetPasswordService()
    jwtService := s.authManager.GetJWTService()

    // Find user by email
    var user models.User
    err := db.DB.Where("email = ?", req.Email).First(&user).Error
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

    // Generate JWT token
    token, err := jwtService.GenerateToken(user.ID, user.Email, user.Username, user.Role)
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
            Role:      user.Role,
            IsActive:  user.IsActive,
            CreatedAt: user.CreatedAt.Format(time.RFC3339),
        },
    }, nil
}

// GetUserProfile returns user profile information
func (s *AuthService) GetUserProfile(userID uuid.UUID) (*UserInfo, error) {
    db := s.authManager.GetDatabase()
    logger := s.authManager.GetLogger()

    var user models.User
    err := db.DB.Where("id = ?", userID).First(&user).Error
    if err != nil {
        if errors.Is(err, gorm.ErrRecordNotFound) {
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
        Role:      user.Role,
        IsActive:  user.IsActive,
        CreatedAt: user.CreatedAt.Format(time.RFC3339),
    }, nil
}