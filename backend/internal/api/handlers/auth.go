package handlers

import (
	"net/http"

	"samurai/backend/internal/auth"
	"samurai/backend/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type AuthHandler struct {
	db          *database.Database
	authManager *auth.AuthManager
	authService *auth.AuthService
	logger      *zap.SugaredLogger
}

func NewAuthHandler(db *database.Database, authManager *auth.AuthManager, logger *zap.SugaredLogger) *AuthHandler {
	authService := auth.NewAuthService(authManager)

	return &AuthHandler{
		db:          db,
		authManager: authManager,
		authService: authService,
		logger:      logger,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, auth.ErrorResponse{
			Error:   "Invalid request data",
			Message: err.Error(),
		})
		return
	}

	response, err := h.authService.Register(&req)
	if err != nil {
		switch err {
		case auth.ErrUserExists:
			c.JSON(http.StatusConflict, auth.ErrorResponse{
				Error:   "User already exists",
				Message: "A user with this email already exists",
			})
		case auth.ErrPasswordTooShort, auth.ErrPasswordTooLong, auth.ErrPasswordTooWeak,
			auth.ErrPasswordNoUppercase, auth.ErrPasswordNoLowercase,
			auth.ErrPasswordNoNumber, auth.ErrPasswordNoSpecial, auth.ErrPasswordCommon:
			c.JSON(http.StatusBadRequest, auth.ErrorResponse{
				Error:   "Password validation failed",
				Message: err.Error(),
			})
		default:
			h.logger.Errorf("Registration error: %v", err)
			c.JSON(http.StatusInternalServerError, auth.ErrorResponse{
				Error:   "Internal server error",
				Message: "Failed to register user",
			})
		}
		return
	}

	c.JSON(http.StatusCreated, response)
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, auth.ErrorResponse{
			Error:   "Invalid request data",
			Message: err.Error(),
		})
		return
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, auth.ErrorResponse{
				Error:   "Authentication failed",
				Message: "Invalid email or password",
			})
		case auth.ErrUserNotActive:
			c.JSON(http.StatusForbidden, auth.ErrorResponse{
				Error:   "Account disabled",
				Message: "Your account has been disabled",
			})
		default:
			h.logger.Errorf("Login error: %v", err)
			c.JSON(http.StatusInternalServerError, auth.ErrorResponse{
				Error:   "Internal server error",
				Message: "Failed to authenticate user",
			})
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

// Profile returns the current user's profile
func (h *AuthHandler) Profile(c *gin.Context) {
	userID, exists := auth.GetUserIDFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, auth.ErrorResponse{
			Error:   "Authentication required",
			Message: "User not authenticated",
		})
		return
	}

	profile, err := h.authService.GetUserProfile(userID)
	if err != nil {
		switch err {
		case auth.ErrUserNotFound:
			c.JSON(http.StatusNotFound, auth.ErrorResponse{
				Error:   "User not found",
				Message: "User profile not found",
			})
		default:
			h.logger.Errorf("Profile error: %v", err)
			c.JSON(http.StatusInternalServerError, auth.ErrorResponse{
				Error:   "Internal server error",
				Message: "Failed to retrieve profile",
			})
		}
		return
	}

	c.JSON(http.StatusOK, profile)
}

// CheckPasswordStrength analyzes password strength
func (h *AuthHandler) CheckPasswordStrength(c *gin.Context) {
	var req auth.PasswordStrengthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, auth.ErrorResponse{
			Error:   "Invalid request data",
			Message: err.Error(),
		})
		return
	}

	response := h.authService.CheckPasswordStrength(req.Password)
	c.JSON(http.StatusOK, response)
}

// GeneratePassword generates a secure password
func (h *AuthHandler) GeneratePassword(c *gin.Context) {
	var req auth.GeneratePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, auth.ErrorResponse{
			Error:   "Invalid request data",
			Message: err.Error(),
		})
		return
	}

	// Default length if not provided
	if req.Length == 0 {
		req.Length = 12
	}

	response, err := h.authService.GenerateSecurePassword(req.Length)
	if err != nil {
		h.logger.Errorf("Password generation error: %v", err)
		c.JSON(http.StatusInternalServerError, auth.ErrorResponse{
			Error:   "Internal server error",
			Message: "Failed to generate password",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}
