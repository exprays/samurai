package routes

import (
	"samurai/backend/internal/api/handlers"
	"samurai/backend/internal/api/middleware"
	"samurai/backend/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func SetupRouter(db *database.Database, logger *zap.SugaredLogger) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode) // can make this configurable

	router := gin.New()

	// Global middleware
	router.Use(middleware.Logger(logger))
	router.Use(middleware.Recovery(logger))
	router.Use(middleware.CORS())

	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(db, logger)
	authHandler := handlers.NewAuthHandler(db, logger)

	// Health check routes
	router.GET("/health", healthHandler.Health)
	router.GET("/health/ready", healthHandler.Ready)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Auth routes (no auth required)
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
		}

		// Protected routes
		protected := v1.Group("/")
		protected.Use(middleware.AuthRequired())
		{
			protected.GET("/profile", authHandler.Profile)
			// Plugin routes will be added later
			// LLM routes will be added later
			// Config routes will be added later
		}
	}

	return router
}
