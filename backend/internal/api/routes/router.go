package routes

import (
	"samurai/backend/internal/api/handlers"
	"samurai/backend/internal/api/middleware"
	"samurai/backend/internal/auth"
	"samurai/backend/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func SetupRouter(db *database.Database, authManager *auth.AuthManager, logger *zap.SugaredLogger) *gin.Engine {
	// Set Gin mode based on environment
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Initialize rate limiter
	middleware.InitRateLimiter(logger)

	// Global middleware (order matters!)
	router.Use(middleware.SilentRecovery(logger))         // Panic recovery ( must be first to catch all panics )
	router.Use(middleware.SecurityMonitoring(logger))     // Security monitoring
	router.Use(middleware.HeaderValidation())             // Security headers
	router.Use(middleware.RequestValidator(logger))       // Request validation
	router.Use(middleware.SQLInjectionProtection(logger)) // SQL injection protection
	router.Use(middleware.XSSProtection(logger))          // XSS protection
	router.Use(middleware.CORS())                         // CORS handling
	router.Use(middleware.Logger(logger))                 // Request logging
	router.Use(middleware.AuditLogger(logger))            // Audit logging
	router.Use(middleware.APIRateLimit())                 // General rate limiting

	// API versioning
	supportedVersions := []string{"v1"}
	router.Use(middleware.APIVersioning(supportedVersions, "v1", logger))

	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(db, logger)
	authHandler := handlers.NewAuthHandler(db, authManager, logger)

	// Health check routes (no rate limiting)
	health := router.Group("/health")
	{
		health.GET("/", healthHandler.Health)
		health.GET("/ready", healthHandler.Ready)
		health.GET("/live", healthHandler.Health) // Kubernetes liveness probe
	}

	// router.GET("/test-panic", func(c *gin.Context) {
	// 	panic("This is a test panic for logging")
	// })

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Auth routes (stricter rate limiting)
		auth := v1.Group("/auth")
		auth.Use(middleware.AuthRateLimit()) // 5 req/min for auth endpoints
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", middleware.TokenRefresh(authManager))
			auth.POST("/password/check", authHandler.CheckPasswordStrength)
			auth.POST("/password/generate", authHandler.GeneratePassword)
		}

		// Protected routes
		protected := v1.Group("/")
		protected.Use(middleware.AuthRequired(authManager)) // JWT validation
		protected.Use(middleware.UserRateLimit())           // Higher limits for authenticated users
		{
			// User profile
			protected.GET("/profile", authHandler.Profile)

			// Admin routes (require admin role)
			admin := protected.Group("/admin")
			admin.Use(middleware.RequireAnyRole(authManager, "admin", "super_admin"))
			{
				// User management
				users := admin.Group("/users")
				users.Use(middleware.RequirePermission(authManager, "users.read"))
				{
					// users.GET("/", userHandler.ListUsers)
					// users.GET("/:id", userHandler.GetUser)
					// Additional user management endpoints will be added later
				}

				// Role management
				roles := admin.Group("/roles")
				roles.Use(middleware.RequirePermission(authManager, "roles.read"))
				{
					// roles.GET("/", roleHandler.ListRoles)
					// roles.GET("/:id", roleHandler.GetRole)
					// Additional role management endpoints will be added later
				}
			}

			// Super admin routes (require super_admin role)
			superAdmin := protected.Group("/super-admin")
			superAdmin.Use(middleware.RequireRole(authManager, "super_admin"))
			{
				// System configuration
				config := superAdmin.Group("/config")
				config.Use(middleware.RequirePermission(authManager, "config.update"))
				{
					// config.GET("/", configHandler.GetConfig)
					// config.PUT("/", configHandler.UpdateConfig)
					// Additional config endpoints will be added later
				}
			}

			// Plugin routes (require plugin permissions)
			plugins := protected.Group("/plugins")
			plugins.Use(middleware.RequirePermission(authManager, "plugins.read"))
			{
				// plugins.GET("/", pluginHandler.ListPlugins)
				// plugins.GET("/:id", pluginHandler.GetPlugin)
				// Additional plugin endpoints will be added later
			}

			// LLM routes (require LLM permissions)
			llm := protected.Group("/llm")
			llm.Use(middleware.RequirePermission(authManager, "llm.read"))
			{
				// llm.GET("/models", llmHandler.ListModels)
				// llm.POST("/chat", llmHandler.Chat)
				// Additional LLM endpoints will be added later
			}
		}

		// Optional auth routes (can be accessed with or without auth)
		public := v1.Group("/public")
		public.Use(middleware.OptionalAuth(authManager))
		{
			// public.GET("/info", infoHandler.GetInfo)
			// Additional public endpoints will be added later
		}
	}

	return router
}
