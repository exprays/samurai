package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"samurai/backend/internal/api/routes"
	"samurai/backend/internal/auth"
	"samurai/backend/internal/config"
	"samurai/backend/internal/database"
	"samurai/backend/internal/utils"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from multiple possible locations
	envPaths := []string{".env", "../.env", "../../.env"}
	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			break
		}
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger (file-based only)
	logger, err := utils.NewSugaredLogger(&cfg.Logger)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// All logging goes to files only - NO console output
	logger.Info("Starting Samurai MCP Super Server...")
	logger.Infof("Server config: %+v", cfg.Server)
	logger.Infof("Database config: host=%s port=%d dbname=%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)

	// Initialize database
	db, err := database.NewConnection(&cfg.Database)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.AutoMigrate(); err != nil {
		logger.Fatalf("Failed to run migrations: %v", err)
	}

	logger.Info("Database migrations completed")

	// Initialize auth manager
	authManager := auth.NewAuthManager(&cfg.Auth, db, logger)
	logger.Info("Auth manager initialized")

	// Initialize RBAC system
	if err := authManager.InitializeRBAC(); err != nil {
		logger.Fatalf("Failed to initialize RBAC: %v", err)
	}
	logger.Info("RBAC system initialized")

	// Setup router with enhanced middleware
	router := routes.SetupRouter(db, authManager, logger)
	logger.Info("Router configured with enhanced security middleware")

	// Setup HTTP server with security configurations
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  120 * time.Second, // 2 minutes idle timeout
		// Add security headers at server level
		MaxHeaderBytes: 1 << 20, // 1 MB max header size
	}

	// Start server in a goroutine
	go func() {
		logger.Infof("Starting server on %s:%d", cfg.Server.Host, cfg.Server.Port)
		logger.Info("Enhanced security middleware active:")
		logger.Info("- Rate limiting enabled")
		logger.Info("- SQL injection protection enabled")
		logger.Info("- XSS protection enabled")
		logger.Info("- Security monitoring enabled")
		logger.Info("- Request validation enabled")
		logger.Info("- RBAC enforcement enabled")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Errorf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}
