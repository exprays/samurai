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
	"go.uber.org/zap"
)

func main() {
	// Load environment variables from multiple possible locations
	envPaths := []string{".env", "../.env", "../../.env"}
	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			log.Printf("Loaded environment from: %s", path)
			break
		}
	}

	// Initialize a basic logger for startup
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize startup logger: %v", err)
	}
	defer logger.Sync()
	sugar := logger.Sugar()

	// Load configuration using ConfigManager
	configManager := config.NewConfigManager(sugar)
	cfg, err := configManager.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize proper logger with loaded configuration
	appLogger, err := utils.NewSugaredLogger(&cfg.Logger)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer appLogger.Sync()

	// All logging goes to files only - NO console output
	appLogger.Info("Starting Samurai MCP Super Server...")
	appLogger.Infof("Server config: %+v", cfg.Server)
	appLogger.Infof("Database config: host=%s port=%d dbname=%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)

	// Initialize database
	db, err := database.NewConnection(&cfg.Database)
	if err != nil {
		appLogger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.AutoMigrate(); err != nil {
		appLogger.Fatalf("Failed to run migrations: %v", err)
	}

	appLogger.Info("Database migrations completed")

	// Initialize auth manager
	authManager := auth.NewAuthManager(&cfg.Auth, db, appLogger)
	appLogger.Info("Auth manager initialized")

	// Initialize RBAC system
	if err := authManager.InitializeRBAC(); err != nil {
		appLogger.Fatalf("Failed to initialize RBAC: %v", err)
	}
	appLogger.Info("RBAC system initialized")

	// Setup router with enhanced middleware
	router := routes.SetupRouter(db, authManager, appLogger)
	appLogger.Info("Router configured with enhanced security middleware")

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
		appLogger.Infof("Starting server on %s:%d", cfg.Server.Host, cfg.Server.Port)
		appLogger.Info("Enhanced security middleware active:")
		appLogger.Info("- Rate limiting enabled")
		appLogger.Info("- SQL injection protection enabled")
		appLogger.Info("- XSS protection enabled")
		appLogger.Info("- Security monitoring enabled")
		appLogger.Info("- Request validation enabled")
		appLogger.Info("- RBAC enforcement enabled")

		if cfg.Server.EnableTLS {
			appLogger.Info("Starting server with TLS")
			if err := srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				appLogger.Fatalf("Failed to start TLS server: %v", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				appLogger.Fatalf("Failed to start server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.GracefulTimeout)*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		appLogger.Errorf("Server forced to shutdown: %v", err)
	}

	appLogger.Info("Server exited")
}
