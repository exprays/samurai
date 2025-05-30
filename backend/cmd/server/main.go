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

	// Show minimal startup info in console only
	fmt.Println("🚀 Starting Samurai MCP Super Server...")
	fmt.Printf("📊 Server: http://%s:%d\n", cfg.Server.Host, cfg.Server.Port)
	fmt.Printf("🏥 Health: http://%s:%d/health\n", cfg.Server.Host, cfg.Server.Port)
	fmt.Printf("📚 API: http://%s:%d/api/v1\n", cfg.Server.Host, cfg.Server.Port)
	fmt.Println("📝 Logs: ./logs/ directory")

	// All detailed logging goes to files only
	logger.Info("Starting Samurai MCP Super Server...")
	logger.Infof("Server config: %+v", cfg.Server)
	logger.Infof("Database config: host=%s port=%d dbname=%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)

	// Initialize database
	db, err := database.NewConnection(&cfg.Database)
	if err != nil {
		fmt.Printf("❌ Failed to connect to database: %v\n", err)
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.AutoMigrate(); err != nil {
		fmt.Printf("❌ Failed to run migrations: %v\n", err)
		logger.Fatalf("Failed to run migrations: %v", err)
	}

	fmt.Println("✅ Database connected and migrations completed")
	logger.Info("Database migrations completed")

	// Setup router
	router := routes.SetupRouter(db, logger)

	// Setup HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	// Start server in a goroutine
	go func() {
		fmt.Println("✅ Server started successfully")
		logger.Infof("Server starting on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("❌ Server failed to start: %v\n", err)
			logger.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\n🛑 Shutting down server...")
	logger.Info("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("❌ Server forced to shutdown: %v\n", err)
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	fmt.Println("✅ Server exited gracefully")
	logger.Info("Server exited")
}
