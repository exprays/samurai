package database

import (
	"fmt"
	"os"
	"time"

	"samurai/backend/internal/config"
	"samurai/backend/internal/database/models"
	"samurai/backend/internal/utils"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	*gorm.DB
}

func NewConnection(cfg *config.DatabaseConfig) (*Database, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	// Create database logger that writes to file
	dbLogger, err := utils.NewDatabaseLogger()
	if err != nil {
		return nil, fmt.Errorf("failed to create database logger: %w", err)
	}

	// Custom GORM logger that writes to file
	gormLogger := logger.New(
		&gormLogWriter{logger: dbLogger},
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Silent, // Only log slow queries and errors
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	// For development, you can change LogLevel to logger.Info to see all queries in logs
	if os.Getenv("SERVER_ENVIRONMENT") == "development" {
		gormLogger = logger.New(
			&gormLogWriter{logger: dbLogger},
			logger.Config{
				SlowThreshold:             time.Second,
				LogLevel:                  logger.Info, // Log all queries to file
				IgnoreRecordNotFoundError: true,
				Colorful:                  false,
			},
		)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return &Database{db}, nil
}

// Custom writer for GORM logger
type gormLogWriter struct {
	logger *zap.SugaredLogger
}

func (w *gormLogWriter) Printf(format string, args ...interface{}) {
	w.logger.Infof(format, args...)
}

func (db *Database) AutoMigrate() error {
	return db.DB.AutoMigrate(
		&models.User{},
		&models.Plugin{},
		&models.Configuration{},
		&models.AuditLog{},
	)
}

func (db *Database) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
