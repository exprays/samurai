package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"samurai/backend/internal/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func NewSugaredLogger(cfg *config.LoggerConfig) (*zap.SugaredLogger, error) {
	// Create logs directory in root project directory
	// From backend/cmd/server/, go up to root and create logs
	logsDir := "../../logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %w", err)
	}

	// Configure log level
	var level zapcore.Level
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	// Configure encoder
	var encoder zapcore.Encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	if cfg.Format == "console" {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// File output in root logs directory
	fileWriter := &lumberjack.Logger{
		Filename:   filepath.Join(logsDir, "app.log"),
		MaxSize:    100, // MB
		MaxBackups: 5,
		MaxAge:     30, // days
		Compress:   true,
	}

	writeSyncer := zapcore.AddSync(fileWriter)
	core := zapcore.NewCore(encoder, writeSyncer, level)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger.Sugar(), nil
}

// Create a separate logger for HTTP access logs
func NewAccessLogger() (*zap.SugaredLogger, error) {
	// Create logs directory in root
	logsDir := "../../logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %w", err)
	}

	writer := &lumberjack.Logger{
		Filename:   filepath.Join(logsDir, "access.log"),
		MaxSize:    100, // MB
		MaxBackups: 5,
		MaxAge:     30, // days
		Compress:   true,
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewJSONEncoder(encoderConfig)

	core := zapcore.NewCore(encoder, zapcore.AddSync(writer), zapcore.InfoLevel)
	logger := zap.New(core)

	return logger.Sugar(), nil
}

// Create a separate logger for database logs
func NewDatabaseLogger() (*zap.SugaredLogger, error) {
	// Create logs directory in root
	logsDir := "../../logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %w", err)
	}

	writer := &lumberjack.Logger{
		Filename:   filepath.Join(logsDir, "database.log"),
		MaxSize:    50, // MB
		MaxBackups: 3,
		MaxAge:     30, // days
		Compress:   true,
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder := zapcore.NewJSONEncoder(encoderConfig)

	core := zapcore.NewCore(encoder, zapcore.AddSync(writer), zapcore.InfoLevel)
	logger := zap.New(core)

	return logger.Sugar(), nil
}
