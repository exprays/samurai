package utils

import (
	"samurai/backend/internal/config"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(cfg *config.LoggerConfig) (*zap.Logger, error) {
	var zapConfig zap.Config

	if cfg.Format == "json" {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
	}

	// Set log level
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)

	// Set output paths
	if cfg.OutputPath != "stdout" {
		zapConfig.OutputPaths = []string{cfg.OutputPath}
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return nil, err
	}

	return logger, nil
}

func NewSugaredLogger(cfg *config.LoggerConfig) (*zap.SugaredLogger, error) {
	logger, err := NewLogger(cfg)
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
}
