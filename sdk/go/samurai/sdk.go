package samurai

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SDK provides the main interface for plugin developers
type SDK struct {
	logger   *zap.SugaredLogger
	metadata *PluginMetadata
	config   *PluginConfig
	host     HostInterface
	events   *EventManager
	metrics  *MetricsCollector
}

// HostInterface defines the interface for communicating with the host system
type HostInterface interface {
	SendMessage(ctx context.Context, message *Message) (*Response, error)
	GetConfig(ctx context.Context) (*PluginConfig, error)
	LogMessage(ctx context.Context, level LogLevel, message string, fields map[string]interface{}) error
	EmitEvent(ctx context.Context, event *Event) error
	GetSecret(ctx context.Context, key string) (string, error)
	SetMetric(ctx context.Context, name string, value interface{}) error
}

// NewSDK creates a new SDK instance
func NewSDK(metadata *PluginMetadata, host HostInterface) *SDK {
	// Handle zap.NewDevelopment error properly
	logger, err := zap.NewDevelopment()
	if err != nil {
		// Fallback to a basic logger if development logger fails
		logger = zap.NewNop()
	}
	sugaredLogger := logger.Sugar().Named(metadata.Name)

	return &SDK{
		logger:   sugaredLogger,
		metadata: metadata,
		host:     host,
		events:   NewEventManager(host),
		metrics:  NewMetricsCollector(host),
	}
}

// Initialize initializes the SDK
func (sdk *SDK) Initialize(ctx context.Context) error {
	sdk.logger.Info("Initializing plugin SDK")

	// Load configuration from host
	config, err := sdk.host.GetConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	sdk.config = config

	// Initialize components
	if err := sdk.events.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize event manager: %w", err)
	}

	if err := sdk.metrics.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize metrics collector: %w", err)
	}

	sdk.logger.Info("Plugin SDK initialized successfully")
	return nil
}

// GetLogger returns the plugin logger
func (sdk *SDK) GetLogger() *zap.SugaredLogger {
	return sdk.logger
}

// GetMetadata returns the plugin metadata
func (sdk *SDK) GetMetadata() *PluginMetadata {
	return sdk.metadata
}

// GetConfig returns the plugin configuration
func (sdk *SDK) GetConfig() *PluginConfig {
	return sdk.config
}

// SendMessage sends a message to the host system
func (sdk *SDK) SendMessage(ctx context.Context, message *Message) (*Response, error) {
	return sdk.host.SendMessage(ctx, message)
}

// GetSecret retrieves a secret from the host system
func (sdk *SDK) GetSecret(ctx context.Context, key string) (string, error) {
	return sdk.host.GetSecret(ctx, key)
}

// EmitEvent emits an event to the host system
func (sdk *SDK) EmitEvent(ctx context.Context, eventType string, data map[string]interface{}) error {
	event := &Event{
		ID:        uuid.New(),
		Type:      eventType,
		Data:      data,
		Timestamp: time.Now(),
		Source:    sdk.metadata.Name,
	}
	return sdk.events.EmitEvent(ctx, event)
}

// SetMetric sets a metric value
func (sdk *SDK) SetMetric(ctx context.Context, name string, value interface{}) error {
	return sdk.metrics.SetMetric(ctx, name, value)
}

// IncrementCounter increments a counter metric
func (sdk *SDK) IncrementCounter(ctx context.Context, name string) error {
	return sdk.metrics.IncrementCounter(ctx, name)
}

// RecordLatency records a latency metric
func (sdk *SDK) RecordLatency(ctx context.Context, name string, duration time.Duration) error {
	return sdk.metrics.RecordLatency(ctx, name, duration)
}

// Log logs a message with the specified level
func (sdk *SDK) Log(ctx context.Context, level LogLevel, message string, fields ...map[string]interface{}) error {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = make(map[string]interface{})
		for _, fieldMap := range fields {
			for k, v := range fieldMap {
				mergedFields[k] = v
			}
		}
	}

	return sdk.host.LogMessage(ctx, level, message, mergedFields)
}

// LogInfo logs an info message
func (sdk *SDK) LogInfo(ctx context.Context, message string, fields ...map[string]interface{}) error {
	return sdk.Log(ctx, LogLevelInfo, message, fields...)
}

// LogWarn logs a warning message
func (sdk *SDK) LogWarn(ctx context.Context, message string, fields ...map[string]interface{}) error {
	return sdk.Log(ctx, LogLevelWarn, message, fields...)
}

// LogError logs an error message
func (sdk *SDK) LogError(ctx context.Context, message string, fields ...map[string]interface{}) error {
	return sdk.Log(ctx, LogLevelError, message, fields...)
}

// LogDebug logs a debug message
func (sdk *SDK) LogDebug(ctx context.Context, message string, fields ...map[string]interface{}) error {
	return sdk.Log(ctx, LogLevelDebug, message, fields...)
}

// Shutdown gracefully shuts down the SDK
func (sdk *SDK) Shutdown(ctx context.Context) error {
	sdk.logger.Info("Shutting down plugin SDK")

	// Shutdown components
	if err := sdk.metrics.Shutdown(ctx); err != nil {
		sdk.logger.Warnw("Error shutting down metrics collector", "error", err)
	}

	if err := sdk.events.Shutdown(ctx); err != nil {
		sdk.logger.Warnw("Error shutting down event manager", "error", err)
	}

	sdk.logger.Info("Plugin SDK shutdown completed")
	return nil
}
