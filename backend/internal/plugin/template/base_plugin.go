// Base template for plugin implementations

package template

import (
	"context"
	"fmt"
	"sync"
	"time"

	"samurai/backend/internal/plugin/interfaces"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// BasePlugin provides a foundation implementation for plugins
type BasePlugin struct {
	mu           sync.RWMutex
	metadata     *interfaces.PluginMetadata
	config       *interfaces.PluginConfig
	status       interfaces.PluginStatus
	logger       *zap.SugaredLogger
	startTime    time.Time
	initialized  bool
	capabilities []interfaces.PluginCapability
	metrics      map[string]interface{}
}

// NewBasePlugin creates a new base plugin with common functionality
func NewBasePlugin(metadata *interfaces.PluginMetadata) *BasePlugin {
	return &BasePlugin{
		metadata:     metadata,
		status:       interfaces.PluginStatusUnknown,
		capabilities: []interfaces.PluginCapability{},
		metrics:      make(map[string]interface{}),
	}
}

// GetMetadata returns plugin metadata
func (bp *BasePlugin) GetMetadata() *interfaces.PluginMetadata {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.metadata
}

// ValidateConfig validates the plugin configuration
func (bp *BasePlugin) ValidateConfig(config *interfaces.PluginConfig) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Basic validation - override in specific plugins for custom validation
	if config.Resources != nil {
		if config.Resources.MaxMemoryMB < 0 {
			return fmt.Errorf("max memory cannot be negative")
		}
		if config.Resources.MaxCPUPercent < 0 || config.Resources.MaxCPUPercent > 100 {
			return fmt.Errorf("max CPU percent must be between 0 and 100")
		}
	}

	return nil
}

// UpdateConfig updates the plugin configuration
func (bp *BasePlugin) UpdateConfig(config *interfaces.PluginConfig) error {
	if err := bp.ValidateConfig(config); err != nil {
		return err
	}

	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.config = config
	bp.logger.Info("Plugin configuration updated")
	return nil
}

// GetConfig returns the current plugin configuration
func (bp *BasePlugin) GetConfig() *interfaces.PluginConfig {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.config
}

// Initialize initializes the plugin
func (bp *BasePlugin) Initialize(ctx context.Context, logger *zap.SugaredLogger) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.initialized {
		return nil
	}

	bp.logger = logger.Named(bp.metadata.Name)
	bp.status = interfaces.PluginStatusLoaded
	bp.initialized = true

	bp.logger.Infow("Plugin initialized",
		"plugin_id", bp.metadata.ID,
		"name", bp.metadata.Name,
		"version", bp.metadata.Version,
	)

	return nil
}

// Start starts the plugin (base implementation)
func (bp *BasePlugin) Start(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.status == interfaces.PluginStatusRunning {
		return nil
	}

	bp.status = interfaces.PluginStatusStarting
	bp.startTime = time.Now()

	// Override in specific plugins for custom start logic
	bp.status = interfaces.PluginStatusRunning

	bp.logger.Info("Plugin started")
	return nil
}

// Stop stops the plugin (base implementation)
func (bp *BasePlugin) Stop(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.status != interfaces.PluginStatusRunning {
		return nil
	}

	bp.status = interfaces.PluginStatusStopping

	// Override in specific plugins for custom stop logic
	bp.status = interfaces.PluginStatusStopped

	bp.logger.Info("Plugin stopped")
	return nil
}

// Shutdown shuts down the plugin
func (bp *BasePlugin) Shutdown(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if err := bp.Stop(ctx); err != nil {
		return err
	}

	bp.initialized = false
	bp.logger.Info("Plugin shutdown completed")
	return nil
}

// GetStatus returns the current plugin status
func (bp *BasePlugin) GetStatus() interfaces.PluginStatus {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.status
}

// GetHealth returns plugin health information
func (bp *BasePlugin) GetHealth(ctx context.Context) *interfaces.PluginHealth {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	var uptime time.Duration
	if bp.status == interfaces.PluginStatusRunning {
		uptime = time.Since(bp.startTime)
	}

	return &interfaces.PluginHealth{
		Status:    bp.status,
		Healthy:   bp.status == interfaces.PluginStatusRunning,
		LastCheck: time.Now(),
		Uptime:    uptime,
		Metrics:   bp.metrics,
		Errors:    []string{},
	}
}

// IsHealthy returns whether the plugin is healthy
func (bp *BasePlugin) IsHealthy() bool {
	return bp.GetStatus() == interfaces.PluginStatusRunning
}

// HandleMessage handles incoming messages (base implementation)
func (bp *BasePlugin) HandleMessage(ctx context.Context, message *interfaces.PluginMessage) (*interfaces.PluginResponse, error) {
	// Override in specific plugins for custom message handling
	return &interfaces.PluginResponse{
		ID:        uuid.New(),
		RequestID: message.ID,
		Success:   false,
		Error:     "message handling not implemented",
		Timestamp: time.Now(),
	}, nil
}

// SendMessage sends a message (base implementation)
func (bp *BasePlugin) SendMessage(ctx context.Context, message *interfaces.PluginMessage) error {
	// Override in specific plugins for custom message sending
	return fmt.Errorf("message sending not implemented")
}

// GetCapabilities returns plugin capabilities
func (bp *BasePlugin) GetCapabilities() []interfaces.PluginCapability {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.capabilities
}

// ExecuteCapability executes a plugin capability
func (bp *BasePlugin) ExecuteCapability(ctx context.Context, capability string, params map[string]interface{}) (*interfaces.PluginResponse, error) {
	// Override in specific plugins for custom capability execution
	return &interfaces.PluginResponse{
		ID:        uuid.New(),
		Success:   false,
		Error:     fmt.Sprintf("capability '%s' not implemented", capability),
		Timestamp: time.Now(),
	}, nil
}

// SetMetric sets a metric value
func (bp *BasePlugin) SetMetric(name string, value interface{}) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.metrics[name] = value
}

// GetMetric gets a metric value
func (bp *BasePlugin) GetMetric(name string) interface{} {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.metrics[name]
}

// AddCapability adds a capability to the plugin
func (bp *BasePlugin) AddCapability(capability interfaces.PluginCapability) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.capabilities = append(bp.capabilities, capability)
}
