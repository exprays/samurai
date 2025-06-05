package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"samurai/backend/internal/database"
	"samurai/backend/internal/plugin/interfaces"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PluginRegistry manages plugin registration and discovery
type PluginRegistry struct {
	mu       sync.RWMutex                             // mutex for thread-safe access
	plugins  map[uuid.UUID]interfaces.Plugin          // registered plugins by ID
	metadata map[uuid.UUID]*interfaces.PluginMetadata // plugin metadata by ID
	status   map[uuid.UUID]interfaces.PluginStatus    // plugin status by ID
	health   map[uuid.UUID]*interfaces.PluginHealth   // plugin health information by ID
	db       *database.Database                       // database instance for persistence
	logger   *zap.SugaredLogger                       // logger for logging plugin events
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry(db *database.Database, logger *zap.SugaredLogger) *PluginRegistry {
	return &PluginRegistry{
		plugins:  make(map[uuid.UUID]interfaces.Plugin),
		metadata: make(map[uuid.UUID]*interfaces.PluginMetadata),
		status:   make(map[uuid.UUID]interfaces.PluginStatus),
		health:   make(map[uuid.UUID]*interfaces.PluginHealth),
		db:       db,
		logger:   logger.Named("plugin-registry"),
	}
}

// Register adds a plugin to the registry
func (r *PluginRegistry) Register(plugin interfaces.Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	metadata := plugin.GetMetadata()
	if metadata == nil {
		return fmt.Errorf("plugin metadata is nil")
	}

	// Check if plugin already exists
	if _, exists := r.plugins[metadata.ID]; exists {
		return fmt.Errorf("plugin %s already registered", metadata.ID)
	}

	// Validate plugin metadata
	if err := r.validateMetadata(metadata); err != nil {
		return fmt.Errorf("invalid plugin metadata: %w", err)
	}

	// Register plugin
	r.plugins[metadata.ID] = plugin
	r.metadata[metadata.ID] = metadata
	r.status[metadata.ID] = interfaces.PluginStatusDiscovered
	r.health[metadata.ID] = &interfaces.PluginHealth{
		Status:    interfaces.PluginStatusDiscovered,
		Healthy:   false,
		LastCheck: time.Now(),
		Metrics:   make(map[string]interface{}),
	}

	r.logger.Infow("Plugin registered",
		"plugin_id", metadata.ID,
		"name", metadata.Name,
		"version", metadata.Version,
		"type", metadata.Type,
	)

	return nil
}

// Unregister removes a plugin from the registry
func (r *PluginRegistry) Unregister(pluginID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	plugin, exists := r.plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	// Stop plugin if running
	if r.status[pluginID] == interfaces.PluginStatusRunning {
		if err := plugin.Stop(context.Background()); err != nil {
			r.logger.Warnw("Error stopping plugin during unregister",
				"plugin_id", pluginID,
				"error", err,
			)
		}
	}

	// Remove from registry
	delete(r.plugins, pluginID)
	delete(r.metadata, pluginID)
	delete(r.status, pluginID)
	delete(r.health, pluginID)

	r.logger.Infow("Plugin unregistered", "plugin_id", pluginID)
	return nil
}

// Get retrieves a plugin by ID
func (r *PluginRegistry) Get(pluginID uuid.UUID) (interfaces.Plugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.plugins[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}

	return plugin, nil
}

// List returns all registered plugins
func (r *PluginRegistry) List() []interfaces.Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]interfaces.Plugin, 0, len(r.plugins))
	for _, plugin := range r.plugins {
		plugins = append(plugins, plugin)
	}

	return plugins
}

// GetMetadata returns plugin metadata
func (r *PluginRegistry) GetMetadata(pluginID uuid.UUID) (*interfaces.PluginMetadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	metadata, exists := r.metadata[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}

	return metadata, nil
}

// GetByType returns plugins of a specific type
func (r *PluginRegistry) GetByType(pluginType interfaces.PluginType) []interfaces.Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var plugins []interfaces.Plugin
	for id, metadata := range r.metadata {
		if metadata.Type == pluginType {
			if plugin, exists := r.plugins[id]; exists {
				plugins = append(plugins, plugin)
			}
		}
	}

	return plugins
}

// UpdateStatus updates plugin status
func (r *PluginRegistry) UpdateStatus(pluginID uuid.UUID, status interfaces.PluginStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.status[pluginID] = status
	if health, exists := r.health[pluginID]; exists {
		health.Status = status
		health.LastCheck = time.Now()
	}
}

// GetStatus returns plugin status
func (r *PluginRegistry) GetStatus(pluginID uuid.UUID) (interfaces.PluginStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status, exists := r.status[pluginID]
	if !exists {
		return interfaces.PluginStatusUnknown, fmt.Errorf("plugin %s not found", pluginID)
	}

	return status, nil
}

// UpdateHealth updates plugin health information
func (r *PluginRegistry) UpdateHealth(pluginID uuid.UUID, health *interfaces.PluginHealth) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.health[pluginID] = health
}

// GetHealth returns plugin health information
func (r *PluginRegistry) GetHealth(pluginID uuid.UUID) (*interfaces.PluginHealth, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	health, exists := r.health[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}

	return health, nil
}

// GetAllHealth returns health information for all plugins
func (r *PluginRegistry) GetAllHealth() map[uuid.UUID]*interfaces.PluginHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()

	healthMap := make(map[uuid.UUID]*interfaces.PluginHealth)
	for id, health := range r.health {
		healthMap[id] = health
	}

	return healthMap
}

// validateMetadata validates plugin metadata
func (r *PluginRegistry) validateMetadata(metadata *interfaces.PluginMetadata) error {
	if metadata.ID == uuid.Nil {
		return fmt.Errorf("plugin ID cannot be nil")
	}

	if metadata.Name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	if metadata.Version == "" {
		return fmt.Errorf("plugin version cannot be empty")
	}

	if metadata.Type == "" {
		return fmt.Errorf("plugin type cannot be empty")
	}

	// Validate plugin type
	validTypes := map[interfaces.PluginType]bool{
		interfaces.PluginTypeMCP:     true,
		interfaces.PluginTypeService: true,
		interfaces.PluginTypeUtility: true,
	}

	if !validTypes[metadata.Type] {
		return fmt.Errorf("invalid plugin type: %s", metadata.Type)
	}

	return nil
}

// StartHealthMonitoring starts background health monitoring
func (r *PluginRegistry) StartHealthMonitoring(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.checkAllPluginHealth(ctx)
			}
		}
	}()
}

// checkAllPluginHealth performs health checks on all plugins
func (r *PluginRegistry) checkAllPluginHealth(ctx context.Context) {
	r.mu.RLock()
	plugins := make(map[uuid.UUID]interfaces.Plugin)
	for id, plugin := range r.plugins {
		plugins[id] = plugin
	}
	r.mu.RUnlock()

	for id, plugin := range plugins {
		go func(pluginID uuid.UUID, p interfaces.Plugin) {
			health := p.GetHealth(ctx)
			r.UpdateHealth(pluginID, health)
		}(id, plugin)
	}
}
