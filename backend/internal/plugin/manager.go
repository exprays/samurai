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

// PluginManager manages the lifecycle of plugins
type PluginManager struct {
	mu        sync.RWMutex
	plugins   map[uuid.UUID]*ManagedPlugin
	loader    *PluginLoader
	registry  *PluginRegistry
	discovery *PluginDiscovery
	validator *ConfigValidator
	db        *database.Database
	logger    *zap.SugaredLogger

	// Configuration
	pluginDirs   []string
	maxPlugins   int
	startTimeout time.Duration
	stopTimeout  time.Duration

	// State management
	isStarted    bool
	shutdownChan chan struct{}
}

// ManagedPlugin represents a plugin under management
type ManagedPlugin struct {
	Plugin     interfaces.Plugin
	Manifest   *PluginManifest
	Status     interfaces.PluginStatus
	Config     *interfaces.PluginConfig
	LoadedAt   time.Time
	StartedAt  *time.Time
	StoppedAt  *time.Time
	ErrorCount int
	LastError  error
	Metrics    *PluginMetrics
}

// PluginMetrics tracks plugin performance metrics
type PluginMetrics struct {
	RequestCount   int64         `json:"request_count"`
	ResponseCount  int64         `json:"response_count"`
	ErrorCount     int64         `json:"error_count"`
	AverageLatency time.Duration `json:"average_latency"`
	TotalLatency   time.Duration `json:"total_latency"`
	LastActivity   time.Time     `json:"last_activity"`
	MemoryUsage    int64         `json:"memory_usage"`
	CPUUsage       float64       `json:"cpu_usage"`
}

// ManagerConfig configures the plugin manager
type ManagerConfig struct {
	PluginDirs     []string      `json:"plugin_dirs"`
	MaxPlugins     int           `json:"max_plugins"`
	StartTimeout   time.Duration `json:"start_timeout"`
	StopTimeout    time.Duration `json:"stop_timeout"`
	ScanInterval   time.Duration `json:"scan_interval"`
	HealthInterval time.Duration `json:"health_interval"`
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(
	config *ManagerConfig,
	db *database.Database,
	logger *zap.SugaredLogger,
) *PluginManager {
	registry := NewPluginRegistry(db, logger)
	loader := NewPluginLoader(config.PluginDirs, registry, db, logger)
	discovery := NewPluginDiscovery(config.PluginDirs, config.ScanInterval, db, logger)
	validator := NewConfigValidator(logger)

	return &PluginManager{
		plugins:      make(map[uuid.UUID]*ManagedPlugin),
		loader:       loader,
		registry:     registry,
		discovery:    discovery,
		validator:    validator,
		db:           db,
		logger:       logger.Named("plugin-manager"),
		pluginDirs:   config.PluginDirs,
		maxPlugins:   config.MaxPlugins,
		startTimeout: config.StartTimeout,
		stopTimeout:  config.StopTimeout,
		shutdownChan: make(chan struct{}),
	}
}

// Start initializes the plugin manager and starts background services
func (pm *PluginManager) Start(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.isStarted {
		return fmt.Errorf("plugin manager already started")
	}

	pm.logger.Info("Starting plugin manager")

	// Start registry health monitoring
	pm.registry.StartHealthMonitoring(ctx, 30*time.Second)

	// Start discovery periodic scanning
	pm.discovery.StartPeriodicScan(ctx)

	// Discover and load available plugins
	if err := pm.discoverAndLoadPlugins(ctx); err != nil {
		return fmt.Errorf("failed to discover and load plugins: %w", err)
	}

	pm.isStarted = true
	pm.logger.Infow("Plugin manager started", "loaded_plugins", len(pm.plugins))

	return nil
}

// Stop gracefully shuts down the plugin manager
func (pm *PluginManager) Stop(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.isStarted {
		return nil
	}

	pm.logger.Info("Stopping plugin manager")

	// Stop all plugins
	var stopErrors []error
	for pluginID := range pm.plugins {
		if err := pm.stopPluginInternal(ctx, pluginID); err != nil {
			stopErrors = append(stopErrors, err)
		}
	}

	// Signal shutdown
	close(pm.shutdownChan)
	pm.isStarted = false

	if len(stopErrors) > 0 {
		return fmt.Errorf("errors occurred while stopping plugins: %v", stopErrors)
	}

	pm.logger.Info("Plugin manager stopped")
	return nil
}

// LoadPlugin loads a plugin from the specified path
func (pm *PluginManager) LoadPlugin(ctx context.Context, manifestPath string) (interfaces.Plugin, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.plugins) >= pm.maxPlugins {
		return nil, fmt.Errorf("maximum number of plugins (%d) reached", pm.maxPlugins)
	}

	pm.logger.Infow("Loading plugin", "manifest_path", manifestPath)

	// Load plugin using loader
	plugin, err := pm.loader.LoadPlugin(ctx, manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin: %w", err)
	}

	// Get plugin metadata
	metadata := plugin.GetMetadata()
	if metadata == nil {
		return nil, fmt.Errorf("plugin metadata is nil")
	}

	// Check if plugin is already managed
	if _, exists := pm.plugins[metadata.ID]; exists {
		return plugin, nil // Already loaded
	}

	// Get manifest from loader
	loadedPlugins := pm.loader.GetLoadedPlugins()
	var manifest *PluginManifest
	for _, loaded := range loadedPlugins {
		if loaded.Plugin.GetMetadata().ID == metadata.ID {
			manifest = loaded.Manifest
			break
		}
	}

	if manifest == nil {
		return nil, fmt.Errorf("plugin manifest not found")
	}

	// Create managed plugin
	managedPlugin := &ManagedPlugin{
		Plugin:     plugin,
		Manifest:   manifest,
		Status:     interfaces.PluginStatusLoaded,
		LoadedAt:   time.Now(),
		ErrorCount: 0,
		Metrics:    &PluginMetrics{},
	}

	// Store managed plugin
	pm.plugins[metadata.ID] = managedPlugin

	// Update registry status
	pm.registry.UpdateStatus(metadata.ID, interfaces.PluginStatusLoaded)

	pm.logger.Infow("Plugin loaded and managed",
		"plugin_id", metadata.ID,
		"name", metadata.Name,
		"version", metadata.Version,
	)

	return plugin, nil
}

// UnloadPlugin unloads a plugin
func (pm *PluginManager) UnloadPlugin(ctx context.Context, pluginID uuid.UUID) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.unloadPluginInternal(ctx, pluginID)
}

// unloadPluginInternal unloads a plugin (internal, assumes lock is held)
func (pm *PluginManager) unloadPluginInternal(ctx context.Context, pluginID uuid.UUID) error {
	managed, exists := pm.plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	pm.logger.Infow("Unloading plugin", "plugin_id", pluginID)

	// Stop plugin if running
	if managed.Status == interfaces.PluginStatusRunning {
		if err := pm.stopPluginInternal(ctx, pluginID); err != nil {
			pm.logger.Warnw("Error stopping plugin during unload",
				"plugin_id", pluginID,
				"error", err,
			)
		}
	}

	// Unload from loader
	if err := pm.loader.UnloadPlugin(ctx, pluginID); err != nil {
		return fmt.Errorf("failed to unload plugin from loader: %w", err)
	}

	// Remove from managed plugins
	delete(pm.plugins, pluginID)

	pm.logger.Infow("Plugin unloaded", "plugin_id", pluginID)
	return nil
}

// StartPlugin starts a loaded plugin
func (pm *PluginManager) StartPlugin(ctx context.Context, pluginID uuid.UUID) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.startPluginInternal(ctx, pluginID)
}

// startPluginInternal starts a plugin (internal, assumes lock is held)
func (pm *PluginManager) startPluginInternal(ctx context.Context, pluginID uuid.UUID) error {
	managed, exists := pm.plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	if managed.Status == interfaces.PluginStatusRunning {
		return nil // Already running
	}

	pm.logger.Infow("Starting plugin", "plugin_id", pluginID)

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, pm.startTimeout)
	defer cancel()

	// Update status
	managed.Status = interfaces.PluginStatusStarting
	pm.registry.UpdateStatus(pluginID, interfaces.PluginStatusStarting)

	// Start plugin
	if err := managed.Plugin.Start(timeoutCtx); err != nil {
		managed.Status = interfaces.PluginStatusError
		managed.ErrorCount++
		managed.LastError = err
		pm.registry.UpdateStatus(pluginID, interfaces.PluginStatusError)
		return fmt.Errorf("failed to start plugin: %w", err)
	}

	// Update status
	now := time.Now()
	managed.Status = interfaces.PluginStatusRunning
	managed.StartedAt = &now
	managed.StoppedAt = nil
	pm.registry.UpdateStatus(pluginID, interfaces.PluginStatusRunning)

	pm.logger.Infow("Plugin started", "plugin_id", pluginID)
	return nil
}

// StopPlugin stops a running plugin
func (pm *PluginManager) StopPlugin(ctx context.Context, pluginID uuid.UUID) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.stopPluginInternal(ctx, pluginID)
}

// stopPluginInternal stops a plugin (internal, assumes lock is held)
func (pm *PluginManager) stopPluginInternal(ctx context.Context, pluginID uuid.UUID) error {
	managed, exists := pm.plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	if managed.Status != interfaces.PluginStatusRunning {
		return nil // Not running
	}

	pm.logger.Infow("Stopping plugin", "plugin_id", pluginID)

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, pm.stopTimeout)
	defer cancel()

	// Update status
	managed.Status = interfaces.PluginStatusStopping
	pm.registry.UpdateStatus(pluginID, interfaces.PluginStatusStopping)

	// Stop plugin
	if err := managed.Plugin.Stop(timeoutCtx); err != nil {
		managed.Status = interfaces.PluginStatusError
		managed.ErrorCount++
		managed.LastError = err
		pm.registry.UpdateStatus(pluginID, interfaces.PluginStatusError)
		return fmt.Errorf("failed to stop plugin: %w", err)
	}

	// Update status
	now := time.Now()
	managed.Status = interfaces.PluginStatusStopped
	managed.StoppedAt = &now
	pm.registry.UpdateStatus(pluginID, interfaces.PluginStatusStopped)

	pm.logger.Infow("Plugin stopped", "plugin_id", pluginID)
	return nil
}

// RestartPlugin restarts a plugin
func (pm *PluginManager) RestartPlugin(ctx context.Context, pluginID uuid.UUID) error {
	pm.logger.Infow("Restarting plugin", "plugin_id", pluginID)

	// Stop plugin
	if err := pm.StopPlugin(ctx, pluginID); err != nil {
		return fmt.Errorf("failed to stop plugin for restart: %w", err)
	}

	// Start plugin
	if err := pm.StartPlugin(ctx, pluginID); err != nil {
		return fmt.Errorf("failed to start plugin after restart: %w", err)
	}

	return nil
}

// ReloadPlugin reloads a plugin
func (pm *PluginManager) ReloadPlugin(ctx context.Context, pluginID uuid.UUID) error {
	pm.logger.Infow("Reloading plugin", "plugin_id", pluginID)

	// Unload plugin
	if err := pm.UnloadPlugin(ctx, pluginID); err != nil {
		return fmt.Errorf("failed to unload plugin for reload: %w", err)
	}

	// Reload plugin using loader
	if err := pm.loader.ReloadPlugin(ctx, pluginID); err != nil {
		return fmt.Errorf("failed to reload plugin: %w", err)
	}

	return nil
}

// GetPlugin retrieves a managed plugin
func (pm *PluginManager) GetPlugin(pluginID uuid.UUID) (*ManagedPlugin, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	managed, exists := pm.plugins[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}

	return managed, nil
}

// ListPlugins returns all managed plugins
func (pm *PluginManager) ListPlugins() map[uuid.UUID]*ManagedPlugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	plugins := make(map[uuid.UUID]*ManagedPlugin)
	for id, managed := range pm.plugins {
		plugins[id] = managed
	}

	return plugins
}

// GetPluginsByStatus returns plugins with a specific status
func (pm *PluginManager) GetPluginsByStatus(status interfaces.PluginStatus) []*ManagedPlugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var plugins []*ManagedPlugin
	for _, managed := range pm.plugins {
		if managed.Status == status {
			plugins = append(plugins, managed)
		}
	}

	return plugins
}

// GetPluginsByType returns plugins of a specific type
func (pm *PluginManager) GetPluginsByType(pluginType interfaces.PluginType) []*ManagedPlugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var plugins []*ManagedPlugin
	for _, managed := range pm.plugins {
		if managed.Manifest.Type == pluginType {
			plugins = append(plugins, managed)
		}
	}

	return plugins
}

// UpdatePluginConfig updates a plugin's configuration
func (pm *PluginManager) UpdatePluginConfig(ctx context.Context, pluginID uuid.UUID, config *interfaces.PluginConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	managed, exists := pm.plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	// Validate configuration against schema
	if err := pm.validator.ValidateConfig(config, managed.Manifest.ConfigSchema); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Update plugin configuration
	if err := managed.Plugin.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to update plugin configuration: %w", err)
	}

	managed.Config = config
	pm.logger.Infow("Plugin configuration updated", "plugin_id", pluginID)

	return nil
}

// SendMessageToPlugin sends a message to a specific plugin
func (pm *PluginManager) SendMessageToPlugin(ctx context.Context, pluginID uuid.UUID, message *interfaces.PluginMessage) (*interfaces.PluginResponse, error) {
	pm.mu.RLock()
	managed, exists := pm.plugins[pluginID]
	pm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}

	if managed.Status != interfaces.PluginStatusRunning {
		return nil, fmt.Errorf("plugin %s is not running", pluginID)
	}

	// Update metrics
	start := time.Now()
	managed.Metrics.RequestCount++
	managed.Metrics.LastActivity = start

	// Send message to plugin
	response, err := managed.Plugin.HandleMessage(ctx, message)

	// Update metrics
	latency := time.Since(start)
	managed.Metrics.TotalLatency += latency
	if managed.Metrics.RequestCount > 0 {
		managed.Metrics.AverageLatency = managed.Metrics.TotalLatency / time.Duration(managed.Metrics.RequestCount)
	}

	if err != nil {
		managed.Metrics.ErrorCount++
		managed.ErrorCount++
		managed.LastError = err
		return nil, fmt.Errorf("plugin message handling failed: %w", err)
	}

	managed.Metrics.ResponseCount++
	return response, nil
}

// BroadcastMessage sends a message to all running plugins
func (pm *PluginManager) BroadcastMessage(ctx context.Context, message *interfaces.PluginMessage) error {
	pm.mu.RLock()
	runningPlugins := make(map[uuid.UUID]*ManagedPlugin)
	for id, managed := range pm.plugins {
		if managed.Status == interfaces.PluginStatusRunning {
			runningPlugins[id] = managed
		}
	}
	pm.mu.RUnlock()

	var errors []error
	for pluginID := range runningPlugins {
		if _, err := pm.SendMessageToPlugin(ctx, pluginID, message); err != nil {
			errors = append(errors, fmt.Errorf("plugin %s: %w", pluginID, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("broadcast errors: %v", errors)
	}

	return nil
}

// GetPluginHealth returns health information for a plugin
func (pm *PluginManager) GetPluginHealth(pluginID uuid.UUID) (*interfaces.PluginHealth, error) {
	pm.mu.RLock()
	managed, exists := pm.plugins[pluginID]
	pm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}

	// Get health from plugin
	health := managed.Plugin.GetHealth(context.Background())

	// Enhance with manager metrics
	if health.Metrics == nil {
		health.Metrics = make(map[string]interface{})
	}

	health.Metrics["request_count"] = managed.Metrics.RequestCount
	health.Metrics["response_count"] = managed.Metrics.ResponseCount
	health.Metrics["error_count"] = managed.Metrics.ErrorCount
	health.Metrics["average_latency_ms"] = float64(managed.Metrics.AverageLatency.Nanoseconds()) / 1e6
	health.Metrics["last_activity"] = managed.Metrics.LastActivity
	health.Metrics["load_time"] = managed.LoadedAt

	if managed.StartedAt != nil {
		health.Uptime = time.Since(*managed.StartedAt)
		health.Metrics["started_at"] = *managed.StartedAt
	}

	return health, nil
}

// GetAllPluginHealth returns health information for all plugins
func (pm *PluginManager) GetAllPluginHealth() map[uuid.UUID]*interfaces.PluginHealth {
	pm.mu.RLock()
	pluginIDs := make([]uuid.UUID, 0, len(pm.plugins))
	for id := range pm.plugins {
		pluginIDs = append(pluginIDs, id)
	}
	pm.mu.RUnlock()

	healthMap := make(map[uuid.UUID]*interfaces.PluginHealth)
	for _, pluginID := range pluginIDs {
		if health, err := pm.GetPluginHealth(pluginID); err == nil {
			healthMap[pluginID] = health
		}
	}

	return healthMap
}

// discoverAndLoadPlugins discovers and loads all available plugins
func (pm *PluginManager) discoverAndLoadPlugins(ctx context.Context) error {
	// Discover plugins
	result, err := pm.discovery.Scan(ctx, true)
	if err != nil {
		return fmt.Errorf("plugin discovery failed: %w", err)
	}

	pm.logger.Infow("Plugin discovery completed",
		"found", len(result.Found),
		"errors", len(result.Errors),
	)

	// Load discovered plugins
	var loadErrors []error
	for _, manifest := range result.Found {
		manifestPath := pm.findManifestPath(manifest)
		if manifestPath == "" {
			continue
		}

		_, err := pm.LoadPlugin(ctx, manifestPath)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("%s: %w", manifest.Name, err))
			pm.logger.Warnw("Failed to load plugin",
				"plugin", manifest.Name,
				"error", err,
			)
		}
	}

	if len(loadErrors) > 0 {
		pm.logger.Warnw("Some plugins failed to load",
			"failed_count", len(loadErrors),
		)
	}

	return nil
}

// findManifestPath finds the manifest path for a given manifest
func (pm *PluginManager) findManifestPath(manifest *PluginManifest) string {
	for _, dir := range pm.pluginDirs {
		manifestPath := fmt.Sprintf("%s/%s/manifest.json", dir, manifest.Name)
		// TODO: Check if file exists
		return manifestPath
	}
	return ""
}

// GetStats returns manager statistics
func (pm *PluginManager) GetStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := map[string]interface{}{
		"total_plugins": len(pm.plugins),
		"max_plugins":   pm.maxPlugins,
		"is_started":    pm.isStarted,
	}

	// Count by status
	statusCount := make(map[interfaces.PluginStatus]int)
	for _, managed := range pm.plugins {
		statusCount[managed.Status]++
	}

	stats["status_counts"] = statusCount

	// Count by type
	typeCount := make(map[interfaces.PluginType]int)
	for _, managed := range pm.plugins {
		typeCount[managed.Manifest.Type]++
	}

	stats["type_counts"] = typeCount

	return stats
}
