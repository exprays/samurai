package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"samurai/backend/internal/database"
	"samurai/backend/internal/plugin/interfaces"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ConfigManager manages plugin configurations
type ConfigManager struct {
	mu        sync.RWMutex
	configs   map[uuid.UUID]*PluginConfigEntry
	configDir string
	validator *ConfigValidator
	db        *database.Database
	logger    *zap.SugaredLogger

	// Configuration watching
	watchers    map[uuid.UUID]*ConfigWatcher
	autoReload  bool
	reloadDelay time.Duration
}

// PluginConfigEntry represents a stored plugin configuration
type PluginConfigEntry struct {
	PluginID     uuid.UUID                `json:"plugin_id"`
	PluginName   string                   `json:"plugin_name"`
	Version      string                   `json:"version"`
	Config       *interfaces.PluginConfig `json:"config"`
	Schema       map[string]interface{}   `json:"schema"`
	FilePath     string                   `json:"file_path"`
	LastModified time.Time                `json:"last_modified"`
	Checksum     string                   `json:"checksum"`
	IsActive     bool                     `json:"is_active"`
	Environment  string                   `json:"environment"`
}

// ConfigWatcher watches configuration files for changes
type ConfigWatcher struct {
	pluginID  uuid.UUID
	filePath  string
	lastMod   time.Time
	stopChan  chan struct{}
	onChanged func(uuid.UUID)
}

// ManagerOptions configures the configuration manager
type ManagerOptions struct {
	ConfigDir   string        `json:"config_dir"`
	AutoReload  bool          `json:"auto_reload"`
	ReloadDelay time.Duration `json:"reload_delay"`
	Environment string        `json:"environment"`
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(
	options *ManagerOptions,
	db *database.Database,
	logger *zap.SugaredLogger,
) *ConfigManager {
	if options.ReloadDelay == 0 {
		options.ReloadDelay = 5 * time.Second
	}

	return &ConfigManager{
		configs:     make(map[uuid.UUID]*PluginConfigEntry),
		configDir:   options.ConfigDir,
		validator:   NewConfigValidator(logger),
		db:          db,
		logger:      logger.Named("config-manager"),
		watchers:    make(map[uuid.UUID]*ConfigWatcher),
		autoReload:  options.AutoReload,
		reloadDelay: options.ReloadDelay,
	}
}

// Initialize initializes the configuration manager
func (cm *ConfigManager) Initialize(ctx context.Context) error {
	cm.logger.Info("Initializing configuration manager")

	// Ensure config directory exists
	if err := os.MkdirAll(cm.configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Load existing configurations
	if err := cm.loadAllConfigurations(ctx); err != nil {
		return fmt.Errorf("failed to load configurations: %w", err)
	}

	cm.logger.Infow("Configuration manager initialized",
		"config_dir", cm.configDir,
		"loaded_configs", len(cm.configs),
	)

	return nil
}

// LoadPluginConfig loads configuration for a specific plugin
func (cm *ConfigManager) LoadPluginConfig(ctx context.Context, pluginID uuid.UUID, pluginName string) (*interfaces.PluginConfig, error) {
	cm.mu.RLock()
	entry, exists := cm.configs[pluginID]
	cm.mu.RUnlock()

	if exists {
		return entry.Config, nil
	}

	// Try to load from file
	configPath := cm.getConfigPath(pluginName)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default configuration
		return cm.createDefaultConfig(ctx, pluginID, pluginName)
	}

	// Load from file
	config, err := cm.loadConfigFromFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config from file: %w", err)
	}

	// Store in memory
	entry = &PluginConfigEntry{
		PluginID:     pluginID,
		PluginName:   pluginName,
		Config:       config,
		FilePath:     configPath,
		LastModified: time.Now(),
		IsActive:     true,
	}

	cm.mu.Lock()
	cm.configs[pluginID] = entry
	cm.mu.Unlock()

	// Start watching if auto-reload is enabled
	if cm.autoReload {
		cm.startWatcher(pluginID, configPath)
	}

	return config, nil
}

// SavePluginConfig saves configuration for a plugin
func (cm *ConfigManager) SavePluginConfig(ctx context.Context, pluginID uuid.UUID, pluginName string, config *interfaces.PluginConfig, schema map[string]interface{}) error {
	cm.logger.Infow("Saving plugin configuration",
		"plugin_id", pluginID,
		"plugin_name", pluginName,
	)

	// Validate configuration against schema
	if schema != nil {
		if err := cm.validator.ValidateConfig(config, schema); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	}

	// Prepare configuration entry
	configPath := cm.getConfigPath(pluginName)
	entry := &PluginConfigEntry{
		PluginID:     pluginID,
		PluginName:   pluginName,
		Config:       config,
		Schema:       schema,
		FilePath:     configPath,
		LastModified: time.Now(),
		IsActive:     true,
	}

	// Calculate checksum
	checksum, err := cm.calculateChecksum(config)
	if err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}
	entry.Checksum = checksum

	// Save to file
	if err := cm.saveConfigToFile(configPath, config); err != nil {
		return fmt.Errorf("failed to save config to file: %w", err)
	}

	// Store in memory
	cm.mu.Lock()
	cm.configs[pluginID] = entry
	cm.mu.Unlock()

	// Save to database
	if err := cm.saveConfigToDB(ctx, entry); err != nil {
		cm.logger.Warnw("Failed to save config to database", "error", err)
	}

	// Start watching if auto-reload is enabled
	if cm.autoReload {
		cm.startWatcher(pluginID, configPath)
	}

	cm.logger.Infow("Plugin configuration saved", "plugin_id", pluginID)
	return nil
}

// UpdatePluginConfig updates an existing plugin configuration
func (cm *ConfigManager) UpdatePluginConfig(ctx context.Context, pluginID uuid.UUID, updates map[string]interface{}) error {
	cm.mu.Lock()
	entry, exists := cm.configs[pluginID]
	if !exists {
		cm.mu.Unlock()
		return fmt.Errorf("plugin configuration not found: %s", pluginID)
	}

	// Create a copy of the current config
	updatedConfig := &interfaces.PluginConfig{
		Enabled:     entry.Config.Enabled,
		Settings:    make(map[string]interface{}),
		Resources:   entry.Config.Resources,
		Permissions: entry.Config.Permissions,
	}

	// Copy existing settings
	for k, v := range entry.Config.Settings {
		updatedConfig.Settings[k] = v
	}

	// Apply updates
	for k, v := range updates {
		updatedConfig.Settings[k] = v
	}
	cm.mu.Unlock()

	// Validate updated configuration
	if entry.Schema != nil {
		if err := cm.validator.ValidateConfig(updatedConfig, entry.Schema); err != nil {
			return fmt.Errorf("updated configuration validation failed: %w", err)
		}
	}

	// Save updated configuration
	return cm.SavePluginConfig(ctx, pluginID, entry.PluginName, updatedConfig, entry.Schema)
}

// DeletePluginConfig deletes a plugin configuration
func (cm *ConfigManager) DeletePluginConfig(ctx context.Context, pluginID uuid.UUID) error {
	cm.mu.Lock()
	entry, exists := cm.configs[pluginID]
	if !exists {
		cm.mu.Unlock()
		return fmt.Errorf("plugin configuration not found: %s", pluginID)
	}

	// Stop watcher
	if watcher, exists := cm.watchers[pluginID]; exists {
		close(watcher.stopChan)
		delete(cm.watchers, pluginID)
	}

	// Remove from memory
	delete(cm.configs, pluginID)
	cm.mu.Unlock()

	// Delete file
	if err := os.Remove(entry.FilePath); err != nil && !os.IsNotExist(err) {
		cm.logger.Warnw("Failed to delete config file",
			"file_path", entry.FilePath,
			"error", err,
		)
	}

	// Delete from database
	if err := cm.deleteConfigFromDB(ctx, pluginID); err != nil {
		cm.logger.Warnw("Failed to delete config from database", "error", err)
	}

	cm.logger.Infow("Plugin configuration deleted", "plugin_id", pluginID)
	return nil
}

// GetPluginConfig retrieves a plugin configuration
func (cm *ConfigManager) GetPluginConfig(pluginID uuid.UUID) (*interfaces.PluginConfig, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	entry, exists := cm.configs[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin configuration not found: %s", pluginID)
	}

	return entry.Config, nil
}

// ListPluginConfigs returns all plugin configurations
func (cm *ConfigManager) ListPluginConfigs() map[uuid.UUID]*PluginConfigEntry {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	configs := make(map[uuid.UUID]*PluginConfigEntry)
	for id, entry := range cm.configs {
		configs[id] = entry
	}

	return configs
}

// ValidatePluginConfig validates a plugin configuration against its schema
func (cm *ConfigManager) ValidatePluginConfig(pluginID uuid.UUID, config *interfaces.PluginConfig) error {
	cm.mu.RLock()
	entry, exists := cm.configs[pluginID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("plugin configuration not found: %s", pluginID)
	}

	if entry.Schema == nil {
		return nil // No schema to validate against
	}

	return cm.validator.ValidateConfig(config, entry.Schema)
}

// ExportPluginConfig exports a plugin configuration to a file
func (cm *ConfigManager) ExportPluginConfig(pluginID uuid.UUID, exportPath string) error {
	cm.mu.RLock()
	entry, exists := cm.configs[pluginID]
	cm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("plugin configuration not found: %s", pluginID)
	}

	return cm.saveConfigToFile(exportPath, entry.Config)
}

// ImportPluginConfig imports a plugin configuration from a file
func (cm *ConfigManager) ImportPluginConfig(ctx context.Context, pluginID uuid.UUID, pluginName string, importPath string, schema map[string]interface{}) error {
	// Load configuration from file
	config, err := cm.loadConfigFromFile(importPath)
	if err != nil {
		return fmt.Errorf("failed to load config from import file: %w", err)
	}

	// Save as new configuration
	return cm.SavePluginConfig(ctx, pluginID, pluginName, config, schema)
}

// GetConfigTemplates returns configuration templates for different plugin types
func (cm *ConfigManager) GetConfigTemplates() map[string]*interfaces.PluginConfig {
	return map[string]*interfaces.PluginConfig{
		"mcp": {
			Enabled: true,
			Settings: map[string]interface{}{
				"timeout": 30,
				"retries": 3,
			},
			Resources: &interfaces.ResourceLimits{
				MaxMemoryMB:      128,
				MaxCPUPercent:    10,
				MaxExecutionTime: 30 * time.Second,
				MaxConcurrency:   10,
			},
			Permissions: []string{"read", "write"},
		},
		"service": {
			Enabled: true,
			Settings: map[string]interface{}{
				"endpoint":   "",
				"api_key":    "",
				"timeout":    60,
				"rate_limit": 100,
			},
			Resources: &interfaces.ResourceLimits{
				MaxMemoryMB:      256,
				MaxCPUPercent:    20,
				MaxExecutionTime: 60 * time.Second,
				MaxConcurrency:   20,
			},
			Permissions: []string{"network", "secrets"},
		},
		"utility": {
			Enabled: true,
			Settings: map[string]interface{}{
				"cache_size": 1000,
				"log_level":  "info",
			},
			Resources: &interfaces.ResourceLimits{
				MaxMemoryMB:      64,
				MaxCPUPercent:    5,
				MaxExecutionTime: 10 * time.Second,
				MaxConcurrency:   5,
			},
			Permissions: []string{"read"},
		},
	}
}

// Private methods

func (cm *ConfigManager) getConfigPath(pluginName string) string {
	return filepath.Join(cm.configDir, fmt.Sprintf("%s.json", pluginName))
}

func (cm *ConfigManager) loadConfigFromFile(filePath string) (*interfaces.PluginConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config interfaces.PluginConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (cm *ConfigManager) saveConfigToFile(filePath string, config *interfaces.PluginConfig) error {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

func (cm *ConfigManager) createDefaultConfig(ctx context.Context, pluginID uuid.UUID, pluginName string) (*interfaces.PluginConfig, error) {
	config := &interfaces.PluginConfig{
		Enabled:  false,
		Settings: make(map[string]interface{}),
		Resources: &interfaces.ResourceLimits{
			MaxMemoryMB:      128,
			MaxCPUPercent:    10,
			MaxExecutionTime: 30 * time.Second,
			MaxConcurrency:   10,
		},
		Permissions: []string{},
	}

	// Save default configuration
	if err := cm.SavePluginConfig(ctx, pluginID, pluginName, config, nil); err != nil {
		return nil, fmt.Errorf("failed to save default config: %w", err)
	}

	return config, nil
}

func (cm *ConfigManager) loadAllConfigurations(ctx context.Context) error {
	// Load from database first
	if err := cm.loadConfigsFromDB(ctx); err != nil {
		cm.logger.Warnw("Failed to load configs from database", "error", err)
	}

	// Load from files
	return filepath.Walk(cm.configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		config, err := cm.loadConfigFromFile(path)
		if err != nil {
			cm.logger.Warnw("Failed to load config file",
				"file_path", path,
				"error", err,
			)
			return nil
		}

		// Create entry for file-based config
		pluginName := filepath.Base(path[:len(path)-5]) // Remove .json extension
		entry := &PluginConfigEntry{
			PluginID:     uuid.New(), // Generate ID for file-based configs
			PluginName:   pluginName,
			Config:       config,
			FilePath:     path,
			LastModified: info.ModTime(),
			IsActive:     true,
		}

		cm.configs[entry.PluginID] = entry

		// Start watcher if auto-reload is enabled
		if cm.autoReload {
			cm.startWatcher(entry.PluginID, path)
		}

		return nil
	})
}

func (cm *ConfigManager) calculateChecksum(config *interfaces.PluginConfig) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}

	// Simple checksum using length and first few bytes
	// In production, use a proper hash function like SHA-256
	if len(data) == 0 {
		return "empty", nil
	}

	checksum := fmt.Sprintf("%d_%x", len(data), data[:min(len(data), 8)])
	return checksum, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (cm *ConfigManager) startWatcher(pluginID uuid.UUID, filePath string) {
	// Stop existing watcher if any
	if watcher, exists := cm.watchers[pluginID]; exists {
		close(watcher.stopChan)
	}

	// Get initial modification time
	info, err := os.Stat(filePath)
	if err != nil {
		cm.logger.Warnw("Failed to stat config file for watching",
			"file_path", filePath,
			"error", err,
		)
		return
	}

	watcher := &ConfigWatcher{
		pluginID:  pluginID,
		filePath:  filePath,
		lastMod:   info.ModTime(),
		stopChan:  make(chan struct{}),
		onChanged: cm.handleConfigChange,
	}

	cm.watchers[pluginID] = watcher

	// Start watching in goroutine
	go cm.watchConfigFile(watcher)
}

func (cm *ConfigManager) watchConfigFile(watcher *ConfigWatcher) {
	ticker := time.NewTicker(cm.reloadDelay)
	defer ticker.Stop()

	for {
		select {
		case <-watcher.stopChan:
			return
		case <-ticker.C:
			info, err := os.Stat(watcher.filePath)
			if err != nil {
				continue
			}

			if info.ModTime().After(watcher.lastMod) {
				watcher.lastMod = info.ModTime()
				watcher.onChanged(watcher.pluginID)
			}
		}
	}
}

func (cm *ConfigManager) handleConfigChange(pluginID uuid.UUID) {
	cm.logger.Infow("Configuration file changed, reloading", "plugin_id", pluginID)

	cm.mu.RLock()
	entry, exists := cm.configs[pluginID]
	cm.mu.RUnlock()

	if !exists {
		return
	}

	// Reload configuration from file
	config, err := cm.loadConfigFromFile(entry.FilePath)
	if err != nil {
		cm.logger.Errorw("Failed to reload configuration",
			"plugin_id", pluginID,
			"file_path", entry.FilePath,
			"error", err,
		)
		return
	}

	// Validate if schema is available
	if entry.Schema != nil {
		if err := cm.validator.ValidateConfig(config, entry.Schema); err != nil {
			cm.logger.Errorw("Reloaded configuration is invalid",
				"plugin_id", pluginID,
				"error", err,
			)
			return
		}
	}

	// Update in memory
	cm.mu.Lock()
	entry.Config = config
	entry.LastModified = time.Now()
	cm.mu.Unlock()

	cm.logger.Infow("Configuration reloaded successfully", "plugin_id", pluginID)
}

// Database operations (placeholder implementations)

func (cm *ConfigManager) saveConfigToDB(ctx context.Context, entry *PluginConfigEntry) error {
	// TODO: Implement database save
	cm.logger.Debug("Saving config to database (not implemented)")
	return nil
}

func (cm *ConfigManager) loadConfigsFromDB(ctx context.Context) error {
	// TODO: Implement database load
	cm.logger.Debug("Loading configs from database (not implemented)")
	return nil
}

func (cm *ConfigManager) deleteConfigFromDB(ctx context.Context, pluginID uuid.UUID) error {
	// TODO: Implement database delete
	cm.logger.Debug("Deleting config from database (not implemented)")
	return nil
}
