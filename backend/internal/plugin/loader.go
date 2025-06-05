package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"sync"
	"time"

	"samurai/backend/internal/database"
	"samurai/backend/internal/plugin/interfaces"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PluginManifest represents plugin metadata from manifest file
type PluginManifest struct {
	Name         string                        `json:"name"`
	Version      string                        `json:"version"`
	Description  string                        `json:"description"`
	Author       string                        `json:"author"`
	Type         interfaces.PluginType         `json:"type"`
	Tags         []string                      `json:"tags"`
	Binary       string                        `json:"binary"`
	EntryPoint   string                        `json:"entry_point"`
	Dependencies []PluginDependency            `json:"dependencies"`
	Capabilities []interfaces.PluginCapability `json:"capabilities"`
	ConfigSchema map[string]interface{}        `json:"config_schema"`
	Resources    *interfaces.ResourceLimits    `json:"resources,omitempty"`
	Permissions  []string                      `json:"permissions"`
}

// PluginDependency represents a plugin dependency
type PluginDependency struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	MinVersion string `json:"min_version,omitempty"`
	MaxVersion string `json:"max_version,omitempty"`
	Optional   bool   `json:"optional"`
}

// LoadedPlugin represents a loaded plugin with its metadata
type LoadedPlugin struct {
	Plugin   interfaces.Plugin
	Manifest *PluginManifest
	LoadedAt time.Time
	LoadPath string
	GoPlugin *plugin.Plugin
}

// PluginLoader handles plugin discovery and loading
type PluginLoader struct {
	mu            sync.RWMutex
	pluginDirs    []string
	loadedPlugins map[uuid.UUID]*LoadedPlugin
	registry      *PluginRegistry
	validator     *ConfigValidator
	db            *database.Database
	logger        *zap.SugaredLogger
}

// NewPluginLoader creates a new plugin loader
func NewPluginLoader(
	pluginDirs []string,
	registry *PluginRegistry,
	db *database.Database,
	logger *zap.SugaredLogger,
) *PluginLoader {
	return &PluginLoader{
		pluginDirs:    pluginDirs,
		loadedPlugins: make(map[uuid.UUID]*LoadedPlugin),
		registry:      registry,
		validator:     NewConfigValidator(logger),
		db:            db,
		logger:        logger.Named("plugin-loader"),
	}
}

// DiscoverPlugins scans plugin directories for available plugins
func (l *PluginLoader) DiscoverPlugins(ctx context.Context) ([]*PluginManifest, error) {
	l.logger.Info("Starting plugin discovery")

	var allManifests []*PluginManifest

	for _, dir := range l.pluginDirs {
		manifests, err := l.discoverInDirectory(ctx, dir)
		if err != nil {
			l.logger.Warnw("Error discovering plugins in directory",
				"directory", dir,
				"error", err,
			)
			continue
		}
		allManifests = append(allManifests, manifests...)
	}

	l.logger.Infow("Plugin discovery completed",
		"total_found", len(allManifests),
	)

	return allManifests, nil
}

// discoverInDirectory discovers plugins in a specific directory
func (l *PluginLoader) discoverInDirectory(ctx context.Context, dir string) ([]*PluginManifest, error) {
	var manifests []*PluginManifest

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(d.Name(), "manifest.json") {
			return nil
		}

		manifest, err := l.loadManifest(path)
		if err != nil {
			l.logger.Warnw("Failed to load plugin manifest",
				"path", path,
				"error", err,
			)
			return nil // Continue with other plugins
		}

		manifests = append(manifests, manifest)
		return nil
	})

	return manifests, err
}

// loadManifest loads and validates a plugin manifest
func (l *PluginLoader) loadManifest(manifestPath string) (*PluginManifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifest PluginManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	// Validate manifest
	if err := l.validator.ValidateManifest(&manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	// Make binary path relative to manifest directory
	manifestDir := filepath.Dir(manifestPath)
	if !filepath.IsAbs(manifest.Binary) {
		manifest.Binary = filepath.Join(manifestDir, manifest.Binary)
	}

	return &manifest, nil
}

// LoadPlugin loads a plugin from the given path
func (l *PluginLoader) LoadPlugin(ctx context.Context, manifestPath string) (interfaces.Plugin, error) {
	l.logger.Infow("Loading plugin", "manifest_path", manifestPath)

	// Load manifest
	manifest, err := l.loadManifest(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	// Check if plugin is already loaded
	l.mu.RLock()
	for _, loaded := range l.loadedPlugins {
		if loaded.Manifest.Name == manifest.Name && loaded.Manifest.Version == manifest.Version {
			l.mu.RUnlock()
			return loaded.Plugin, nil
		}
	}
	l.mu.RUnlock()

	// Validate dependencies
	if err := l.validateDependencies(manifest); err != nil {
		return nil, fmt.Errorf("dependency validation failed: %w", err)
	}

	// Load plugin binary
	pluginInstance, goPlugin, err := l.loadPluginBinary(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin binary: %w", err)
	}

	// Initialize plugin
	if err := pluginInstance.Initialize(ctx, l.logger); err != nil {
		return nil, fmt.Errorf("plugin initialization failed: %w", err)
	}

	// Create loaded plugin record
	loadedPlugin := &LoadedPlugin{
		Plugin:   pluginInstance,
		Manifest: manifest,
		LoadedAt: time.Now(),
		LoadPath: manifestPath,
		GoPlugin: goPlugin,
	}

	// Store loaded plugin
	metadata := pluginInstance.GetMetadata()
	l.mu.Lock()
	l.loadedPlugins[metadata.ID] = loadedPlugin
	l.mu.Unlock()

	// Register with registry
	if err := l.registry.Register(pluginInstance); err != nil {
		// Clean up on registration failure
		l.mu.Lock()
		delete(l.loadedPlugins, metadata.ID)
		l.mu.Unlock()
		return nil, fmt.Errorf("failed to register plugin: %w", err)
	}

	l.logger.Infow("Plugin loaded successfully",
		"plugin_id", metadata.ID,
		"name", metadata.Name,
		"version", metadata.Version,
	)

	return pluginInstance, nil
}

// loadPluginBinary loads the actual plugin binary
func (l *PluginLoader) loadPluginBinary(manifest *PluginManifest) (interfaces.Plugin, *plugin.Plugin, error) {
	// Check if binary exists
	if _, err := os.Stat(manifest.Binary); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("plugin binary not found: %s", manifest.Binary)
	}

	// Load Go plugin
	goPlugin, err := plugin.Open(manifest.Binary)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open plugin binary: %w", err)
	}

	// Look up entry point symbol
	symbol, err := goPlugin.Lookup(manifest.EntryPoint)
	if err != nil {
		return nil, nil, fmt.Errorf("entry point '%s' not found in plugin: %w", manifest.EntryPoint, err)
	}

	// Type assert to plugin factory function
	factoryFunc, ok := symbol.(func() interfaces.Plugin)
	if !ok {
		return nil, nil, fmt.Errorf("entry point '%s' is not a valid plugin factory function", manifest.EntryPoint)
	}

	// Create plugin instance
	pluginInstance := factoryFunc()
	if pluginInstance == nil {
		return nil, nil, fmt.Errorf("plugin factory returned nil")
	}

	return pluginInstance, goPlugin, nil
}

// validateDependencies validates plugin dependencies
func (l *PluginLoader) validateDependencies(manifest *PluginManifest) error {
	for _, dep := range manifest.Dependencies {
		if dep.Optional {
			continue // Skip optional dependencies for now
		}

		// Check if dependency is loaded
		found := false
		l.mu.RLock()
		for _, loaded := range l.loadedPlugins {
			if loaded.Manifest.Name == dep.Name {
				// TODO: Add version compatibility checking
				found = true
				break
			}
		}
		l.mu.RUnlock()

		if !found {
			return fmt.Errorf("required dependency '%s' not found", dep.Name)
		}
	}

	return nil
}

// UnloadPlugin unloads a plugin
func (l *PluginLoader) UnloadPlugin(ctx context.Context, pluginID uuid.UUID) error {
	l.mu.Lock()
	loaded, exists := l.loadedPlugins[pluginID]
	if !exists {
		l.mu.Unlock()
		return fmt.Errorf("plugin %s not loaded", pluginID)
	}
	delete(l.loadedPlugins, pluginID)
	l.mu.Unlock()

	// Stop plugin if running
	if err := loaded.Plugin.Stop(ctx); err != nil {
		l.logger.Warnw("Error stopping plugin during unload",
			"plugin_id", pluginID,
			"error", err,
		)
	}

	// Shutdown plugin
	if err := loaded.Plugin.Shutdown(ctx); err != nil {
		l.logger.Warnw("Error shutting down plugin during unload",
			"plugin_id", pluginID,
			"error", err,
		)
	}

	// Unregister from registry
	if err := l.registry.Unregister(pluginID); err != nil {
		l.logger.Warnw("Error unregistering plugin",
			"plugin_id", pluginID,
			"error", err,
		)
	}

	l.logger.Infow("Plugin unloaded",
		"plugin_id", pluginID,
		"name", loaded.Manifest.Name,
	)

	return nil
}

// LoadAllPlugins discovers and loads all available plugins
func (l *PluginLoader) LoadAllPlugins(ctx context.Context) error {
	manifests, err := l.DiscoverPlugins(ctx)
	if err != nil {
		return fmt.Errorf("plugin discovery failed: %w", err)
	}

	var loadErrors []string
	for _, manifest := range manifests {
		manifestPath := l.findManifestPath(manifest)
		if manifestPath == "" {
			continue
		}

		_, err := l.LoadPlugin(ctx, manifestPath)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", manifest.Name, err))
			l.logger.Warnw("Failed to load plugin",
				"plugin", manifest.Name,
				"error", err,
			)
		}
	}

	if len(loadErrors) > 0 {
		l.logger.Warnw("Some plugins failed to load",
			"failed_count", len(loadErrors),
			"errors", loadErrors,
		)
	}

	return nil
}

// findManifestPath finds the manifest path for a given manifest
func (l *PluginLoader) findManifestPath(manifest *PluginManifest) string {
	for _, dir := range l.pluginDirs {
		manifestPath := filepath.Join(dir, manifest.Name, "manifest.json")
		if _, err := os.Stat(manifestPath); err == nil {
			return manifestPath
		}
	}
	return ""
}

// GetLoadedPlugins returns all loaded plugins
func (l *PluginLoader) GetLoadedPlugins() map[uuid.UUID]*LoadedPlugin {
	l.mu.RLock()
	defer l.mu.RUnlock()

	loaded := make(map[uuid.UUID]*LoadedPlugin)
	for id, plugin := range l.loadedPlugins {
		loaded[id] = plugin
	}

	return loaded
}

// ReloadPlugin reloads a specific plugin
func (l *PluginLoader) ReloadPlugin(ctx context.Context, pluginID uuid.UUID) error {
	l.mu.RLock()
	loaded, exists := l.loadedPlugins[pluginID]
	if !exists {
		l.mu.RUnlock()
		return fmt.Errorf("plugin %s not loaded", pluginID)
	}
	manifestPath := loaded.LoadPath
	l.mu.RUnlock()

	// Unload current plugin
	if err := l.UnloadPlugin(ctx, pluginID); err != nil {
		return fmt.Errorf("failed to unload plugin for reload: %w", err)
	}

	// Load plugin again
	_, err := l.LoadPlugin(ctx, manifestPath)
	if err != nil {
		return fmt.Errorf("failed to reload plugin: %w", err)
	}

	return nil
}

// StartWatcher starts watching plugin directories for changes
func (l *PluginLoader) StartWatcher(ctx context.Context) {
	// TODO: Implement file system watcher for hot-reloading
	// This would watch for changes in plugin directories and automatically reload plugins
	l.logger.Info("Plugin directory watcher started (placeholder)")
}
