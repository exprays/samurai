package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"samurai/backend/internal/database"
	"samurai/backend/internal/plugin/interfaces"

	"go.uber.org/zap"
)

// PluginDiscovery handles plugin discovery and metadata caching
type PluginDiscovery struct {
	mu           sync.RWMutex
	searchPaths  []string
	cache        map[string]*PluginManifest
	lastScan     time.Time
	scanInterval time.Duration
	db           *database.Database
	logger       *zap.SugaredLogger
}

// NewPluginDiscovery creates a new plugin discovery service
func NewPluginDiscovery(
	searchPaths []string,
	scanInterval time.Duration,
	db *database.Database,
	logger *zap.SugaredLogger,
) *PluginDiscovery {
	return &PluginDiscovery{
		searchPaths:  searchPaths,
		cache:        make(map[string]*PluginManifest),
		scanInterval: scanInterval,
		db:           db,
		logger:       logger.Named("plugin-discovery"),
	}
}

// ScanResult represents the result of a plugin scan
type ScanResult struct {
	Found    []*PluginManifest
	Errors   []PluginError
	Duration time.Duration
}

// PluginError represents a plugin-related error
type PluginError struct {
	Path    string
	Message string
	Error   error
}

// Scan performs a full scan of all search paths
func (d *PluginDiscovery) Scan(ctx context.Context, force bool) (*ScanResult, error) {
	startTime := time.Now()

	// Check if scan is needed
	if !force && time.Since(d.lastScan) < d.scanInterval {
		return d.getCachedResult(), nil
	}

	d.logger.Info("Starting plugin scan")

	var allManifests []*PluginManifest
	var allErrors []PluginError

	for _, searchPath := range d.searchPaths {
		manifests, errors := d.scanPath(ctx, searchPath)
		allManifests = append(allManifests, manifests...)
		allErrors = append(allErrors, errors...)
	}

	// Update cache
	d.mu.Lock()
	d.cache = make(map[string]*PluginManifest)
	for _, manifest := range allManifests {
		key := fmt.Sprintf("%s@%s", manifest.Name, manifest.Version)
		d.cache[key] = manifest
	}
	d.lastScan = time.Now()
	d.mu.Unlock()

	result := &ScanResult{
		Found:    allManifests,
		Errors:   allErrors,
		Duration: time.Since(startTime),
	}

	d.logger.Infow("Plugin scan completed",
		"found", len(allManifests),
		"errors", len(allErrors),
		"duration", result.Duration,
	)

	return result, nil
}

// scanPath scans a specific path for plugins
func (d *PluginDiscovery) scanPath(ctx context.Context, searchPath string) ([]*PluginManifest, []PluginError) {
	var manifests []*PluginManifest
	var errors []PluginError

	err := filepath.WalkDir(searchPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			errors = append(errors, PluginError{
				Path:    path,
				Message: "Failed to access path",
				Error:   err,
			})
			return nil // Continue walking
		}

		// Look for manifest files
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "manifest.json") {
			return nil
		}

		manifest, err := d.loadAndValidateManifest(path)
		if err != nil {
			errors = append(errors, PluginError{
				Path:    path,
				Message: "Failed to load manifest",
				Error:   err,
			})
			return nil
		}

		manifests = append(manifests, manifest)
		return nil
	})

	if err != nil {
		errors = append(errors, PluginError{
			Path:    searchPath,
			Message: "Failed to scan directory",
			Error:   err,
		})
	}

	return manifests, errors
}

// loadAndValidateManifest loads and validates a plugin manifest
func (d *PluginDiscovery) loadAndValidateManifest(manifestPath string) (*PluginManifest, error) {
	loader := &PluginLoader{logger: d.logger}
	return loader.loadManifest(manifestPath)
}

// GetAvailablePlugins returns all available plugins from cache
func (d *PluginDiscovery) GetAvailablePlugins() []*PluginManifest {
	d.mu.RLock()
	defer d.mu.RUnlock()

	manifests := make([]*PluginManifest, 0, len(d.cache))
	for _, manifest := range d.cache {
		manifests = append(manifests, manifest)
	}

	return manifests
}

// FindPlugin finds a plugin by name and optional version
func (d *PluginDiscovery) FindPlugin(name string, version string) (*PluginManifest, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if version != "" {
		key := fmt.Sprintf("%s@%s", name, version)
		if manifest, exists := d.cache[key]; exists {
			return manifest, nil
		}
		return nil, fmt.Errorf("plugin %s version %s not found", name, version)
	}

	// Find latest version if no version specified
	var latestManifest *PluginManifest
	for _, manifest := range d.cache {
		if manifest.Name == name {
			if latestManifest == nil || d.compareVersions(manifest.Version, latestManifest.Version) > 0 {
				latestManifest = manifest
			}
		}
	}

	if latestManifest == nil {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	return latestManifest, nil
}

// GetPluginsByType returns plugins of a specific type
func (d *PluginDiscovery) GetPluginsByType(pluginType interfaces.PluginType) []*PluginManifest {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*PluginManifest
	for _, manifest := range d.cache {
		if manifest.Type == pluginType {
			result = append(result, manifest)
		}
	}

	return result
}

// GetPluginsByTag returns plugins with specific tags
func (d *PluginDiscovery) GetPluginsByTag(tag string) []*PluginManifest {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*PluginManifest
	for _, manifest := range d.cache {
		for _, manifestTag := range manifest.Tags {
			if manifestTag == tag {
				result = append(result, manifest)
				break
			}
		}
	}

	return result
}

// getCachedResult returns a cached scan result
func (d *PluginDiscovery) getCachedResult() *ScanResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	manifests := make([]*PluginManifest, 0, len(d.cache))
	for _, manifest := range d.cache {
		manifests = append(manifests, manifest)
	}

	return &ScanResult{
		Found:    manifests,
		Errors:   []PluginError{},
		Duration: 0, // Cached result
	}
}

// compareVersions compares two version strings (simplified semantic versioning)
func (d *PluginDiscovery) compareVersions(v1, v2 string) int {
	// TODO: Implement proper semantic version comparison
	// For now, simple string comparison
	if v1 == v2 {
		return 0
	}
	if v1 > v2 {
		return 1
	}
	return -1
}

// StartPeriodicScan starts periodic scanning in the background
func (d *PluginDiscovery) StartPeriodicScan(ctx context.Context) {
	if d.scanInterval <= 0 {
		d.logger.Info("Periodic scanning disabled")
		return
	}

	ticker := time.NewTicker(d.scanInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				d.logger.Info("Stopping periodic plugin scan")
				return
			case <-ticker.C:
				_, err := d.Scan(ctx, false)
				if err != nil {
					d.logger.Warnw("Periodic plugin scan failed", "error", err)
				}
			}
		}
	}()

	d.logger.Infow("Started periodic plugin scanning",
		"interval", d.scanInterval,
	)
}
