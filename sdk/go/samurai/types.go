package samurai

import (
	"time"

	"github.com/google/uuid"
)

// PluginMetadata represents plugin metadata
type PluginMetadata struct {
	ID           uuid.UUID          `json:"id"`
	Name         string             `json:"name"`
	Version      string             `json:"version"`
	Description  string             `json:"description"`
	Author       string             `json:"author"`
	Type         PluginType         `json:"type"`
	Tags         []string           `json:"tags"`
	Capabilities []PluginCapability `json:"capabilities"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Enabled     bool                   `json:"enabled"`
	Settings    map[string]interface{} `json:"settings"`
	Resources   *ResourceLimits        `json:"resources,omitempty"`
	Permissions []string               `json:"permissions"`
}

// ResourceLimits defines resource constraints for plugins
type ResourceLimits struct {
	MaxMemoryMB      int           `json:"max_memory_mb"`
	MaxCPUPercent    int           `json:"max_cpu_percent"`
	MaxExecutionTime time.Duration `json:"max_execution_time"`
	MaxConcurrency   int           `json:"max_concurrency"`
}

// PluginType represents the type of plugin
type PluginType string

const (
	PluginTypeMCP     PluginType = "mcp"
	PluginTypeService PluginType = "service"
	PluginTypeUtility PluginType = "utility"
)

// PluginCapability represents a plugin capability
type PluginCapability struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Schema      map[string]interface{} `json:"schema,omitempty"`
}

// Message represents a message between plugin and host
type Message struct {
	ID        uuid.UUID              `json:"id"`
	Type      string                 `json:"type"`
	Role      string                 `json:"role,omitempty"`
	Content   []Content              `json:"content,omitempty"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// Response represents a response from the host
type Response struct {
	ID        uuid.UUID              `json:"id"`
	RequestID uuid.UUID              `json:"request_id"`
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// Event represents an event emitted by a plugin
type Event struct {
	ID        uuid.UUID              `json:"id"`
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
}

// LogLevel represents logging levels
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// PluginStatus represents the status of a plugin
type PluginStatus string

const (
	PluginStatusUnknown  PluginStatus = "unknown"
	PluginStatusLoaded   PluginStatus = "loaded"
	PluginStatusStarting PluginStatus = "starting"
	PluginStatusRunning  PluginStatus = "running"
	PluginStatusStopping PluginStatus = "stopping"
	PluginStatusStopped  PluginStatus = "stopped"
	PluginStatusError    PluginStatus = "error"
)

// Health represents plugin health information
type Health struct {
	Status    PluginStatus           `json:"status"`
	Healthy   bool                   `json:"healthy"`
	LastCheck time.Time              `json:"last_check"`
	Uptime    time.Duration          `json:"uptime"`
	Metrics   map[string]interface{} `json:"metrics"`
	Errors    []string               `json:"errors"`
}
