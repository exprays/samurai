package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PluginStatus represents the current state of a plugin
type PluginStatus string

const (
	PluginStatusUnknown    PluginStatus = "unknown"
	PluginStatusDiscovered PluginStatus = "discovered"
	PluginStatusLoaded     PluginStatus = "loaded"
	PluginStatusConfigured PluginStatus = "configured"
	PluginStatusStarting   PluginStatus = "starting"
	PluginStatusRunning    PluginStatus = "running"
	PluginStatusStopping   PluginStatus = "stopping"
	PluginStatusStopped    PluginStatus = "stopped"
	PluginStatusError      PluginStatus = "error"
	PluginStatusUnloaded   PluginStatus = "unloaded"
)

// PluginType defines the category of plugin
type PluginType string

const (
	PluginTypeMCP     PluginType = "mcp"
	PluginTypeService PluginType = "service"
	PluginTypeUtility PluginType = "utility"
)

// PluginCapability represents what a plugin can do
type PluginCapability struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"` // tool, resource, prompt, endpoint
	Schema      map[string]interface{} `json:"schema,omitempty"`
}

// PluginMetadata contains plugin information
type PluginMetadata struct {
	ID           uuid.UUID              `json:"id"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Author       string                 `json:"author"`
	Type         PluginType             `json:"type"`
	Tags         []string               `json:"tags"`
	Dependencies []string               `json:"dependencies"`
	Capabilities []PluginCapability     `json:"capabilities"`
	ConfigSchema map[string]interface{} `json:"config_schema"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Enabled     bool                   `json:"enabled"`
	Settings    map[string]interface{} `json:"settings"`
	Resources   *ResourceLimits        `json:"resources,omitempty"`
	Permissions []string               `json:"permissions"`
}

// ResourceLimits defines resource constraints for plugin execution
type ResourceLimits struct {
	MaxMemoryMB      int           `json:"max_memory_mb"`
	MaxCPUPercent    int           `json:"max_cpu_percent"`
	MaxExecutionTime time.Duration `json:"max_execution_time"`
	MaxConcurrency   int           `json:"max_concurrency"`
}

// PluginMessage represents communication between system and plugin
type PluginMessage struct {
	ID        uuid.UUID              `json:"id"`
	Type      string                 `json:"type"`
	Method    string                 `json:"method,omitempty"`
	Payload   map[string]interface{} `json:"payload"`
	Timestamp time.Time              `json:"timestamp"`
}

// PluginResponse represents plugin response
type PluginResponse struct {
	ID        uuid.UUID              `json:"id"`
	RequestID uuid.UUID              `json:"request_id"`
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// PluginHealth represents plugin health status
type PluginHealth struct {
	Status    PluginStatus           `json:"status"`
	Healthy   bool                   `json:"healthy"`
	LastCheck time.Time              `json:"last_check"`
	Uptime    time.Duration          `json:"uptime"`
	Metrics   map[string]interface{} `json:"metrics"`
	Errors    []string               `json:"errors,omitempty"`
}

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	// Metadata returns plugin information
	GetMetadata() *PluginMetadata

	// Configuration methods
	ValidateConfig(config *PluginConfig) error
	UpdateConfig(config *PluginConfig) error
	GetConfig() *PluginConfig

	// Lifecycle methods
	Initialize(ctx context.Context, logger *zap.SugaredLogger) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Shutdown(ctx context.Context) error

	// Health and status
	GetStatus() PluginStatus
	GetHealth(ctx context.Context) *PluginHealth
	IsHealthy() bool

	// Communication
	HandleMessage(ctx context.Context, message *PluginMessage) (*PluginResponse, error)
	SendMessage(ctx context.Context, message *PluginMessage) error

	// Capabilities
	GetCapabilities() []PluginCapability
	ExecuteCapability(ctx context.Context, capability string, params map[string]interface{}) (*PluginResponse, error)
}

// MCPPlugin extends Plugin with MCP-specific functionality
type MCPPlugin interface {
	Plugin

	// MCP Protocol methods
	ListTools(ctx context.Context) ([]MCPTool, error)
	CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*MCPToolResult, error)
	ListResources(ctx context.Context) ([]MCPResource, error)
	ReadResource(ctx context.Context, uri string) (*MCPResourceContent, error)
	ListPrompts(ctx context.Context) ([]MCPPrompt, error)
	GetPrompt(ctx context.Context, name string, arguments map[string]interface{}) (*MCPPromptResult, error)
}

// ServicePlugin extends Plugin with service-specific functionality
type ServicePlugin interface {
	Plugin

	// Service-specific methods
	GetServiceInfo() *ServiceInfo
	TestConnection(ctx context.Context) error
	GetServiceHealth(ctx context.Context) *ServiceHealth
}

// PluginManager defines the interface for plugin management
type PluginManager interface {
	// Plugin lifecycle
	LoadPlugin(ctx context.Context, path string) (Plugin, error)
	UnloadPlugin(ctx context.Context, pluginID uuid.UUID) error
	StartPlugin(ctx context.Context, pluginID uuid.UUID) error
	StopPlugin(ctx context.Context, pluginID uuid.UUID) error

	// Plugin registry
	RegisterPlugin(plugin Plugin) error
	UnregisterPlugin(pluginID uuid.UUID) error
	GetPlugin(pluginID uuid.UUID) (Plugin, error)
	ListPlugins() []Plugin
	GetPluginsByType(pluginType PluginType) []Plugin

	// Plugin communication
	SendMessageToPlugin(ctx context.Context, pluginID uuid.UUID, message *PluginMessage) (*PluginResponse, error)
	BroadcastMessage(ctx context.Context, message *PluginMessage) error

	// Health and monitoring
	GetPluginHealth(pluginID uuid.UUID) (*PluginHealth, error)
	GetAllPluginHealth() map[uuid.UUID]*PluginHealth
}
