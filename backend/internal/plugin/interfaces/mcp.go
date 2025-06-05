package interfaces

import (
	"encoding/json"
	"time"
)

// MCPTool represents an MCP tool definition
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// MCPToolResult represents the result of an MCP tool execution
type MCPToolResult struct {
	Content []MCPContent `json:"content"`
	IsError bool         `json:"isError"`
}

// MCPContent represents MCP content
type MCPContent struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	MimeType string          `json:"mimeType,omitempty"`
}

// MCPResource represents an MCP resource
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// MCPResourceContent represents MCP resource content
type MCPResourceContent struct {
	Contents []MCPContent `json:"contents"`
}

// MCPPrompt represents an MCP prompt template
type MCPPrompt struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Arguments   []MCPPromptArgument `json:"arguments,omitempty"`
}

// MCPPromptArgument represents a prompt argument
type MCPPromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// MCPPromptResult represents the result of prompt processing
type MCPPromptResult struct {
	Description string       `json:"description,omitempty"`
	Messages    []MCPMessage `json:"messages"`
}

// MCPMessage represents an MCP message
type MCPMessage struct {
	Role    string       `json:"role"`
	Content []MCPContent `json:"content"`
}

// ServiceInfo represents service plugin information
type ServiceInfo struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Endpoint    string    `json:"endpoint"`
	Status      string    `json:"status"`
	LastChecked time.Time `json:"last_checked"`
}

// ServiceHealth represents service health information
type ServiceHealth struct {
	Available    bool                   `json:"available"`
	ResponseTime time.Duration          `json:"response_time"`
	ErrorRate    float64                `json:"error_rate"`
	LastError    string                 `json:"last_error,omitempty"`
	Metrics      map[string]interface{} `json:"metrics"`
	Dependencies []DependencyHealth     `json:"dependencies,omitempty"`
}

// DependencyHealth represents dependency health status
type DependencyHealth struct {
	Name      string        `json:"name"`
	Available bool          `json:"available"`
	Latency   time.Duration `json:"latency"`
	Error     string        `json:"error,omitempty"`
}
