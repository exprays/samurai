package mcp

import (
	"context"
	"fmt"

	"samurai/sdk/go/samurai"

	"github.com/google/uuid"
)

// MCPPlugin represents an MCP protocol plugin
type MCPPlugin struct {
	*samurai.SDK
	tools     []Tool
	resources []Resource
	prompts   []Prompt
	handlers  *HandlerRegistry
}

// Tool represents an MCP tool
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	Handler     ToolHandler            `json:"-"`
}

// Resource represents an MCP resource
type Resource struct {
	URI         string          `json:"uri"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	MimeType    string          `json:"mimeType,omitempty"`
	Handler     ResourceHandler `json:"-"`
}

// Prompt represents an MCP prompt
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
	Handler     PromptHandler    `json:"-"`
}

// PromptArgument represents a prompt argument
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// Content represents MCP content
type Content struct {
	Type     string                 `json:"type"`
	Text     string                 `json:"text,omitempty"`
	Data     string                 `json:"data,omitempty"`
	MimeType string                 `json:"mimeType,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError"`
}

// ResourceContent represents resource content
type ResourceContent struct {
	Contents []Content `json:"contents"`
}

// PromptResult represents the result of a prompt
type PromptResult struct {
	Description string    `json:"description,omitempty"`
	Messages    []Message `json:"messages"`
}

// Message represents an MCP message
type Message struct {
	Role    string    `json:"role"`
	Content []Content `json:"content"`
}

// Handler function types
type ToolHandler func(ctx context.Context, arguments map[string]interface{}) (*ToolResult, error)
type ResourceHandler func(ctx context.Context, uri string) (*ResourceContent, error)
type PromptHandler func(ctx context.Context, name string, arguments map[string]interface{}) (*PromptResult, error)

// HandlerRegistry manages MCP handlers
type HandlerRegistry struct {
	tools     map[string]ToolHandler
	resources map[string]ResourceHandler
	prompts   map[string]PromptHandler
}

// NewMCPPlugin creates a new MCP plugin
func NewMCPPlugin(metadata *samurai.PluginMetadata, host samurai.HostInterface) *MCPPlugin {
	sdk := samurai.NewSDK(metadata, host)

	return &MCPPlugin{
		SDK:       sdk,
		tools:     []Tool{},
		resources: []Resource{},
		prompts:   []Prompt{},
		handlers:  NewHandlerRegistry(),
	}
}

// NewHandlerRegistry creates a new handler registry
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		tools:     make(map[string]ToolHandler),
		resources: make(map[string]ResourceHandler),
		prompts:   make(map[string]PromptHandler),
	}
}

// RegisterTool registers an MCP tool
func (mcp *MCPPlugin) RegisterTool(tool Tool) error {
	if tool.Name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}

	if tool.Handler == nil {
		return fmt.Errorf("tool handler cannot be nil")
	}

	// Check for duplicates
	for _, existingTool := range mcp.tools {
		if existingTool.Name == tool.Name {
			return fmt.Errorf("tool '%s' already registered", tool.Name)
		}
	}

	mcp.tools = append(mcp.tools, tool)
	mcp.handlers.tools[tool.Name] = tool.Handler

	mcp.GetLogger().Infow("MCP tool registered", "tool_name", tool.Name)
	return nil
}

// RegisterResource registers an MCP resource
func (mcp *MCPPlugin) RegisterResource(resource Resource) error {
	if resource.URI == "" {
		return fmt.Errorf("resource URI cannot be empty")
	}

	if resource.Handler == nil {
		return fmt.Errorf("resource handler cannot be nil")
	}

	// Check for duplicates
	for _, existingResource := range mcp.resources {
		if existingResource.URI == resource.URI {
			return fmt.Errorf("resource '%s' already registered", resource.URI)
		}
	}

	mcp.resources = append(mcp.resources, resource)
	mcp.handlers.resources[resource.URI] = resource.Handler

	mcp.GetLogger().Infow("MCP resource registered", "resource_uri", resource.URI)
	return nil
}

// RegisterPrompt registers an MCP prompt
func (mcp *MCPPlugin) RegisterPrompt(prompt Prompt) error {
	if prompt.Name == "" {
		return fmt.Errorf("prompt name cannot be empty")
	}

	if prompt.Handler == nil {
		return fmt.Errorf("prompt handler cannot be nil")
	}

	// Check for duplicates
	for _, existingPrompt := range mcp.prompts {
		if existingPrompt.Name == prompt.Name {
			return fmt.Errorf("prompt '%s' already registered", prompt.Name)
		}
	}

	mcp.prompts = append(mcp.prompts, prompt)
	mcp.handlers.prompts[prompt.Name] = prompt.Handler

	mcp.GetLogger().Infow("MCP prompt registered", "prompt_name", prompt.Name)
	return nil
}

// ListTools returns all registered tools
func (mcp *MCPPlugin) ListTools(ctx context.Context) ([]Tool, error) {
	return mcp.tools, nil
}

// CallTool executes a tool
func (mcp *MCPPlugin) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*ToolResult, error) {
	handler, exists := mcp.handlers.tools[name]
	if !exists {
		return &ToolResult{
			Content: []Content{
				{
					Type: "text",
					Text: fmt.Sprintf("Tool '%s' not found", name),
				},
			},
			IsError: true,
		}, fmt.Errorf("tool not found: %s", name)
	}

	mcp.GetLogger().Infow("Executing MCP tool", "tool_name", name, "arguments", arguments)

	start := samurai.Now()
	result, err := handler(ctx, arguments)
	duration := samurai.Since(start)

	// Record metrics
	mcp.SetMetric(ctx, fmt.Sprintf("tool_%s_calls", name), 1)
	mcp.RecordLatency(ctx, fmt.Sprintf("tool_%s_latency", name), duration)

	if err != nil {
		mcp.SetMetric(ctx, fmt.Sprintf("tool_%s_errors", name), 1)
		mcp.GetLogger().Errorw("Tool execution failed", "tool_name", name, "error", err)
	}

	return result, err
}

// ListResources returns all registered resources
func (mcp *MCPPlugin) ListResources(ctx context.Context) ([]Resource, error) {
	return mcp.resources, nil
}

// ReadResource reads a resource
func (mcp *MCPPlugin) ReadResource(ctx context.Context, uri string) (*ResourceContent, error) {
	handler, exists := mcp.handlers.resources[uri]
	if !exists {
		return &ResourceContent{
			Contents: []Content{
				{
					Type: "text",
					Text: fmt.Sprintf("Resource '%s' not found", uri),
				},
			},
		}, fmt.Errorf("resource not found: %s", uri)
	}

	mcp.GetLogger().Infow("Reading MCP resource", "resource_uri", uri)

	start := samurai.Now()
	result, err := handler(ctx, uri)
	duration := samurai.Since(start)

	// Record metrics
	mcp.SetMetric(ctx, "resource_reads", 1)
	mcp.RecordLatency(ctx, "resource_read_latency", duration)

	if err != nil {
		mcp.SetMetric(ctx, "resource_read_errors", 1)
		mcp.GetLogger().Errorw("Resource read failed", "resource_uri", uri, "error", err)
	}

	return result, err
}

// ListPrompts returns all registered prompts
func (mcp *MCPPlugin) ListPrompts(ctx context.Context) ([]Prompt, error) {
	return mcp.prompts, nil
}

// GetPrompt gets a prompt
func (mcp *MCPPlugin) GetPrompt(ctx context.Context, name string, arguments map[string]interface{}) (*PromptResult, error) {
	handler, exists := mcp.handlers.prompts[name]
	if !exists {
		return &PromptResult{
			Description: fmt.Sprintf("Prompt '%s' not found", name),
			Messages:    []Message{},
		}, fmt.Errorf("prompt not found: %s", name)
	}

	mcp.GetLogger().Infow("Getting MCP prompt", "prompt_name", name, "arguments", arguments)

	start := samurai.Now()
	result, err := handler(ctx, name, arguments)
	duration := samurai.Since(start)

	// Record metrics
	mcp.SetMetric(ctx, fmt.Sprintf("prompt_%s_calls", name), 1)
	mcp.RecordLatency(ctx, fmt.Sprintf("prompt_%s_latency", name), duration)

	if err != nil {
		mcp.SetMetric(ctx, fmt.Sprintf("prompt_%s_errors", name), 1)
		mcp.GetLogger().Errorw("Prompt execution failed", "prompt_name", name, "error", err)
	}

	return result, err
}

// HandleMCPMessage handles incoming MCP protocol messages
func (mcp *MCPPlugin) HandleMCPMessage(ctx context.Context, message *samurai.Message) (*samurai.Response, error) {
	switch message.Type {
	case "tools/list":
		return mcp.handleListTools(ctx, message)
	case "tools/call":
		return mcp.handleCallTool(ctx, message)
	case "resources/list":
		return mcp.handleListResources(ctx, message)
	case "resources/read":
		return mcp.handleReadResource(ctx, message)
	case "prompts/list":
		return mcp.handleListPrompts(ctx, message)
	case "prompts/get":
		return mcp.handleGetPrompt(ctx, message)
	default:
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     fmt.Sprintf("Unknown MCP message type: %s", message.Type),
		}, nil
	}
}

// Helper methods for handling MCP messages

func (mcp *MCPPlugin) handleListTools(ctx context.Context, message *samurai.Message) (*samurai.Response, error) {
	tools, err := mcp.ListTools(ctx)
	if err != nil {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     err.Error(),
		}, nil
	}

	return &samurai.Response{
		ID:        uuid.New(),
		RequestID: message.ID,
		Success:   true,
		Data: map[string]interface{}{
			"tools": tools,
		},
	}, nil
}

func (mcp *MCPPlugin) handleCallTool(ctx context.Context, message *samurai.Message) (*samurai.Response, error) {
	name, ok := message.Data["name"].(string)
	if !ok {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     "Missing tool name",
		}, nil
	}

	arguments, _ := message.Data["arguments"].(map[string]interface{})

	result, err := mcp.CallTool(ctx, name, arguments)
	if err != nil {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     err.Error(),
		}, nil
	}

	return &samurai.Response{
		ID:        uuid.New(),
		RequestID: message.ID,
		Success:   true,
		Data: map[string]interface{}{
			"result": result,
		},
	}, nil
}

func (mcp *MCPPlugin) handleListResources(ctx context.Context, message *samurai.Message) (*samurai.Response, error) {
	resources, err := mcp.ListResources(ctx)
	if err != nil {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     err.Error(),
		}, nil
	}

	return &samurai.Response{
		ID:        uuid.New(),
		RequestID: message.ID,
		Success:   true,
		Data: map[string]interface{}{
			"resources": resources,
		},
	}, nil
}

func (mcp *MCPPlugin) handleReadResource(ctx context.Context, message *samurai.Message) (*samurai.Response, error) {
	uri, ok := message.Data["uri"].(string)
	if !ok {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     "Missing resource URI",
		}, nil
	}

	content, err := mcp.ReadResource(ctx, uri)
	if err != nil {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     err.Error(),
		}, nil
	}

	return &samurai.Response{
		ID:        uuid.New(),
		RequestID: message.ID,
		Success:   true,
		Data: map[string]interface{}{
			"content": content,
		},
	}, nil
}

func (mcp *MCPPlugin) handleListPrompts(ctx context.Context, message *samurai.Message) (*samurai.Response, error) {
	prompts, err := mcp.ListPrompts(ctx)
	if err != nil {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     err.Error(),
		}, nil
	}

	return &samurai.Response{
		ID:        uuid.New(),
		RequestID: message.ID,
		Success:   true,
		Data: map[string]interface{}{
			"prompts": prompts,
		},
	}, nil
}

func (mcp *MCPPlugin) handleGetPrompt(ctx context.Context, message *samurai.Message) (*samurai.Response, error) {
	name, ok := message.Data["name"].(string)
	if !ok {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     "Missing prompt name",
		}, nil
	}

	arguments, _ := message.Data["arguments"].(map[string]interface{})

	result, err := mcp.GetPrompt(ctx, name, arguments)
	if err != nil {
		return &samurai.Response{
			ID:        uuid.New(),
			RequestID: message.ID,
			Success:   false,
			Error:     err.Error(),
		}, nil
	}

	return &samurai.Response{
		ID:        uuid.New(),
		RequestID: message.ID,
		Success:   true,
		Data: map[string]interface{}{
			"result": result,
		},
	}, nil
}
