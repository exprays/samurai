package template

import (
	"context"
	"fmt"

	"samurai/backend/internal/plugin/interfaces"
)

// MCPBasePlugin extends BasePlugin with MCP-specific functionality
type MCPBasePlugin struct {
	*BasePlugin
	tools     []interfaces.MCPTool
	resources []interfaces.MCPResource
	prompts   []interfaces.MCPPrompt
}

// NewMCPBasePlugin creates a new MCP base plugin
func NewMCPBasePlugin(metadata *interfaces.PluginMetadata) *MCPBasePlugin {
	return &MCPBasePlugin{
		BasePlugin: NewBasePlugin(metadata),
		tools:      []interfaces.MCPTool{},
		resources:  []interfaces.MCPResource{},
		prompts:    []interfaces.MCPPrompt{},
	}
}

// ListTools returns available MCP tools
func (mp *MCPBasePlugin) ListTools(ctx context.Context) ([]interfaces.MCPTool, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.tools, nil
}

// CallTool executes an MCP tool
func (mp *MCPBasePlugin) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*interfaces.MCPToolResult, error) {
	// Override in specific plugins for custom tool implementation
	return &interfaces.MCPToolResult{
		Content: []interfaces.MCPContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Tool '%s' not implemented", name),
			},
		},
		IsError: true,
	}, nil
}

// ListResources returns available MCP resources
func (mp *MCPBasePlugin) ListResources(ctx context.Context) ([]interfaces.MCPResource, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.resources, nil
}

// ReadResource reads an MCP resource
func (mp *MCPBasePlugin) ReadResource(ctx context.Context, uri string) (*interfaces.MCPResourceContent, error) {
	// Override in specific plugins for custom resource implementation
	return &interfaces.MCPResourceContent{
		Contents: []interfaces.MCPContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Resource '%s' not found", uri),
			},
		},
	}, fmt.Errorf("resource not found: %s", uri)
}

// ListPrompts returns available MCP prompts
func (mp *MCPBasePlugin) ListPrompts(ctx context.Context) ([]interfaces.MCPPrompt, error) {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.prompts, nil
}

// GetPrompt gets an MCP prompt
func (mp *MCPBasePlugin) GetPrompt(ctx context.Context, name string, arguments map[string]interface{}) (*interfaces.MCPPromptResult, error) {
	// Override in specific plugins for custom prompt implementation
	return &interfaces.MCPPromptResult{
		Description: fmt.Sprintf("Prompt '%s' not implemented", name),
		Messages:    []interfaces.MCPMessage{},
	}, fmt.Errorf("prompt not found: %s", name)
}

// AddTool adds an MCP tool
func (mp *MCPBasePlugin) AddTool(tool interfaces.MCPTool) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.tools = append(mp.tools, tool)
}

// AddResource adds an MCP resource
func (mp *MCPBasePlugin) AddResource(resource interfaces.MCPResource) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.resources = append(mp.resources, resource)
}

// AddPrompt adds an MCP prompt
func (mp *MCPBasePlugin) AddPrompt(prompt interfaces.MCPPrompt) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.prompts = append(mp.prompts, prompt)
}
