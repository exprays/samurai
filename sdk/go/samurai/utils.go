package samurai

import (
	"time"
)

// Content represents content with type and data
type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError"`
}

// Now returns the current time (wrapper for easier testing)
func Now() time.Time {
	return time.Now()
}

// Since returns the duration since the given time (wrapper for easier testing)
func Since(t time.Time) time.Duration {
	return time.Since(t)
}

// NewTextContent creates a new text content
func NewTextContent(text string) Content {
	return Content{
		Type: "text",
		Text: text,
	}
}

// NewDataContent creates a new data content
func NewDataContent(data, mimeType string) Content {
	return Content{
		Type:     "data",
		Data:     data,
		MimeType: mimeType,
	}
}

// NewSuccessResult creates a successful tool result
func NewSuccessResult(contents ...Content) *ToolResult {
	return &ToolResult{
		Content: contents,
		IsError: false,
	}
}

// NewErrorResult creates an error tool result
func NewErrorResult(message string) *ToolResult {
	return &ToolResult{
		Content: []Content{NewTextContent(message)},
		IsError: true,
	}
}

// NewPromptMessage creates a new prompt message
func NewPromptMessage(role string, contents ...Content) Message {
	return Message{
		Role:    role,
		Content: contents,
	}
}
