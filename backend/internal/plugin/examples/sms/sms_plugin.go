package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"samurai/backend/internal/plugin/interfaces"
	"samurai/backend/internal/plugin/template"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SMSPlugin implements SMS functionality using Twilio API
type SMSPlugin struct {
	*template.MCPBasePlugin
	twilioClient *TwilioClient
	config       *SMSConfig
	logger       *zap.SugaredLogger
}

// SMSConfig holds SMS plugin configuration
type SMSConfig struct {
	AccountSID    string `json:"account_sid"`
	AuthToken     string `json:"auth_token"`
	FromNumber    string `json:"from_number"`
	MaxRetries    int    `json:"max_retries"`
	RetryDelay    int    `json:"retry_delay_seconds"`
	RateLimit     int    `json:"rate_limit_per_minute"`
	EnableLogging bool   `json:"enable_logging"`
}

// TwilioClient represents a Twilio API client (mock for this example)
type TwilioClient struct {
	accountSID string
	authToken  string
	logger     *zap.SugaredLogger
}

// NewSMSPlugin creates a new SMS plugin instance
func NewSMSPlugin() interfaces.Plugin {
	metadata := &interfaces.PluginMetadata{
		ID:           uuid.New(),
		Name:         "sms-twilio",
		Version:      "1.0.0",
		Description:  "SMS sending plugin using Twilio API",
		Author:       "Samurai Team",
		Type:         interfaces.PluginTypeMCP,
		Tags:         []string{"sms", "communication", "twilio", "messaging"},
		Dependencies: []string{},
		Capabilities: []interfaces.PluginCapability{
			{
				Name:        "send_sms",
				Description: "Send SMS messages via Twilio",
				Type:        "tool",
				Schema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"to": map[string]interface{}{
							"type":        "string",
							"description": "Recipient phone number in E.164 format",
							"pattern":     "^\\+[1-9]\\d{1,14}$",
						},
						"message": map[string]interface{}{
							"type":        "string",
							"description": "Message content to send",
							"minLength":   1,
							"maxLength":   1600,
						},
						"media_url": map[string]interface{}{
							"type":        "string",
							"description": "Optional media URL for MMS",
							"format":      "uri",
						},
					},
					"required": []string{"to", "message"},
				},
			},
			{
				Name:        "get_delivery_status",
				Description: "Get delivery status of sent messages",
				Type:        "tool",
				Schema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"message_sid": map[string]interface{}{
							"type":        "string",
							"description": "Twilio message SID",
						},
					},
					"required": []string{"message_sid"},
				},
			},
		},
		ConfigSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"account_sid": map[string]interface{}{
					"type":        "string",
					"description": "Twilio Account SID",
					"minLength":   34,
					"maxLength":   34,
				},
				"auth_token": map[string]interface{}{
					"type":        "string",
					"description": "Twilio Auth Token",
					"minLength":   32,
				},
				"from_number": map[string]interface{}{
					"type":        "string",
					"description": "Twilio phone number in E.164 format",
					"pattern":     "^\\+[1-9]\\d{1,14}$",
				},
				"max_retries": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum retry attempts for failed sends",
					"minimum":     0,
					"maximum":     5,
					"default":     3,
				},
				"retry_delay_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Delay between retries in seconds",
					"minimum":     1,
					"maximum":     300,
					"default":     30,
				},
				"rate_limit_per_minute": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum messages per minute",
					"minimum":     1,
					"maximum":     1000,
					"default":     60,
				},
				"enable_logging": map[string]interface{}{
					"type":        "boolean",
					"description": "Enable detailed logging",
					"default":     true,
				},
			},
			"required": []string{"account_sid", "auth_token", "from_number"},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	plugin := &SMSPlugin{
		MCPBasePlugin: template.NewMCPBasePlugin(metadata),
	}

	// Add MCP tools
	plugin.setupMCPTools()

	return plugin
}

// setupMCPTools sets up MCP tools for the SMS plugin
func (sp *SMSPlugin) setupMCPTools() {
	// Add send SMS tool
	sp.AddTool(interfaces.MCPTool{
		Name:        "send_sms",
		Description: "Send SMS message via Twilio",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"to": map[string]interface{}{
					"type":        "string",
					"description": "Recipient phone number",
				},
				"message": map[string]interface{}{
					"type":        "string",
					"description": "Message content",
				},
				"media_url": map[string]interface{}{
					"type":        "string",
					"description": "Optional media URL",
				},
			},
			"required": []string{"to", "message"},
		},
	})

	// Add delivery status tool
	sp.AddTool(interfaces.MCPTool{
		Name:        "get_delivery_status",
		Description: "Get message delivery status",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"message_sid": map[string]interface{}{
					"type":        "string",
					"description": "Twilio message SID",
				},
			},
			"required": []string{"message_sid"},
		},
	})
}

// Initialize initializes the SMS plugin
func (sp *SMSPlugin) Initialize(ctx context.Context, logger *zap.SugaredLogger) error {
	if err := sp.MCPBasePlugin.Initialize(ctx, logger); err != nil {
		return err
	}

	sp.logger.Info("SMS plugin initialized")
	return nil
}

// Start starts the SMS plugin
func (sp *SMSPlugin) Start(ctx context.Context) error {
	if err := sp.MCPBasePlugin.Start(ctx); err != nil {
		return err
	}

	// Initialize Twilio client if config is available
	if sp.config != nil {
		sp.twilioClient = NewTwilioClient(sp.config.AccountSID, sp.config.AuthToken, sp.logger)
	}

	sp.logger.Info("SMS plugin started")
	return nil
}

// UpdateConfig updates the plugin configuration
func (sp *SMSPlugin) UpdateConfig(config *interfaces.PluginConfig) error {
	if err := sp.MCPBasePlugin.UpdateConfig(config); err != nil {
		return err
	}

	// Parse SMS-specific configuration
	smsConfig, err := sp.parseSMSConfig(config.Settings)
	if err != nil {
		return fmt.Errorf("failed to parse SMS configuration: %w", err)
	}

	sp.config = smsConfig

	// Update Twilio client if plugin is running
	if sp.GetStatus() == interfaces.PluginStatusRunning {
		sp.twilioClient = NewTwilioClient(sp.config.AccountSID, sp.config.AuthToken, sp.logger)
	}

	sp.logger.Info("SMS plugin configuration updated")
	return nil
}

// CallTool executes SMS tools
func (sp *SMSPlugin) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*interfaces.MCPToolResult, error) {
	if sp.config == nil {
		return &interfaces.MCPToolResult{
			Content: []interfaces.MCPContent{
				{Type: "text", Text: "Plugin not configured"},
			},
			IsError: true,
		}, fmt.Errorf("plugin not configured")
	}

	switch name {
	case "send_sms":
		return sp.handleSendSMS(ctx, arguments)
	case "get_delivery_status":
		return sp.handleGetDeliveryStatus(ctx, arguments)
	default:
		return &interfaces.MCPToolResult{
			Content: []interfaces.MCPContent{
				{Type: "text", Text: fmt.Sprintf("Unknown tool: %s", name)},
			},
			IsError: true,
		}, fmt.Errorf("unknown tool: %s", name)
	}
}

// handleSendSMS handles SMS sending
func (sp *SMSPlugin) handleSendSMS(ctx context.Context, arguments map[string]interface{}) (*interfaces.MCPToolResult, error) {
	// Extract arguments
	to, ok := arguments["to"].(string)
	if !ok || to == "" {
		return sp.createErrorResult("Missing or invalid 'to' parameter")
	}

	message, ok := arguments["message"].(string)
	if !ok || message == "" {
		return sp.createErrorResult("Missing or invalid 'message' parameter")
	}

	mediaURL, _ := arguments["media_url"].(string)

	// Send SMS
	result, err := sp.twilioClient.SendSMS(ctx, to, message, mediaURL)
	if err != nil {
		sp.logger.Errorw("Failed to send SMS",
			"to", to,
			"error", err,
		)
		return sp.createErrorResult(fmt.Sprintf("Failed to send SMS: %v", err))
	}

	// Update metrics
	sp.SetMetric("sms_sent_count", sp.getMetricInt("sms_sent_count")+1)
	sp.SetMetric("last_sms_sent", time.Now())

	return &interfaces.MCPToolResult{
		Content: []interfaces.MCPContent{
			{
				Type: "text",
				Text: fmt.Sprintf("SMS sent successfully. Message SID: %s", result.SID),
			},
		},
		IsError: false,
	}, nil
}

// handleGetDeliveryStatus handles delivery status checks
func (sp *SMSPlugin) handleGetDeliveryStatus(ctx context.Context, arguments map[string]interface{}) (*interfaces.MCPToolResult, error) {
	messageSID, ok := arguments["message_sid"].(string)
	if !ok || messageSID == "" {
		return sp.createErrorResult("Missing or invalid 'message_sid' parameter")
	}

	status, err := sp.twilioClient.GetMessageStatus(ctx, messageSID)
	if err != nil {
		return sp.createErrorResult(fmt.Sprintf("Failed to get message status: %v", err))
	}

	return &interfaces.MCPToolResult{
		Content: []interfaces.MCPContent{
			{
				Type: "text",
				Text: fmt.Sprintf("Message status: %s", status),
			},
		},
		IsError: false,
	}, nil
}

// Helper methods

func (sp *SMSPlugin) parseSMSConfig(settings map[string]interface{}) (*SMSConfig, error) {
	configBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}

	var config SMSConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, err
	}

	// Set defaults
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 30
	}
	if config.RateLimit == 0 {
		config.RateLimit = 60
	}

	return &config, nil
}

func (sp *SMSPlugin) createErrorResult(message string) (*interfaces.MCPToolResult, error) {
	return &interfaces.MCPToolResult{
		Content: []interfaces.MCPContent{
			{Type: "text", Text: message},
		},
		IsError: true,
	}, fmt.Errorf(message)
}

func (sp *SMSPlugin) getMetricInt(name string) int {
	if val := sp.GetMetric(name); val != nil {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}

// NewTwilioClient creates a new Twilio client (mock implementation)
func NewTwilioClient(accountSID, authToken string, logger *zap.SugaredLogger) *TwilioClient {
	return &TwilioClient{
		accountSID: accountSID,
		authToken:  authToken,
		logger:     logger,
	}
}

// SMSResult represents the result of sending an SMS
type SMSResult struct {
	SID    string `json:"sid"`
	Status string `json:"status"`
}

// SendSMS sends an SMS message (mock implementation)
func (tc *TwilioClient) SendSMS(ctx context.Context, to, message, mediaURL string) (*SMSResult, error) {
	// Mock implementation - in real plugin, this would call Twilio API
	tc.logger.Infow("Sending SMS",
		"to", to,
		"message", message,
		"media_url", mediaURL,
	)

	// Simulate API call delay
	time.Sleep(100 * time.Millisecond)

	// Return mock result
	return &SMSResult{
		SID:    fmt.Sprintf("SM%s", uuid.New().String()[:32]),
		Status: "queued",
	}, nil
}

// GetMessageStatus gets message delivery status (mock implementation)
func (tc *TwilioClient) GetMessageStatus(ctx context.Context, messageSID string) (string, error) {
	// Mock implementation
	tc.logger.Infow("Getting message status", "message_sid", messageSID)

	// Simulate API call
	time.Sleep(50 * time.Millisecond)

	// Return mock status
	return "delivered", nil
}
