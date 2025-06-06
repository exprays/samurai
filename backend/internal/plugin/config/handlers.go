package config

import (
	"encoding/json"
	"net/http"

	"samurai/backend/internal/plugin/interfaces"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ConfigHandlers handles HTTP requests for plugin configuration
type ConfigHandlers struct {
	configManager *ConfigManager
	logger        *zap.SugaredLogger
}

// NewConfigHandlers creates new configuration handlers
func NewConfigHandlers(configManager *ConfigManager, logger *zap.SugaredLogger) *ConfigHandlers {
	return &ConfigHandlers{
		configManager: configManager,
		logger:        logger.Named("config-handlers"),
	}
}

// GetPluginConfig handles GET /api/v1/plugins/{id}/config
func (ch *ConfigHandlers) GetPluginConfig(c *gin.Context) {
	pluginIDStr := c.Param("id")
	pluginID, err := uuid.Parse(pluginIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	config, err := ch.configManager.GetPluginConfig(pluginID)
	if err != nil {
		ch.logger.Errorw("Failed to get plugin config",
			"plugin_id", pluginID,
			"error", err,
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "Plugin configuration not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"config": config})
}

// UpdatePluginConfig handles PUT /api/v1/plugins/{id}/config
func (ch *ConfigHandlers) UpdatePluginConfig(c *gin.Context) {
	pluginIDStr := c.Param("id")
	pluginID, err := uuid.Parse(pluginIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	if err := ch.configManager.UpdatePluginConfig(c.Request.Context(), pluginID, updates); err != nil {
		ch.logger.Errorw("Failed to update plugin config",
			"plugin_id", pluginID,
			"error", err,
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration updated successfully"})
}

// SavePluginConfig handles POST /api/v1/plugins/{id}/config
func (ch *ConfigHandlers) SavePluginConfig(c *gin.Context) {
	pluginIDStr := c.Param("id")
	pluginID, err := uuid.Parse(pluginIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	var request struct {
		Config     *interfaces.PluginConfig `json:"config"`
		PluginName string                   `json:"plugin_name"`
		Schema     map[string]interface{}   `json:"schema,omitempty"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	if request.Config == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Configuration is required"})
		return
	}

	if request.PluginName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Plugin name is required"})
		return
	}

	if err := ch.configManager.SavePluginConfig(c.Request.Context(), pluginID, request.PluginName, request.Config, request.Schema); err != nil {
		ch.logger.Errorw("Failed to save plugin config",
			"plugin_id", pluginID,
			"plugin_name", request.PluginName,
			"error", err,
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration saved successfully"})
}

// DeletePluginConfig handles DELETE /api/v1/plugins/{id}/config
func (ch *ConfigHandlers) DeletePluginConfig(c *gin.Context) {
	pluginIDStr := c.Param("id")
	pluginID, err := uuid.Parse(pluginIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	if err := ch.configManager.DeletePluginConfig(c.Request.Context(), pluginID); err != nil {
		ch.logger.Errorw("Failed to delete plugin config",
			"plugin_id", pluginID,
			"error", err,
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "Plugin configuration not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration deleted successfully"})
}

// ListPluginConfigs handles GET /api/v1/plugins/configs
func (ch *ConfigHandlers) ListPluginConfigs(c *gin.Context) {
	configs := ch.configManager.ListPluginConfigs()

	// Convert to response format
	response := make([]gin.H, 0, len(configs))
	for pluginID, entry := range configs {
		response = append(response, gin.H{
			"plugin_id":     pluginID,
			"plugin_name":   entry.PluginName,
			"version":       entry.Version,
			"config":        entry.Config,
			"last_modified": entry.LastModified,
			"is_active":     entry.IsActive,
		})
	}

	c.JSON(http.StatusOK, gin.H{"configs": response})
}

// ValidatePluginConfig handles POST /api/v1/plugins/{id}/config/validate
func (ch *ConfigHandlers) ValidatePluginConfig(c *gin.Context) {
	pluginIDStr := c.Param("id")
	pluginID, err := uuid.Parse(pluginIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	var config interfaces.PluginConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	if err := ch.configManager.ValidatePluginConfig(pluginID, &config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"message": "Configuration is valid",
	})
}

// ExportPluginConfig handles GET /api/v1/plugins/{id}/config/export
func (ch *ConfigHandlers) ExportPluginConfig(c *gin.Context) {
	pluginIDStr := c.Param("id")
	pluginID, err := uuid.Parse(pluginIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	config, err := ch.configManager.GetPluginConfig(pluginID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Plugin configuration not found"})
		return
	}

	// Set headers for file download
	filename := c.Query("filename")
	if filename == "" {
		filename = "plugin-config.json"
	}

	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "application/json")

	// Write config as JSON
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	c.Data(http.StatusOK, "application/json", configJSON)
}

// ImportPluginConfig handles POST /api/v1/plugins/{id}/config/import
func (ch *ConfigHandlers) ImportPluginConfig(c *gin.Context) {
	pluginIDStr := c.Param("id")
	pluginID, err := uuid.Parse(pluginIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plugin ID"})
		return
	}

	pluginName := c.PostForm("plugin_name")
	if pluginName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Plugin name is required"})
		return
	}

	// Handle file upload
	file, err := c.FormFile("config_file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Configuration file is required"})
		return
	}

	// Save uploaded file temporarily
	tempPath := "/tmp/" + file.Filename
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save uploaded file"})
		return
	}

	// Import configuration
	if err := ch.configManager.ImportPluginConfig(c.Request.Context(), pluginID, pluginName, tempPath, nil); err != nil {
		ch.logger.Errorw("Failed to import plugin config",
			"plugin_id", pluginID,
			"plugin_name", pluginName,
			"error", err,
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration imported successfully"})
}

// GetConfigTemplates handles GET /api/v1/plugins/config/templates
func (ch *ConfigHandlers) GetConfigTemplates(c *gin.Context) {
	templates := ch.configManager.GetConfigTemplates()
	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

// GetConfigTemplate handles GET /api/v1/plugins/config/templates/{type}
func (ch *ConfigHandlers) GetConfigTemplate(c *gin.Context) {
	templateType := c.Param("type")
	templates := ch.configManager.GetConfigTemplates()

	if template, exists := templates[templateType]; exists {
		c.JSON(http.StatusOK, gin.H{"template": template})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
	}
}
