package sms

import "samurai/backend/internal/plugin/interfaces"

// NewSMSPluginFactory is the factory function that will be called by the plugin loader
// This function signature must match what the loader expects
func NewSMSPluginFactory() interfaces.Plugin {
	return NewSMSPlugin()
}
