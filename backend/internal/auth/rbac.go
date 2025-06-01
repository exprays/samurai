package auth

import (
	"errors"
	"fmt"
	"strings"

	"samurai/backend/internal/database/models"
)

type RBACManager struct {
	// In-memory cache for permissions (can be enhanced with Redis later)
	permissionCache map[string]map[string]bool // userID -> permission -> bool
}

func NewRBACManager() *RBACManager {
	return &RBACManager{
		permissionCache: make(map[string]map[string]bool),
	}
}

func (r *RBACManager) CheckPermission(user *models.User, resource, action string) bool {
	if user == nil {
		return false
	}

	// Admin role has all permissions
	if user.HasRole("admin") {
		return true
	}

	// Check specific permission
	return user.HasPermission(resource, action)
}

func (r *RBACManager) CheckAnyPermission(user *models.User, permissions []string) bool {
	if user == nil {
		return false
	}

	// Admin role has all permissions
	if user.HasRole("admin") {
		return true
	}

	for _, perm := range permissions {
		parts := strings.Split(perm, ".")
		if len(parts) != 2 {
			continue
		}
		if user.HasPermission(parts[0], parts[1]) {
			return true
		}
	}

	return false
}

func (r *RBACManager) GetUserPermissions(user *models.User) []string {
	if user == nil {
		return []string{}
	}

	var permissions []string
	for _, permission := range user.GetPermissions() {
		permissions = append(permissions, permission.Name)
	}

	return permissions
}

func (r *RBACManager) GetUserRoles(user *models.User) []string {
	if user == nil {
		return []string{}
	}

	var roles []string
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	return roles
}

func (r *RBACManager) ValidateRoleAssignment(requester *models.User, targetUserID string, roleNames []string) error {
	// Only admins can assign roles
	if !requester.HasRole("admin") {
		return errors.New("insufficient permissions to assign roles")
	}

	// Validate role names
	for _, roleName := range roleNames {
		if !r.isValidRole(roleName) {
			return fmt.Errorf("invalid role: %s", roleName)
		}
	}

	return nil
}

func (r *RBACManager) isValidRole(roleName string) bool {
	validRoles := []string{"admin", "user", "developer", "viewer"}
	for _, validRole := range validRoles {
		if validRole == roleName {
			return true
		}
	}
	return false
}

// Permission constants for easy reference
const (
	// User permissions
	PermissionUsersCreate = "users.create"
	PermissionUsersRead   = "users.read"
	PermissionUsersUpdate = "users.update"
	PermissionUsersDelete = "users.delete"

	// Plugin permissions
	PermissionPluginsCreate  = "plugins.create"
	PermissionPluginsRead    = "plugins.read"
	PermissionPluginsUpdate  = "plugins.update"
	PermissionPluginsDelete  = "plugins.delete"
	PermissionPluginsExecute = "plugins.execute"

	// Configuration permissions
	PermissionConfigRead   = "config.read"
	PermissionConfigUpdate = "config.update"

	// Analytics permissions
	PermissionAnalyticsRead = "analytics.read"

	// System permissions
	PermissionLogsRead      = "logs.read"
	PermissionSystemMonitor = "system.monitor"
)

// Role-based permission sets
var RolePermissions = map[string][]string{
	"admin": {
		PermissionUsersCreate, PermissionUsersRead, PermissionUsersUpdate, PermissionUsersDelete,
		PermissionPluginsCreate, PermissionPluginsRead, PermissionPluginsUpdate, PermissionPluginsDelete, PermissionPluginsExecute,
		PermissionConfigRead, PermissionConfigUpdate,
		PermissionAnalyticsRead, PermissionLogsRead, PermissionSystemMonitor,
	},
	"developer": {
		PermissionPluginsCreate, PermissionPluginsRead, PermissionPluginsUpdate, PermissionPluginsExecute,
		PermissionConfigRead, PermissionAnalyticsRead,
	},
	"user": {
		PermissionPluginsRead, PermissionPluginsExecute,
		PermissionConfigRead,
	},
	"viewer": {
		PermissionPluginsRead, PermissionConfigRead, PermissionAnalyticsRead,
	},
}
