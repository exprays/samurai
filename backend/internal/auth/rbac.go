package auth

import (
	"errors"

	"samurai/backend/internal/database"
	"samurai/backend/internal/database/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	ErrRoleNotFound       = errors.New("role not found")
	ErrPermissionNotFound = errors.New("permission not found")
	ErrRoleExists         = errors.New("role already exists")
	ErrPermissionExists   = errors.New("permission already exists")
	ErrCannotDeleteSystem = errors.New("cannot delete system role")
	ErrInsufficientPerms  = errors.New("insufficient permissions")
)

// RBAC represents the Role-Based Access Control service
type RBAC struct {
	db     *database.Database
	logger *zap.SugaredLogger
}

// NewRBAC creates a new RBAC service instance
func NewRBAC(db *database.Database, logger *zap.SugaredLogger) *RBAC {
	return &RBAC{
		db:     db,
		logger: logger,
	}
}

// InitializeDefaultRoles creates default system roles and permissions
func (r *RBAC) InitializeDefaultRoles() error {
	// Create default permissions
	permissions := []models.Permission{
		// User management
		{Name: "users.create", DisplayName: "Create Users", Description: "Create new user accounts", Resource: "users", Action: "create"},
		{Name: "users.read", DisplayName: "Read Users", Description: "View user accounts", Resource: "users", Action: "read"},
		{Name: "users.update", DisplayName: "Update Users", Description: "Modify user accounts", Resource: "users", Action: "update"},
		{Name: "users.delete", DisplayName: "Delete Users", Description: "Delete user accounts", Resource: "users", Action: "delete"},

		// Role management
		{Name: "roles.create", DisplayName: "Create Roles", Description: "Create new roles", Resource: "roles", Action: "create"},
		{Name: "roles.read", DisplayName: "Read Roles", Description: "View roles", Resource: "roles", Action: "read"},
		{Name: "roles.update", DisplayName: "Update Roles", Description: "Modify roles", Resource: "roles", Action: "update"},
		{Name: "roles.delete", DisplayName: "Delete Roles", Description: "Delete roles", Resource: "roles", Action: "delete"},

		// Plugin management
		{Name: "plugins.create", DisplayName: "Create Plugins", Description: "Install new plugins", Resource: "plugins", Action: "create"},
		{Name: "plugins.read", DisplayName: "Read Plugins", Description: "View plugins", Resource: "plugins", Action: "read"},
		{Name: "plugins.update", DisplayName: "Update Plugins", Description: "Modify plugins", Resource: "plugins", Action: "update"},
		{Name: "plugins.delete", DisplayName: "Delete Plugins", Description: "Remove plugins", Resource: "plugins", Action: "delete"},
		{Name: "plugins.execute", DisplayName: "Execute Plugins", Description: "Run plugin operations", Resource: "plugins", Action: "execute"},

		// Configuration management
		{Name: "config.read", DisplayName: "Read Config", Description: "View configuration", Resource: "config", Action: "read"},
		{Name: "config.update", DisplayName: "Update Config", Description: "Modify configuration", Resource: "config", Action: "update"},

		// LLM management
		{Name: "llm.read", DisplayName: "Read LLM", Description: "View LLM configurations", Resource: "llm", Action: "read"},
		{Name: "llm.update", DisplayName: "Update LLM", Description: "Modify LLM configurations", Resource: "llm", Action: "update"},
		{Name: "llm.execute", DisplayName: "Execute LLM", Description: "Use LLM services", Resource: "llm", Action: "execute"},
	}

	// Create permissions if they don't exist
	for _, perm := range permissions {
		var existingPerm models.Permission
		err := r.db.DB.Where("name = ?", perm.Name).First(&existingPerm).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			perm.ID = uuid.New()
			if err := r.db.DB.Create(&perm).Error; err != nil {
				r.logger.Errorf("Failed to create permission %s: %v", perm.Name, err)
				return err
			}
			r.logger.Infof("Created permission: %s", perm.Name)
		}
	}

	// Create default roles
	roles := []struct {
		Role        models.Role
		Permissions []string
	}{
		{
			Role: models.Role{
				Name:        "super_admin",
				DisplayName: "Super Administrator",
				Description: "Full system access with all permissions",
				IsSystem:    true,
			},
			Permissions: []string{
				"users.create", "users.read", "users.update", "users.delete",
				"roles.create", "roles.read", "roles.update", "roles.delete",
				"plugins.create", "plugins.read", "plugins.update", "plugins.delete", "plugins.execute",
				"config.read", "config.update",
				"llm.read", "llm.update", "llm.execute",
			},
		},
		{
			Role: models.Role{
				Name:        "admin",
				DisplayName: "Administrator",
				Description: "Administrative access with user and plugin management",
				IsSystem:    true,
			},
			Permissions: []string{
				"users.read", "users.update",
				"roles.read",
				"plugins.read", "plugins.update", "plugins.execute",
				"config.read",
				"llm.read", "llm.execute",
			},
		},
		{
			Role: models.Role{
				Name:        "user",
				DisplayName: "Regular User",
				Description: "Basic user access with plugin execution",
				IsSystem:    true,
			},
			Permissions: []string{
				"plugins.read", "plugins.execute",
				"llm.read", "llm.execute",
			},
		},
		{
			Role: models.Role{
				Name:        "viewer",
				DisplayName: "Viewer",
				Description: "Read-only access",
				IsSystem:    true,
			},
			Permissions: []string{
				"plugins.read",
				"llm.read",
			},
		},
	}

	for _, roleData := range roles {
		var existingRole models.Role
		err := r.db.DB.Where("name = ?", roleData.Role.Name).First(&existingRole).Error

		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create the role
			roleData.Role.ID = uuid.New()
			if err := r.db.DB.Create(&roleData.Role).Error; err != nil {
				r.logger.Errorf("Failed to create role %s: %v", roleData.Role.Name, err)
				return err
			}

			// Assign permissions to role
			if err := r.AssignPermissionsToRole(roleData.Role.ID, roleData.Permissions); err != nil {
				r.logger.Errorf("Failed to assign permissions to role %s: %v", roleData.Role.Name, err)
				return err
			}

			r.logger.Infof("Created role: %s", roleData.Role.Name)
		}
	}

	return nil
}

// AssignPermissionsToRole assigns multiple permissions to a role
func (r *RBAC) AssignPermissionsToRole(roleID uuid.UUID, permissionNames []string) error {
	for _, permName := range permissionNames {
		var permission models.Permission
		if err := r.db.DB.Where("name = ?", permName).First(&permission).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				r.logger.Warnf("Permission not found: %s", permName)
				continue
			}
			return err
		}

		// Check if association already exists
		var existingAssoc models.RolePermission
		err := r.db.DB.Where("role_id = ? AND permission_id = ?", roleID, permission.ID).First(&existingAssoc).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create the association
			assoc := models.RolePermission{
				RoleID:       roleID,
				PermissionID: permission.ID,
			}
			if err := r.db.DB.Create(&assoc).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// GetUserWithRole retrieves a user with their role and permissions
func (r *RBAC) GetUserWithRole(userID uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.DB.Preload("Role.Permissions").Where("id = ?", userID).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// AssignRoleToUser assigns a role to a user
func (r *RBAC) AssignRoleToUser(userID uuid.UUID, roleName string) error {
	// Find the role
	var role models.Role
	if err := r.db.DB.Where("name = ?", roleName).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
		return err
	}

	// Update user's role
	if err := r.db.DB.Model(&models.User{}).Where("id = ?", userID).Update("role_id", role.ID).Error; err != nil {
		return err
	}

	r.logger.Infof("Assigned role %s to user %s", roleName, userID)
	return nil
}

// CheckPermission checks if a user has a specific permission
func (r *RBAC) CheckPermission(userID uuid.UUID, permission string) (bool, error) {
	user, err := r.GetUserWithRole(userID)
	if err != nil {
		return false, err
	}

	return user.HasPermission(permission), nil
}

// GetDefaultRoleID gets the ID of the default user role
func (r *RBAC) GetDefaultRoleID() (*uuid.UUID, error) {
	var role models.Role
	if err := r.db.DB.Where("name = ?", "user").First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role.ID, nil
}

// ListRoles returns all active roles
func (r *RBAC) ListRoles() ([]models.Role, error) {
	var roles []models.Role
	err := r.db.DB.Preload("Permissions").Where("is_active = ?", true).Find(&roles).Error
	return roles, err
}

// ListPermissions returns all active permissions
func (r *RBAC) ListPermissions() ([]models.Permission, error) {
	var permissions []models.Permission
	err := r.db.DB.Where("is_active = ?", true).Find(&permissions).Error
	return permissions, err
}
