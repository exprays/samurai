package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID             uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Username       string     `gorm:"uniqueIndex;not null;size:50" json:"username" validate:"required,min=3,max=50,alphanum"`
	Email          string     `gorm:"uniqueIndex;not null;size:255" json:"email" validate:"required,email"`
	PasswordHash   string     `gorm:"not null;size:255" json:"-"`
	FirstName      string     `gorm:"not null;size:100" json:"first_name" validate:"required,min=2,max=100"`
	LastName       string     `gorm:"not null;size:100" json:"last_name" validate:"required,min=2,max=100"`
	IsActive       bool       `gorm:"default:true" json:"is_active"`
	EmailVerified  bool       `gorm:"default:false" json:"email_verified"`
	LastLogin      *time.Time `json:"last_login"`
	FailedAttempts int        `gorm:"default:0" json:"-"`
	LockedUntil    *time.Time `json:"-"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`

	// RBAC Relations
	Roles []Role `gorm:"many2many:user_roles;" json:"roles,omitempty"`

	// Audit Relations
	AuditLogs []AuditLog `gorm:"foreignKey:UserID" json:"-"`
}

type Role struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string    `gorm:"uniqueIndex;not null;size:50" json:"name" validate:"required,min=2,max=50"`
	Description string    `gorm:"size:255" json:"description"`
	IsSystem    bool      `gorm:"default:false" json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relations
	Users       []User       `gorm:"many2many:user_roles;" json:"users,omitempty"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
}

type Permission struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string    `gorm:"uniqueIndex;not null;size:100" json:"name" validate:"required"`
	Resource    string    `gorm:"not null;size:50" json:"resource" validate:"required"`
	Action      string    `gorm:"not null;size:50" json:"action" validate:"required"`
	Description string    `gorm:"size:255" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relations
	Roles []Role `gorm:"many2many:role_permissions;" json:"roles,omitempty"`
}

// User methods
func (u *User) BeforeCreate(tx *gorm.DB) error {
	u.ID = uuid.New()
	return nil
}

func (u *User) SetPassword(password string, cost int) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	return nil
}

func (u *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
}

func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}

func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

func (u *User) HasRole(roleName string) bool {
	for _, role := range u.Roles {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

func (u *User) HasPermission(resource, action string) bool {
	for _, role := range u.Roles {
		for _, permission := range role.Permissions {
			if permission.Resource == resource && permission.Action == action {
				return true
			}
		}
	}
	return false
}

func (u *User) GetPermissions() []Permission {
	var permissions []Permission
	permissionMap := make(map[uuid.UUID]bool)

	for _, role := range u.Roles {
		for _, permission := range role.Permissions {
			if !permissionMap[permission.ID] {
				permissions = append(permissions, permission)
				permissionMap[permission.ID] = true
			}
		}
	}

	return permissions
}

// Role methods
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	r.ID = uuid.New()
	return nil
}

// Permission methods
func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	p.ID = uuid.New()
	return nil
}

// System roles and permissions
var SystemRoles = map[string]string{
	"admin":     "System Administrator",
	"user":      "Regular User",
	"developer": "Plugin Developer",
	"viewer":    "Read-only User",
}

var SystemPermissions = []Permission{
	{Name: "users.create", Resource: "users", Action: "create", Description: "Create new users"},
	{Name: "users.read", Resource: "users", Action: "read", Description: "View user information"},
	{Name: "users.update", Resource: "users", Action: "update", Description: "Update user information"},
	{Name: "users.delete", Resource: "users", Action: "delete", Description: "Delete users"},

	{Name: "plugins.create", Resource: "plugins", Action: "create", Description: "Create/install plugins"},
	{Name: "plugins.read", Resource: "plugins", Action: "read", Description: "View plugins"},
	{Name: "plugins.update", Resource: "plugins", Action: "update", Description: "Update plugins"},
	{Name: "plugins.delete", Resource: "plugins", Action: "delete", Description: "Delete plugins"},
	{Name: "plugins.execute", Resource: "plugins", Action: "execute", Description: "Execute plugins"},

	{Name: "config.read", Resource: "config", Action: "read", Description: "View configuration"},
	{Name: "config.update", Resource: "config", Action: "update", Description: "Update configuration"},

	{Name: "analytics.read", Resource: "analytics", Action: "read", Description: "View analytics"},
	{Name: "logs.read", Resource: "logs", Action: "read", Description: "View logs"},
	{Name: "system.monitor", Resource: "system", Action: "monitor", Description: "Monitor system health"},
}
