package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Email        string         `json:"email" gorm:"uniqueIndex;not null"`
	Username     string         `json:"username" gorm:"uniqueIndex;not null"`
	PasswordHash string         `json:"-" gorm:"column:password_hash;not null"`
	FirstName    string         `json:"first_name"`
	LastName     string         `json:"last_name"`
	RoleID       *uuid.UUID     `json:"role_id" gorm:"type:uuid"` // Foreign key to roles table
	IsActive     bool           `json:"is_active" gorm:"default:true"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Role *Role `json:"role" gorm:"foreignKey:RoleID"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// TableName specifies the table name for the User model
func (User) TableName() string {
	return "users"
}

// GetFullName returns the user's full name
func (u *User) GetFullName() string {
	return u.FirstName + " " + u.LastName
}

// GetRoleName returns the user's role name
func (u *User) GetRoleName() string {
	if u.Role != nil {
		return u.Role.Name
	}
	return "user" // Default role
}

// HasRole checks if user has a specific role
func (u *User) HasRole(roleName string) bool {
	if u.Role != nil {
		return u.Role.Name == roleName
	}
	return roleName == "user" // Default role
}

// HasPermission checks if user has a specific permission
func (u *User) HasPermission(permission string) bool {
	if u.Role == nil {
		return false
	}

	for _, perm := range u.Role.Permissions {
		if perm.GetFullName() == permission || perm.Name == permission {
			return perm.IsActive
		}
	}
	return false
}

// IsAdmin checks if user has admin role
func (u *User) IsAdmin() bool {
	return u.HasRole("admin")
}

// IsSuperAdmin checks if user has super admin role
func (u *User) IsSuperAdmin() bool {
	return u.HasRole("super_admin")
}
