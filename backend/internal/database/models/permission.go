package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Permission struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string         `json:"name" gorm:"uniqueIndex;not null"`
	DisplayName string         `json:"display_name" gorm:"not null"`
	Description string         `json:"description"`
	Resource    string         `json:"resource" gorm:"not null"` // e.g., "users", "plugins", "config"
	Action      string         `json:"action" gorm:"not null"`   // e.g., "create", "read", "update", "delete"
	IsActive    bool           `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Roles []Role `json:"roles" gorm:"many2many:role_permissions;"`
}

func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

func (Permission) TableName() string {
	return "permissions"
}

// GetFullName returns the full permission name (resource.action)
func (p *Permission) GetFullName() string {
	return p.Resource + "." + p.Action
}
