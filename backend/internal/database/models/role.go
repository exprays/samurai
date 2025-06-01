package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Role struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string         `json:"name" gorm:"uniqueIndex;not null"`
	DisplayName string         `json:"display_name" gorm:"not null"`
	Description string         `json:"description"`
	IsActive    bool           `json:"is_active" gorm:"default:true"`
	IsSystem    bool           `json:"is_system" gorm:"default:false"` // System roles cannot be deleted
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Permissions []Permission `json:"permissions" gorm:"many2many:role_permissions;"`
	Users       []User       `json:"users" gorm:"foreignKey:RoleID"`
}

func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

func (Role) TableName() string {
	return "roles"
}
