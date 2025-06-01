package models

import (
	"time"

	"github.com/google/uuid"
)

type RolePermission struct {
	RoleID       uuid.UUID `json:"role_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
	CreatedAt    time.Time `json:"created_at"`

	// Relationships
	Role       Role       `json:"role" gorm:"foreignKey:RoleID"`
	Permission Permission `json:"permission" gorm:"foreignKey:PermissionID"`
}

func (RolePermission) TableName() string {
	return "role_permissions"
}
