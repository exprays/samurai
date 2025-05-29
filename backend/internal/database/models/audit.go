package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuditLog struct {
	ID        uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    *uuid.UUID `json:"user_id,omitempty" gorm:"type:uuid"`
	User      *User      `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Action    string     `json:"action" gorm:"not null"`
	Resource  string     `json:"resource" gorm:"not null"`
	Details   string     `json:"details" gorm:"type:jsonb"`
	IPAddress string     `json:"ip_address"`
	UserAgent string     `json:"user_agent"`
	CreatedAt time.Time  `json:"created_at"`
}

func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}
