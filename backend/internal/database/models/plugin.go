// Plugin model definition

package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Plugin struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string         `json:"name" gorm:"not null"`
	Version     string         `json:"version" gorm:"not null"`
	Description string         `json:"description"`
	Author      string         `json:"author"`
	Enabled     bool           `json:"enabled" gorm:"default:false"`
	Config      string         `json:"config" gorm:"type:jsonb"`
	UserID      uuid.UUID      `json:"user_id" gorm:"type:uuid"`
	User        User           `json:"user" gorm:"foreignKey:UserID"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

func (p *Plugin) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
