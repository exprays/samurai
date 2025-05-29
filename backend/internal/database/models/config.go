package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Configuration struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Key       string         `json:"key" gorm:"uniqueIndex;not null"`
	Value     string         `json:"value" gorm:"type:jsonb"`
	UserID    *uuid.UUID     `json:"user_id,omitempty" gorm:"type:uuid"`
	User      *User          `json:"user,omitempty" gorm:"foreignKey:UserID"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

func (c *Configuration) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}
