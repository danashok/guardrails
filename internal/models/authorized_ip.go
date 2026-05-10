package models

import (
	"time"

	"github.com/google/uuid"
)

type AuthorizedIP struct {
	ID          uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	NTAccount   string    `gorm:"uniqueIndex:idx_authorized_ips_ntaccount_ip;not null;column:ntaccount" json:"ntaccount"`
	AllowedIP   string    `gorm:"type:inet;uniqueIndex:idx_authorized_ips_ntaccount_ip;not null;column:allowed_ip" json:"allowed_ip"`
	Enabled     bool      `gorm:"not null;default:true" json:"enabled"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (AuthorizedIP) TableName() string {
	return "authorized_ips"
}
