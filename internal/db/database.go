package db

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/ashokdan/guardrails/internal/config"
	"github.com/ashokdan/guardrails/internal/models"
)

func InitDB(cfg config.DBConfig) (*gorm.DB, error) {
	gormDB, err := gorm.Open(postgres.Open(cfg.DBSource), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}
	return gormDB, nil
}

func AutoMigrate(gormDB *gorm.DB) error {
	if err := gormDB.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
		return fmt.Errorf("failed to create uuid-ossp extension: %w", err)
	}
	if err := gormDB.AutoMigrate(
		&models.GuardrailEvent{},
		&models.AuthorizedIP{},
	); err != nil {
		return fmt.Errorf("failed to auto-migrate models: %w", err)
	}
	return nil
}
