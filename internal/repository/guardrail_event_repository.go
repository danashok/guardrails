package repository

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/ashokdan/guardrails/internal/models"
)

type IGuardrailEventRepository interface {
	Create(ctx context.Context, logger *zap.Logger, event *models.GuardrailEvent) error
}

type guardrailEventRepository struct {
	db *gorm.DB
}

func NewGuardrailEventRepository(gormDB *gorm.DB) IGuardrailEventRepository {
	return &guardrailEventRepository{db: gormDB}
}

func (r *guardrailEventRepository) Create(ctx context.Context, logger *zap.Logger, event *models.GuardrailEvent) error {
	if err := r.db.WithContext(ctx).Create(event).Error; err != nil {
		return fmt.Errorf("failed to insert guardrail_event: %w", err)
	}
	return nil
}
