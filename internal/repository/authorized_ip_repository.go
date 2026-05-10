package repository

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/ashokdan/guardrails/internal/models"
)

type IAuthorizedIPRepository interface {
	ListByNTAccount(ctx context.Context, ntaccount string) ([]string, error)
}

type authorizedIPRepository struct {
	db *gorm.DB
}

func NewAuthorizedIPRepository(gormDB *gorm.DB) IAuthorizedIPRepository {
	return &authorizedIPRepository{db: gormDB}
}

func (r *authorizedIPRepository) ListByNTAccount(ctx context.Context, ntaccount string) ([]string, error) {
	var ips []string
	if err := r.db.WithContext(ctx).
		Model(&models.AuthorizedIP{}).
		Where("ntaccount = ? AND enabled = ?", ntaccount, true).
		Pluck("allowed_ip", &ips).Error; err != nil {
		return nil, fmt.Errorf("failed to list authorized_ips for ntaccount: %w", err)
	}
	return ips, nil
}
