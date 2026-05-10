package repository

import (
	"gorm.io/gorm"
)

type Handler struct {
	GuardrailEvent IGuardrailEventRepository
}

func NewHandler(gormDB *gorm.DB) *Handler {
	return &Handler{
		GuardrailEvent: NewGuardrailEventRepository(gormDB),
	}
}
