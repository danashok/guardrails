package repository

import (
	"gorm.io/gorm"
)

type Handler struct {
	GuardrailEvent IGuardrailEventRepository
	AuthorizedIP   IAuthorizedIPRepository
}

func NewHandler(gormDB *gorm.DB) *Handler {
	return &Handler{
		GuardrailEvent: NewGuardrailEventRepository(gormDB),
		AuthorizedIP:   NewAuthorizedIPRepository(gormDB),
	}
}
