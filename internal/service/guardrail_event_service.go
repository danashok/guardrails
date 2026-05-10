package service

import (
	"context"
	"sync"

	"go.uber.org/zap"

	"github.com/ashokdan/guardrails/internal/models"
	"github.com/ashokdan/guardrails/internal/repository"
)

type IGuardrailEventService interface {
	Submit(event *models.GuardrailEvent)
	Shutdown()
}

type guardrailEventService struct {
	repo    repository.IGuardrailEventRepository
	logger  *zap.Logger
	enabled bool
	ch      chan *models.GuardrailEvent
	wg      sync.WaitGroup
}

func NewGuardrailEventService(
	repo repository.IGuardrailEventRepository,
	logger *zap.Logger,
	enabled bool,
	workers int,
	buffer int,
) IGuardrailEventService {
	svc := &guardrailEventService{
		repo:    repo,
		logger:  logger,
		enabled: enabled,
		ch:      make(chan *models.GuardrailEvent, buffer),
	}
	if !enabled {
		return svc
	}
	for i := 0; i < workers; i++ {
		svc.wg.Add(1)
		go svc.worker()
	}
	return svc
}

func (s *guardrailEventService) Submit(event *models.GuardrailEvent) {
	if !s.enabled {
		return
	}
	select {
	case s.ch <- event:
	default:
		s.logger.Warn("audit channel full, dropping event",
			zap.String("policy", event.Policy),
			zap.String("litellm_call_id", event.LiteLLMCallID),
		)
	}
}

func (s *guardrailEventService) Shutdown() {
	if !s.enabled {
		return
	}
	close(s.ch)
	s.wg.Wait()
}

func (s *guardrailEventService) worker() {
	defer s.wg.Done()
	for event := range s.ch {
		ctx := context.Background()
		if err := s.repo.Create(ctx, s.logger, event); err != nil {
			s.logger.Error("failed to persist guardrail event",
				zap.Error(err),
				zap.String("policy", event.Policy),
				zap.String("litellm_call_id", event.LiteLLMCallID),
			)
		}
	}
}
