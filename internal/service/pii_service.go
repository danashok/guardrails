package service

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/ashokdan/guardrails/internal/engine"
	"github.com/ashokdan/guardrails/internal/models"
)

type Decision struct {
	Action        models.GuardrailAction
	BlockedReason string
	Texts         []string
}

type IPIIService interface {
	Evaluate(ctx context.Context, logger *zap.Logger, texts []string) (*Decision, error)
}

type piiService struct {
	maxConcurrent int
}

func NewPIIService(maxConcurrent int) IPIIService {
	if maxConcurrent <= 0 {
		maxConcurrent = 32
	}
	return &piiService{maxConcurrent: maxConcurrent}
}

func (s *piiService) Evaluate(ctx context.Context, logger *zap.Logger, texts []string) (*Decision, error) {
	if len(texts) == 0 {
		return &Decision{Action: models.ActionNone}, nil
	}

	// Parallel redaction. Independent, no early-exit. PII is always redacted,
	// never blocked — SSN, credit cards, names, emails, etc. are rewritten
	// in-place via engine.Redact.
	out := make([]string, len(texts))
	g, gctx := errgroup.WithContext(ctx)
	sem := semaphore.NewWeighted(int64(s.maxConcurrent))
	changed := false
	var changedMu sync.Mutex

	for i := range texts {
		idx := i
		text := texts[i]
		if err := sem.Acquire(gctx, 1); err != nil {
			break
		}
		g.Go(func() error {
			defer sem.Release(1)
			redacted := engine.Redact(text)
			out[idx] = redacted
			if redacted != text {
				changedMu.Lock()
				changed = true
				changedMu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("pii redaction failed: %w", err)
	}

	if !changed {
		return &Decision{Action: models.ActionNone}, nil
	}
	return &Decision{
		Action: models.ActionIntervened,
		Texts:  out,
	}, nil
}
