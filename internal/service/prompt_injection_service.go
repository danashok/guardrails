package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/ashokdan/guardrails/internal/engine"
	"github.com/ashokdan/guardrails/internal/models"
)

// errBlockedSentinel signals an errgroup goroutine that a block decision
// has been made, so siblings can short-circuit. Not a real error.
var errBlockedSentinel = errors.New("blocked")

type IPromptInjectionService interface {
	Evaluate(ctx context.Context, logger *zap.Logger, texts []string) (*Decision, error)
}

type promptInjectionService struct {
	maxConcurrent int
}

func NewPromptInjectionService(maxConcurrent int) IPromptInjectionService {
	if maxConcurrent <= 0 {
		maxConcurrent = 32
	}
	return &promptInjectionService{maxConcurrent: maxConcurrent}
}

func (s *promptInjectionService) Evaluate(ctx context.Context, logger *zap.Logger, texts []string) (*Decision, error) {
	if len(texts) == 0 {
		return &Decision{Action: models.ActionNone}, nil
	}

	var (
		blockKind engine.BlockKind
		blockMu   sync.Mutex
	)

	sem := semaphore.NewWeighted(int64(s.maxConcurrent))
	g, gctx := errgroup.WithContext(ctx)

	for i := range texts {
		text := texts[i]
		if err := sem.Acquire(gctx, 1); err != nil {
			break
		}
		g.Go(func() error {
			defer sem.Release(1)
			if kind := engine.CheckPromptInjection(text); kind != "" {
				blockMu.Lock()
				if blockKind == "" {
					blockKind = kind
				}
				blockMu.Unlock()
				return errBlockedSentinel
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil && err != errBlockedSentinel {
		return nil, fmt.Errorf("prompt-injection evaluation failed: %w", err)
	}

	if blockKind != "" {
		return &Decision{
			Action:        models.ActionBlocked,
			BlockedReason: fmt.Sprintf("Prompt contains restricted content (type: %s)", blockKind),
		}, nil
	}
	return &Decision{Action: models.ActionNone}, nil
}
