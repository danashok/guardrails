package service

import (
	"context"
	"encoding/json"
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

type IPIIAndToolCheckService interface {
	Evaluate(
		ctx context.Context,
		logger *zap.Logger,
		texts []string,
		rawTools, rawToolCalls json.RawMessage,
	) (*Decision, error)
}

type piiAndToolCheckService struct {
	maxConcurrent int
}

func NewPIIAndToolCheckService(maxConcurrent int) IPIIAndToolCheckService {
	if maxConcurrent <= 0 {
		maxConcurrent = 32
	}
	return &piiAndToolCheckService{maxConcurrent: maxConcurrent}
}

// Evaluate runs the tool-call security checks first; on a match it returns
// BLOCKED and the PII redaction never runs. Otherwise it falls through to
// the existing parallel PII redaction over `texts`.
func (s *piiAndToolCheckService) Evaluate(
	ctx context.Context,
	logger *zap.Logger,
	texts []string,
	rawTools, rawToolCalls json.RawMessage,
) (*Decision, error) {
	if kind, rule := engine.CheckTools(rawTools, rawToolCalls); kind != "" {
		return &Decision{
			Action:        models.ActionBlocked,
			BlockedReason: fmt.Sprintf("Tool call blocked (type: %s)", rule),
		}, nil
	}

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
