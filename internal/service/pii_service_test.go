package service

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/ashokdan/guardrails/internal/models"
)

func TestPIIService_SSNRedactedNotBlocked(t *testing.T) {
	svc := NewPIIService(8)
	d, err := svc.Evaluate(context.Background(), zap.NewNop(), []string{
		"email me at a@b.com",
		"ssn 123-45-6789",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionIntervened {
		t.Fatalf("expected GUARDRAIL_INTERVENED, got %s", d.Action)
	}
	if len(d.Texts) != 2 {
		t.Fatalf("expected 2 redacted texts, got %d", len(d.Texts))
	}
	if !strings.Contains(d.Texts[0], "[REDACTED_EMAIL]") {
		t.Errorf("texts[0] not redacted: %q", d.Texts[0])
	}
	if !strings.Contains(d.Texts[1], "[REDACTED_SSN]") {
		t.Errorf("texts[1] not redacted: %q", d.Texts[1])
	}
	if strings.Contains(d.Texts[1], "123-45-6789") {
		t.Fatalf("ssn leaked through redaction: %q", d.Texts[1])
	}
}

func TestPIIService_RedactReturnsAllTexts(t *testing.T) {
	svc := NewPIIService(8)
	in := []string{"email a@b.com", "clean text", "phone 555-123-4567"}
	d, err := svc.Evaluate(context.Background(), zap.NewNop(), in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionIntervened {
		t.Fatalf("expected GUARDRAIL_INTERVENED, got %s", d.Action)
	}
	if len(d.Texts) != 3 {
		t.Fatalf("expected 3 redacted texts, got %d", len(d.Texts))
	}
	if !strings.Contains(d.Texts[0], "[REDACTED_EMAIL]") {
		t.Errorf("texts[0] not redacted: %q", d.Texts[0])
	}
	if d.Texts[1] != "clean text" {
		t.Errorf("clean text mutated: %q", d.Texts[1])
	}
	if !strings.Contains(d.Texts[2], "[REDACTED_PHONE]") {
		t.Errorf("texts[2] not redacted: %q", d.Texts[2])
	}
}

func TestPIIService_AllCleanReturnsNone(t *testing.T) {
	svc := NewPIIService(8)
	d, err := svc.Evaluate(context.Background(), zap.NewNop(), []string{
		"hello world",
		"how are you",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionNone {
		t.Fatalf("expected NONE, got %s", d.Action)
	}
}

func TestPIIService_EmptyInput(t *testing.T) {
	svc := NewPIIService(8)
	d, err := svc.Evaluate(context.Background(), zap.NewNop(), nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionNone {
		t.Fatalf("expected NONE on empty input, got %s", d.Action)
	}
}
