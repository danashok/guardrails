package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/ashokdan/guardrails/internal/engine"
	"github.com/ashokdan/guardrails/internal/models"
)

func newPIISvc() IPIIAndToolCheckService { return NewPIIAndToolCheckService(8) }

func TestPIIService_SSNRedactedNotBlocked(t *testing.T) {
	d, err := newPIISvc().Evaluate(context.Background(), zap.NewNop(), []string{
		"email me at a@b.com",
		"ssn 123-45-6789",
	}, nil, nil)
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
	in := []string{"email a@b.com", "clean text", "phone 555-123-4567"}
	d, err := newPIISvc().Evaluate(context.Background(), zap.NewNop(), in, nil, nil)
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
	d, err := newPIISvc().Evaluate(context.Background(), zap.NewNop(), []string{
		"hello world",
		"how are you",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionNone {
		t.Fatalf("expected NONE, got %s", d.Action)
	}
}

func TestPIIService_EmptyInput(t *testing.T) {
	d, err := newPIISvc().Evaluate(context.Background(), zap.NewNop(), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionNone {
		t.Fatalf("expected NONE on empty input, got %s", d.Action)
	}
}

// Tool-check short-circuits: when tools/tool_calls trigger a block, PII
// redaction should not run even if `texts` contains PII.
func TestToolCheckShortCircuitsPII(t *testing.T) {
	engine.InitToolChecks(
		[]string{"tsmc"},
		[]string{"/tmp"},
		[]string{"/tmp"},
	)
	dirty := []string{"email a@b.com"} // would normally redact to INTERVENED
	tools := json.RawMessage(`[{"type":"function","function":{"name":"shell","description":"sudo apt install nginx"}}]`)

	d, err := newPIISvc().Evaluate(context.Background(), zap.NewNop(), dirty, tools, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionBlocked {
		t.Fatalf("expected BLOCKED on tool-check match, got %s", d.Action)
	}
	if !strings.Contains(d.BlockedReason, "Tool call blocked") {
		t.Errorf("reason missing 'Tool call blocked': %q", d.BlockedReason)
	}
	// Critical: PII redaction must not have produced any texts.
	if len(d.Texts) != 0 {
		t.Errorf("PII redaction ran despite tool-block: %v", d.Texts)
	}
}

// Clean tools + dirty texts → INTERVENED with redacted texts (no block).
func TestCleanToolsDirtyTexts(t *testing.T) {
	engine.InitToolChecks(
		[]string{"tsmc"},
		[]string{"/tmp"},
		[]string{"/tmp"},
	)
	tools := json.RawMessage(`[{"type":"function","function":{"name":"calc","description":"add two numbers"}}]`)
	d, err := newPIISvc().Evaluate(context.Background(), zap.NewNop(),
		[]string{"reach me at a@b.com"}, tools, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionIntervened {
		t.Fatalf("expected INTERVENED, got %s", d.Action)
	}
	if !strings.Contains(d.Texts[0], "[REDACTED_EMAIL]") {
		t.Errorf("PII not redacted: %q", d.Texts[0])
	}
}

func TestCleanBothReturnsNone(t *testing.T) {
	engine.InitToolChecks(
		[]string{"tsmc"},
		[]string{"/tmp"},
		[]string{"/tmp"},
	)
	tools := json.RawMessage(`[{"type":"function","function":{"name":"calc"}}]`)
	d, err := newPIISvc().Evaluate(context.Background(), zap.NewNop(),
		[]string{"hello world"}, tools, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if d.Action != models.ActionNone {
		t.Fatalf("expected NONE, got %s", d.Action)
	}
}
