package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type GuardrailAction string

const (
	ActionBlocked     GuardrailAction = "BLOCKED"
	ActionIntervened  GuardrailAction = "GUARDRAIL_INTERVENED"
	ActionNone        GuardrailAction = "NONE"
)

type IPSource string

const (
	IPSourceXFF    IPSource = "xff"
	IPSourceXRI    IPSource = "xri"
	IPSourceDirect IPSource = "direct"
)

type GuardrailEvent struct {
	ID                 uuid.UUID       `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	LiteLLMCallID      string          `gorm:"index;column:litellm_call_id" json:"litellm_call_id"`
	LiteLLMTraceID     string          `gorm:"index;column:litellm_trace_id" json:"litellm_trace_id"`
	Policy             string          `gorm:"index" json:"policy"`
	Action             GuardrailAction `json:"action"`
	BlockedReason      *string         `json:"blocked_reason,omitempty"`
	RawTexts           datatypes.JSON  `gorm:"type:jsonb" json:"raw_texts"`
	RedactedTexts      datatypes.JSON  `gorm:"type:jsonb" json:"redacted_texts,omitempty"`
	RequesterIP        *string         `gorm:"type:inet;index" json:"requester_ip,omitempty"`
	RequesterIPSource  IPSource        `json:"requester_ip_source"`
	ClientAPIKeyHash   string          `gorm:"index;column:client_api_key_hash" json:"client_api_key_hash"`
	ClientAlias        string          `json:"client_alias"`
	EvalDurationMS     int             `json:"eval_duration_ms"`
	EvaluatedAt        time.Time       `gorm:"index" json:"evaluated_at"`
}

func (GuardrailEvent) TableName() string {
	return "guardrail_events"
}
