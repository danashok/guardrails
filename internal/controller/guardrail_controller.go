package controller

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"github.com/ashokdan/guardrails/internal/middleware"
	"github.com/ashokdan/guardrails/internal/models"
	"github.com/ashokdan/guardrails/internal/service"
)

const (
	policyPII             = "pii"
	policyPromptInjection = "prompt_injection"
	policyAuthorization   = "authorization"

	authzBlockedReason = "API key not authorized from source IP"
)

// LiteLLMRequest mirrors the body shape LiteLLM POSTs per generic_guardrail_api spec.
// Fields not used today are kept as RawMessage so future LiteLLM additions don't
// break unmarshalling.
type LiteLLMRequest struct {
	Texts                            []string          `json:"texts"`
	Images                           []string          `json:"images"`
	Tools                            json.RawMessage   `json:"tools"`
	ToolCalls                        json.RawMessage   `json:"tool_calls"`
	StructuredMessages               json.RawMessage   `json:"structured_messages"`
	RequestData                      RequestData       `json:"request_data"`
	RequestHeaders                   map[string]string `json:"request_headers"`
	LiteLLMCallID                    string            `json:"litellm_call_id"`
	LiteLLMTraceID                   string            `json:"litellm_trace_id"`
	InputType                        string            `json:"input_type"`
	LiteLLMVersion                   string            `json:"litellm_version"`
	AdditionalProviderSpecificParams map[string]any    `json:"additional_provider_specific_params"`
}

type RequestData struct {
	UserAPIKeyHash      string `json:"user_api_key_hash"`
	UserAPIKeyAlias     string `json:"user_api_key_alias"`
	UserAPIKeyUserID    string `json:"user_api_key_user_id"`
	UserAPIKeyUserEmail string `json:"user_api_key_user_email"`
	UserAPIKeyTeamID    string `json:"user_api_key_team_id"`
	UserAPIKeyTeamAlias string `json:"user_api_key_team_alias"`
	UserAPIKeyEndUserID string `json:"user_api_key_end_user_id"`
	UserAPIKeyOrgID     string `json:"user_api_key_org_id"`
}

type LiteLLMResponse struct {
	Action        models.GuardrailAction `json:"action"`
	BlockedReason string                 `json:"blocked_reason,omitempty"`
	Texts         []string               `json:"texts,omitempty"`
	Images        []string               `json:"images,omitempty"`
}

type GuardrailController struct {
	pii    service.IPIIService
	prompt service.IPromptInjectionService
	authz  service.IAuthorizationService
	audit  service.IGuardrailEventService
	logger *zap.Logger
}

func NewGuardrailController(
	pii service.IPIIService,
	prompt service.IPromptInjectionService,
	authz service.IAuthorizationService,
	audit service.IGuardrailEventService,
	logger *zap.Logger,
) *GuardrailController {
	return &GuardrailController{pii: pii, prompt: prompt, authz: authz, audit: audit, logger: logger}
}

// Evaluate godoc
// @Summary Evaluate a guardrail policy on a LiteLLM payload
// @Tags guardrails
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param payload body LiteLLMRequest true "LiteLLM generic_guardrail_api body"
// @Success 200 {object} LiteLLMResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /beta/litellm_basic_guardrail_api [post]
func (ctrl *GuardrailController) Evaluate(c *gin.Context) {
	authCtx := middleware.GetAuthContext(c)
	_ = authCtx

	var req LiteLLMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	policy, _ := req.AdditionalProviderSpecificParams["policy"].(string)
	if policy != policyPII && policy != policyPromptInjection {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown or missing policy"})
		return
	}

	start := time.Now()

	identity := req.RequestData.UserAPIKeyUserID
	ip, ipSrc := service.ResolveRequesterIP(c, req.RequestHeaders)

	if identity == "" || ip == "" || ipSrc == models.IPSourceDirect {
		ctrl.logger.Warn("authorization rejected: missing identity or untrusted IP source",
			zap.String("ntaccount", identity),
			zap.String("ip_source", string(ipSrc)),
			zap.String("litellm_call_id", req.LiteLLMCallID),
		)
		d := &service.Decision{Action: models.ActionBlocked, BlockedReason: authzBlockedReason}
		ctrl.recordAudit(c, &req, d, policyAuthorization, time.Since(start))
		c.JSON(http.StatusOK, LiteLLMResponse{Action: d.Action, BlockedReason: d.BlockedReason})
		return
	}

	allowed, authzErr := ctrl.authz.IsAllowed(c.Request.Context(), identity, ip)
	if authzErr != nil {
		ctrl.logger.Error("authorization check failed",
			zap.String("ntaccount", identity),
			zap.String("litellm_call_id", req.LiteLLMCallID),
			zap.Error(authzErr),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization check failed"})
		return
	}
	if !allowed {
		ctrl.logger.Warn("authorization rejected: source IP not in allowlist",
			zap.String("ntaccount", identity),
			zap.String("ip", ip),
			zap.String("litellm_call_id", req.LiteLLMCallID),
		)
		d := &service.Decision{Action: models.ActionBlocked, BlockedReason: authzBlockedReason}
		ctrl.recordAudit(c, &req, d, policyAuthorization, time.Since(start))
		c.JSON(http.StatusOK, LiteLLMResponse{Action: d.Action, BlockedReason: d.BlockedReason})
		return
	}

	var (
		decision *service.Decision
		err      error
	)

	switch policy {
	case policyPII:
		decision, err = ctrl.pii.Evaluate(c.Request.Context(), ctrl.logger, req.Texts)
	case policyPromptInjection:
		decision, err = ctrl.prompt.Evaluate(c.Request.Context(), ctrl.logger, req.Texts)
	}

	if err != nil {
		ctrl.logger.Error("guardrail evaluation failed",
			zap.String("policy", policy),
			zap.String("litellm_call_id", req.LiteLLMCallID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "guardrail evaluation failed"})
		return
	}

	resp := LiteLLMResponse{Action: decision.Action}
	if decision.Action == models.ActionBlocked {
		resp.BlockedReason = decision.BlockedReason
	}
	if decision.Action == models.ActionIntervened {
		resp.Texts = decision.Texts
	}

	ctrl.recordAudit(c, &req, decision, policy, time.Since(start))

	c.JSON(http.StatusOK, resp)
}

func (ctrl *GuardrailController) recordAudit(
	c *gin.Context,
	req *LiteLLMRequest,
	decision *service.Decision,
	policy string,
	dur time.Duration,
) {
	rawJSON, _ := json.Marshal(req.Texts)

	var redactedJSON datatypes.JSON
	if decision.Action == models.ActionIntervened && len(decision.Texts) > 0 {
		if b, err := json.Marshal(decision.Texts); err == nil {
			redactedJSON = b
		}
	}

	ip, ipSrc := service.ResolveRequesterIP(c, req.RequestHeaders)
	var ipPtr *string
	if ip != "" {
		ipPtr = &ip
	}

	var reasonPtr *string
	if decision.Action == models.ActionBlocked && decision.BlockedReason != "" {
		r := decision.BlockedReason
		reasonPtr = &r
	}

	event := &models.GuardrailEvent{
		LiteLLMCallID:     req.LiteLLMCallID,
		LiteLLMTraceID:    req.LiteLLMTraceID,
		Policy:            policy,
		Action:            decision.Action,
		BlockedReason:     reasonPtr,
		RawTexts:          rawJSON,
		RedactedTexts:     redactedJSON,
		RequesterIP:       ipPtr,
		RequesterIPSource: ipSrc,
		ClientAPIKeyHash:  req.RequestData.UserAPIKeyHash,
		ClientAlias:       req.RequestData.UserAPIKeyAlias,
		EvalDurationMS:    int(dur.Milliseconds()),
		EvaluatedAt:       time.Now().UTC(),
	}
	ctrl.audit.Submit(event)
}
