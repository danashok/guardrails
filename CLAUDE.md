# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this service is

Go HTTP service that implements the LiteLLM `generic_guardrail_api` BETA contract. LiteLLM POSTs each chat-completions body to `POST /beta/litellm_basic_guardrail_api`; this service responds with one of three `action` values that LiteLLM interprets:

- `BLOCKED` — LiteLLM rejects the request (used by `prompt_injection` policy).
- `GUARDRAIL_INTERVENED` — LiteLLM substitutes our `texts` back into the request (used by `pii` policy after redaction).
- `NONE` — request passes through unchanged.

Policy is selected by LiteLLM via `additional_provider_specific_params.policy` in the body (`pii` or `prompt_injection`).

## Common commands

```bash
make test           # go test -v ./...
make build          # build binary to bin/main
make run            # go run cmd/main.go (needs DB up + .env)
make tidy           # go mod tidy
make swag           # regenerate OpenAPI/Swagger from godoc comments → openapi/

make db-up          # start only Postgres (docker-compose/infra.yml)
make db-down
make app-up         # build + start app + db on litellm-net (docker-compose/local.yml)
make app-down
```

Single test: `go test -v -run TestName ./internal/engine/` (or whichever package).

The Docker stack joins an external network `litellm-net` so LiteLLM resolves this service as `http://guardrails:8080`. Create it once with `docker network create litellm-net` before `make app-up`.

## Architecture

Layered Gin app wired in `cmd/main.go` → `internal/routes/router.go`:

```
controller (Gin handler)
  → service (IPIIService / IPromptInjectionService)  ← stateless evaluators
      → engine (regex + Luhn)                        ← all policy logic
  → service (IGuardrailEventService)                 ← async audit
      → repository (GORM)
          → Postgres
```

Key boundaries:

- **`internal/engine/`** owns *all* policy logic (regex compilation in `patterns.go`, dispatch in `redactor.go`, Luhn in `luhn.go`). It is intentionally the only place that knows what gets blocked or redacted; callers never see match details. Adding a new rule means editing `patterns.go` (compile the regex) and either `Redact` (for redaction) or `CheckPromptInjection` / a new `BlockKind` constant (for blocking) in `redactor.go`. Regex order in `Redact` matters — see the comment there (SSN/CC before phone; company-domain before bare-word).
- **Service layer** parallelises evaluation across `texts[]` using `errgroup` + `semaphore` capped by `MAX_CONCURRENT_CHECKS`. PII is always redact-only (no early exit, all texts processed). Prompt-injection short-circuits via a sentinel error (`errBlockedSentinel`) on the first match.
- **Audit pipeline** (`guardrail_event_service.go`) is fire-and-forget: the controller calls `Submit(event)` which non-blocking-sends onto a buffered channel; a worker pool drains it. If the channel is full, events are *dropped with a warning* rather than blocking the request path. Toggle with `AUDIT_ENABLED`; tune with `AUDIT_WORKERS` / `AUDIT_BUFFER`. `Routes.Shutdown()` (deferred in `main`) closes the channel and waits for workers.
- **`ResolveRequesterIP`** (`internal/service/ip_resolver.go`) reads the `request_headers` map *inside the LiteLLM body* (not the inbound HTTP headers — those come from LiteLLM itself). Order: `x-forwarded-for` first hop → `x-real-ip` → direct `c.ClientIP()`. This is because LiteLLM forwards original client headers via `extra_headers` in its config.

## Auth and request shape

- All `/beta/*` routes require `X-Guardrail-Auth-Key: <GUARDRAIL_API_KEY>` (constant-time compare in `middleware/auth.go`). Missing/invalid → 401.
- Body size capped by `MaxBodyBytesMiddleware` (`MAX_BODY_BYTES`, default 16 MB; `.env.example` ships with 256 KB — verify before changing).
- `LiteLLMRequest` in `controller/guardrail_controller.go` mirrors LiteLLM's spec; unused fields (`tools`, `tool_calls`, `structured_messages`) are kept as `json.RawMessage` so future LiteLLM additions don't break unmarshalling. Don't drop them.

## Database

- Single table `guardrail_events` (`internal/models/guardrail_event.go`), GORM AutoMigrate on startup, requires `uuid-ossp` extension (created on boot in `db/database.go`).
- `RawTexts` and `RedactedTexts` are JSONB; `RequesterIP` is `inet`.
- `GuardrailAction` enum mirrors LiteLLM's response contract — don't rename string values.

## Conventions worth preserving

- Decisions never echo matched content back through the API (e.g. `BlockedReason` is a labeled type like `Prompt contains restricted content (type: PROMPT_INJECTION)`, never the offending substring).
- Service methods take `(ctx, logger, texts)` and return `*Decision`. The controller is the only place that maps `Decision` → HTTP response.
- `swag` reads godoc on the controller method and `cmd/main.go` `@title`/`@securityDefinitions` block — keep those annotations in sync when adding endpoints.
