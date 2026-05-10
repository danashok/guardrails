# guardrails

Go service that evaluates LLM prompt guardrail policies (PII redaction, prompt-injection
blocking) for the [LiteLLM proxy](https://docs.litellm.ai/) via its
[`generic_guardrail_api`](https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api)
BETA contract.

LiteLLM POSTs each chat-completions request body to this service before forwarding to the
upstream model. The service responds with one of:

- `BLOCKED` — LiteLLM rejects the request.
- `GUARDRAIL_INTERVENED` — LiteLLM substitutes the redacted text back into the request.
- `NONE` — request passes through unchanged.

All policy logic (regex, Luhn checks, signature lists) lives in `internal/engine/` and is
intentionally unexported — callers cannot see how a decision is made.

## Endpoint

```
POST /beta/litellm_basic_guardrail_api
Header: X-Guardrail-Auth-Key: <shared secret>
```

LiteLLM picks the policy via `additional_provider_specific_params.policy`:
- `pii` — runs PII block (SSN, CC) + redaction (email, phone, API key, company, names).
- `prompt_injection` — blocks known jailbreak / system-prompt-leak signatures.

## Run locally

The service joins the same Docker network as the `ai-gateway` LiteLLM stack so LiteLLM
can resolve it as `http://guardrails:8080`. Make sure that network exists first:

```bash
docker network create litellm-net   # one-time
cp .env.example .env                # fill in GUARDRAIL_API_KEY
make app-up                         # builds image, starts app + db
make app-down                       # stop
```

For DB only (e.g. when running the Go binary on the host):

```bash
make db-up
go run cmd/main.go
```

Health: `curl http://localhost:8080/health/liveliness`

## Build OpenAPI / Swagger

```bash
make swag
# Swagger UI: http://localhost:8080/swagger/index.html
```

## Audit log

Every evaluation is recorded in `guardrail_events` (Postgres):

| column | purpose |
|---|---|
| `policy`, `action`, `blocked_reason` | decision |
| `raw_texts`, `redacted_texts` | input + post-redaction output (jsonb) |
| `requester_ip`, `requester_ip_source` | from `X-Forwarded-For` → `X-Real-IP` → direct |
| `client_api_key_hash`, `client_alias` | from LiteLLM virtual-key context |
| `litellm_call_id`, `litellm_trace_id`, `eval_duration_ms`, `evaluated_at` | observability |

Audit writes go through a buffered channel + worker pool — DB latency does not slow the
guardrail decision path. Toggle with `AUDIT_ENABLED=false`.

## Adding a new pattern

Edit `internal/engine/patterns.go`:
- BLOCK rule → add a compiled regex and a check inside `CheckBlock` in `redactor.go`.
  Return a labeled error; never echo matched content back to the caller.
- REDACT rule → add a compiled regex and a `.ReplaceAllString(text, "[REDACTED_X]")`
  inside `Redact` in `redactor.go`.

`make test` for parity tests, `make app-down && make app-up` to deploy.

## Env

See `.env.example`. `GUARDRAIL_API_KEY` is the shared secret LiteLLM presents in
`X-Guardrail-Auth-Key`.
