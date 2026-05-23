package service

import (
	"net"
	"strings"

	"github.com/ashokdan/guardrails/internal/models"
)

// ResolveRequesterIP returns the first hop in request_headers["x-forwarded-for"]
// — the original client. It is the only accepted source: there is no fallback
// to x-real-ip or to the direct connection IP, because in our deployment the
// direct peer is LiteLLM and x-real-ip is not set end-to-end.
//
// Returns "" if the header is missing, empty, or the first hop is not a valid
// IP. Callers must treat an empty return as a block.
//
// `forwarded` is the request_headers map sent inside the LiteLLM body — these
// come from `extra_headers` in config.yaml.
func ResolveRequesterIP(forwarded map[string]string) (string, models.IPSource) {
	v := lookup(forwarded, "x-forwarded-for")
	if v == "" {
		return "", models.IPSourceXFF
	}
	first := firstHop(v)
	if first == "" || net.ParseIP(first) == nil {
		return "", models.IPSourceXFF
	}
	return first, models.IPSourceXFF
}

func lookup(headers map[string]string, name string) string {
	if headers == nil {
		return ""
	}
	if v, ok := headers[name]; ok {
		return v
	}
	// Headers may arrive in canonical form
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func firstHop(xff string) string {
	if i := strings.IndexByte(xff, ','); i >= 0 {
		return strings.TrimSpace(xff[:i])
	}
	return strings.TrimSpace(xff)
}
