package service

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/ashokdan/guardrails/internal/models"
)

// ResolveRequesterIP picks the most upstream-trustworthy IP available.
// Order:
//  1. First hop in request_headers["x-forwarded-for"] (the original client).
//  2. request_headers["x-real-ip"].
//  3. Direct connection IP from gin (which is LiteLLM in our deployment).
//
// `forwarded` is the request_headers map sent inside the LiteLLM body —
// these come from `extra_headers` in config.yaml.
func ResolveRequesterIP(c *gin.Context, forwarded map[string]string) (string, models.IPSource) {
	if v := lookup(forwarded, "x-forwarded-for"); v != "" {
		if first := firstHop(v); first != "" && net.ParseIP(first) != nil {
			return first, models.IPSourceXFF
		}
	}
	if v := lookup(forwarded, "x-real-ip"); v != "" {
		v = strings.TrimSpace(v)
		if net.ParseIP(v) != nil {
			return v, models.IPSourceXRI
		}
	}
	if ip := c.ClientIP(); ip != "" && net.ParseIP(ip) != nil {
		return ip, models.IPSourceDirect
	}
	return "", models.IPSourceDirect
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
