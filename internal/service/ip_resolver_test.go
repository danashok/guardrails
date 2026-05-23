package service

import (
	"testing"

	"github.com/ashokdan/guardrails/internal/models"
)

func TestResolveRequesterIP_ReturnsXFFFirstHop(t *testing.T) {
	ip, src := ResolveRequesterIP(map[string]string{
		"x-forwarded-for": "203.0.113.5, 198.51.100.7",
		"x-real-ip":       "198.51.100.7",
	})
	if ip != "203.0.113.5" {
		t.Errorf("expected XFF first-hop, got %q", ip)
	}
	if src != models.IPSourceXFF {
		t.Errorf("expected source xff, got %q", src)
	}
}

func TestResolveRequesterIP_HeaderCaseInsensitive(t *testing.T) {
	ip, src := ResolveRequesterIP(map[string]string{
		"X-Forwarded-For": "203.0.113.5",
	})
	if ip != "203.0.113.5" || src != models.IPSourceXFF {
		t.Fatalf("expected XFF resolution from canonical header; got %q / %q", ip, src)
	}
}

func TestResolveRequesterIP_BlocksWhenXFFMissing(t *testing.T) {
	ip, _ := ResolveRequesterIP(nil)
	if ip != "" {
		t.Errorf("expected empty IP when XFF missing, got %q", ip)
	}

	ip, _ = ResolveRequesterIP(map[string]string{
		"x-real-ip": "198.51.100.7",
	})
	if ip != "" {
		t.Errorf("expected empty IP when only XRI present, got %q", ip)
	}
}

func TestResolveRequesterIP_BlocksWhenXFFInvalid(t *testing.T) {
	ip, _ := ResolveRequesterIP(map[string]string{
		"x-forwarded-for": "not-an-ip",
		"x-real-ip":       "203.0.113.99",
	})
	if ip != "" {
		t.Errorf("expected empty IP on invalid XFF (no XRI fallback), got %q", ip)
	}
}

func TestResolveRequesterIP_BlocksWhenXFFEmpty(t *testing.T) {
	ip, _ := ResolveRequesterIP(map[string]string{
		"x-forwarded-for": "   ",
	})
	if ip != "" {
		t.Errorf("expected empty IP on blank XFF, got %q", ip)
	}
}
