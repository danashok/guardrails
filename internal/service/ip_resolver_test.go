package service

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/ashokdan/guardrails/internal/models"
)

func newCtx(t *testing.T) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/x", nil)
	c.Request.RemoteAddr = "192.0.2.10:1234"
	return c
}

func TestResolveRequesterIP_PrefersXFFFirstHop(t *testing.T) {
	c := newCtx(t)
	ip, src := ResolveRequesterIP(c, map[string]string{
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

func TestResolveRequesterIP_FallsBackToXRI(t *testing.T) {
	c := newCtx(t)
	ip, src := ResolveRequesterIP(c, map[string]string{
		"x-real-ip": "198.51.100.7",
	})
	if ip != "198.51.100.7" {
		t.Errorf("expected XRI ip, got %q", ip)
	}
	if src != models.IPSourceXRI {
		t.Errorf("expected source xri, got %q", src)
	}
}

func TestResolveRequesterIP_FallsBackToDirect(t *testing.T) {
	c := newCtx(t)
	ip, src := ResolveRequesterIP(c, nil)
	if ip != "192.0.2.10" {
		t.Errorf("expected direct ip 192.0.2.10, got %q", ip)
	}
	if src != models.IPSourceDirect {
		t.Errorf("expected source direct, got %q", src)
	}
}

func TestResolveRequesterIP_HeaderCaseInsensitive(t *testing.T) {
	c := newCtx(t)
	ip, src := ResolveRequesterIP(c, map[string]string{
		"X-Forwarded-For": "203.0.113.5",
	})
	if ip != "203.0.113.5" || src != models.IPSourceXFF {
		t.Fatalf("expected XFF resolution from canonical header; got %q / %q", ip, src)
	}
}

func TestResolveRequesterIP_InvalidIPFallsThrough(t *testing.T) {
	c := newCtx(t)
	ip, src := ResolveRequesterIP(c, map[string]string{
		"x-forwarded-for": "not-an-ip",
		"x-real-ip":       "203.0.113.99",
	})
	if ip != "203.0.113.99" {
		t.Errorf("expected fallback to XRI on invalid XFF, got %q", ip)
	}
	if src != models.IPSourceXRI {
		t.Errorf("expected source xri on fallback, got %q", src)
	}
}
