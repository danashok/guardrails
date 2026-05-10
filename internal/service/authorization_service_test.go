package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

type fakeAuthzRepo struct {
	calls atomic.Int32
	rows  map[string][]string
	err   error
}

func (f *fakeAuthzRepo) ListByNTAccount(_ context.Context, ntaccount string) ([]string, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.rows[ntaccount], nil
}

func newSvc(repo *fakeAuthzRepo, ttl time.Duration) IAuthorizationService {
	return NewAuthorizationService(repo, zap.NewNop(), ttl)
}

func TestAuthorization_AllowedHit(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{"jdoe": {"10.0.0.1", "10.0.0.2"}}}
	svc := newSvc(repo, time.Minute)

	ok, err := svc.IsAllowed(context.Background(), "jdoe", "10.0.0.1")
	if err != nil || !ok {
		t.Fatalf("expected allowed, got ok=%v err=%v", ok, err)
	}
}

func TestAuthorization_NotAllowed(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{"jdoe": {"10.0.0.1"}}}
	svc := newSvc(repo, time.Minute)

	ok, err := svc.IsAllowed(context.Background(), "jdoe", "10.0.0.99")
	if err != nil || ok {
		t.Fatalf("expected blocked, got ok=%v err=%v", ok, err)
	}
}

func TestAuthorization_UnknownNTAccountBlocked(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{}}
	svc := newSvc(repo, time.Minute)

	ok, err := svc.IsAllowed(context.Background(), "ghost", "10.0.0.1")
	if err != nil || ok {
		t.Fatalf("expected blocked for unknown account, got ok=%v err=%v", ok, err)
	}
}

func TestAuthorization_EmptyInputs(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{"jdoe": {"10.0.0.1"}}}
	svc := newSvc(repo, time.Minute)

	cases := []struct{ nt, ip string }{
		{"", "10.0.0.1"},
		{"jdoe", ""},
		{"", ""},
	}
	for _, c := range cases {
		ok, err := svc.IsAllowed(context.Background(), c.nt, c.ip)
		if err != nil || ok {
			t.Fatalf("expected blocked for nt=%q ip=%q, got ok=%v err=%v", c.nt, c.ip, ok, err)
		}
	}
	if repo.calls.Load() != 0 {
		t.Fatalf("repo should not be called for empty inputs, got %d", repo.calls.Load())
	}
}

func TestAuthorization_InvalidIPBlocked(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{"jdoe": {"10.0.0.1"}}}
	svc := newSvc(repo, time.Minute)

	ok, err := svc.IsAllowed(context.Background(), "jdoe", "not-an-ip")
	if err != nil || ok {
		t.Fatalf("expected blocked for invalid ip, got ok=%v err=%v", ok, err)
	}
	if repo.calls.Load() != 0 {
		t.Fatalf("repo should not be called for invalid ip, got %d", repo.calls.Load())
	}
}

func TestAuthorization_CacheHitsRepoOnce(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{"jdoe": {"10.0.0.1"}}}
	svc := newSvc(repo, time.Minute)

	for i := 0; i < 5; i++ {
		if _, err := svc.IsAllowed(context.Background(), "jdoe", "10.0.0.1"); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}
	if got := repo.calls.Load(); got != 1 {
		t.Fatalf("expected 1 repo call, got %d", got)
	}
}

func TestAuthorization_CacheExpiry(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{"jdoe": {"10.0.0.1"}}}
	svc := newSvc(repo, 10*time.Millisecond)

	if _, err := svc.IsAllowed(context.Background(), "jdoe", "10.0.0.1"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := svc.IsAllowed(context.Background(), "jdoe", "10.0.0.1"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got := repo.calls.Load(); got != 2 {
		t.Fatalf("expected 2 repo calls after expiry, got %d", got)
	}
}

func TestAuthorization_NegativeResultCached(t *testing.T) {
	repo := &fakeAuthzRepo{rows: map[string][]string{}}
	svc := newSvc(repo, time.Minute)

	for i := 0; i < 3; i++ {
		if _, err := svc.IsAllowed(context.Background(), "ghost", "10.0.0.1"); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	}
	if got := repo.calls.Load(); got != 1 {
		t.Fatalf("expected 1 repo call (negative cached), got %d", got)
	}
}

func TestAuthorization_RepoErrorPropagates(t *testing.T) {
	repo := &fakeAuthzRepo{err: errors.New("db down")}
	svc := newSvc(repo, time.Minute)

	ok, err := svc.IsAllowed(context.Background(), "jdoe", "10.0.0.1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if ok {
		t.Fatalf("expected blocked on error")
	}
}
