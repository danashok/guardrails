package service

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/ashokdan/guardrails/internal/repository"
)

type IAuthorizationService interface {
	IsAllowed(ctx context.Context, ntaccount, ip string) (bool, error)
}

type authorizationService struct {
	repo   repository.IAuthorizedIPRepository
	logger *zap.Logger
	ttl    time.Duration
	cache  sync.Map // ntaccount -> *cacheEntry
}

type cacheEntry struct {
	ips       map[string]struct{}
	expiresAt time.Time
}

func NewAuthorizationService(
	repo repository.IAuthorizedIPRepository,
	logger *zap.Logger,
	ttl time.Duration,
) IAuthorizationService {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &authorizationService{repo: repo, logger: logger, ttl: ttl}
}

func (s *authorizationService) IsAllowed(ctx context.Context, ntaccount, ip string) (bool, error) {
	if ntaccount == "" || ip == "" {
		return false, nil
	}
	if net.ParseIP(ip) == nil {
		return false, nil
	}

	if entry, ok := s.loadEntry(ntaccount); ok {
		_, allowed := entry.ips[ip]
		return allowed, nil
	}

	ips, err := s.repo.ListByNTAccount(ctx, ntaccount)
	if err != nil {
		return false, err
	}
	entry := &cacheEntry{
		ips:       make(map[string]struct{}, len(ips)),
		expiresAt: time.Now().Add(s.ttl),
	}
	for _, allowedIP := range ips {
		entry.ips[allowedIP] = struct{}{}
	}
	s.cache.Store(ntaccount, entry)

	_, allowed := entry.ips[ip]
	return allowed, nil
}

func (s *authorizationService) loadEntry(ntaccount string) (*cacheEntry, bool) {
	v, ok := s.cache.Load(ntaccount)
	if !ok {
		return nil, false
	}
	entry := v.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		s.cache.Delete(ntaccount)
		return nil, false
	}
	return entry, true
}
