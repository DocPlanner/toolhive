// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package upstreamtoken

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/stacklok/toolhive/pkg/authserver/storage"
)

// refreshTimeout bounds how long a singleflight-deduplicated token refresh
// may take before being cancelled. It is deliberately detached from the
// triggering request's context so that waiting callers are not abandoned.
const refreshTimeout = 30 * time.Second

// InProcessService implements the Service interface for in-process use.
// It composes storage (read), refresher (refresh + persist), and singleflight
// (dedup) to provide a single GetValidTokens call.
type InProcessService struct {
	storage   storage.UpstreamTokenStorage
	refresher storage.UpstreamTokenRefresher
	sfGroup   singleflight.Group
}

// Compile-time checks.
var (
	_ Service     = (*InProcessService)(nil)
	_ TokenReader = (*InProcessService)(nil)
)

// NewInProcessService creates a new InProcessService.
// The refresher may be nil if upstream token refresh is not configured;
// expired tokens will return ErrNoRefreshToken in that case.
func NewInProcessService(
	stor storage.UpstreamTokenStorage,
	refresher storage.UpstreamTokenRefresher,
) *InProcessService {
	return &InProcessService{
		storage:   stor,
		refresher: refresher,
	}
}

// GetValidTokens returns a valid upstream credential for a session and provider.
// It transparently refreshes expired access tokens using the refresh token.
func (s *InProcessService) GetValidTokens(ctx context.Context, sessionID, providerName string) (*UpstreamCredential, error) {
	tokens, err := s.storage.GetUpstreamTokens(ctx, sessionID, providerName)
	if err != nil {
		// ErrExpired returns tokens (including refresh token) alongside the error.
		// Attempt a refresh before giving up.
		if errors.Is(err, storage.ErrExpired) {
			if tokens != nil {
				return s.refreshOrFail(ctx, sessionID, providerName, tokens)
			}
			// Expired but storage returned nil tokens — can't refresh.
			return nil, ErrNoRefreshToken
		}
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		if errors.Is(err, storage.ErrInvalidBinding) {
			return nil, ErrInvalidBinding
		}
		return nil, fmt.Errorf("failed to get upstream tokens: %w", err)
	}

	// Defense in depth: some storage implementations may return tokens
	// without checking expiry (the interface does not require it).
	if !tokens.ExpiresAt.IsZero() && tokens.IsExpired(time.Now()) {
		return s.refreshOrFail(ctx, sessionID, providerName, tokens)
	}

	return &UpstreamCredential{
		AccessToken: tokens.AccessToken,
		Status:      StatusValid,
	}, nil
}

// GetAllValidTokens returns credential state for all upstream providers in a
// session. Expired tokens are refreshed transparently; if refresh fails, the
// provider remains in the result with a non-valid status so downstream authz can
// produce an explicit re-authentication error instead of silently dropping it.
func (s *InProcessService) GetAllValidTokens(ctx context.Context, sessionID string) (map[string]UpstreamCredential, error) {
	allTokens, err := s.storage.GetAllUpstreamTokens(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("bulk read upstream tokens: %w", err)
	}

	if len(allTokens) == 0 {
		return map[string]UpstreamCredential{}, nil
	}

	result := make(map[string]UpstreamCredential, len(allTokens))
	// TODO(auth): Refresh providers in parallel using errgroup to avoid
	// worst-case latency of N * refreshTimeout when multiple providers need refresh.
	for providerName, tokens := range allTokens {
		if tokens == nil {
			continue
		}

		// If token is not expired, use it directly.
		if tokens.ExpiresAt.IsZero() || !tokens.IsExpired(time.Now()) {
			result[providerName] = UpstreamCredential{
				AccessToken: tokens.AccessToken,
				Status:      StatusValid,
			}
			continue
		}

		// Token is expired — attempt refresh.
		refreshed, refreshErr := s.refreshOrFail(ctx, sessionID, providerName, tokens)
		if refreshErr != nil {
			status := statusFromError(refreshErr)
			slog.WarnContext(ctx, "provider has unrefreshable expired upstream token",
				"session_id", sessionID,
				"provider", providerName,
				"status", status,
				"error", refreshErr,
			)
			result[providerName] = UpstreamCredential{Status: status}
			continue
		}
		result[providerName] = *refreshed
	}

	return result, nil
}

// refreshOrFail attempts a singleflight-deduplicated refresh and maps errors
// to the service's sentinel errors.
func (s *InProcessService) refreshOrFail(
	ctx context.Context,
	sessionID string,
	providerName string,
	expired *storage.UpstreamTokens,
) (*UpstreamCredential, error) {
	if expired.RefreshToken == "" {
		return nil, ErrNoRefreshToken
	}

	if s.refresher == nil {
		slog.Debug("token refresher not configured, cannot refresh upstream tokens",
			"session_id", sessionID,
			"provider", providerName,
		)
		return nil, ErrNoRefreshToken
	}

	result, err, _ := s.sfGroup.Do(sessionID+":"+providerName, func() (any, error) {
		// Detach from the triggering request's context so that if the first
		// caller disconnects, the refresh still completes for waiting callers.
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		defer cancel()

		refreshed, refreshErr := s.refresher.RefreshAndStore(refreshCtx, sessionID, expired)
		if refreshErr != nil {
			return nil, refreshErr
		}
		return refreshed, nil
	})
	if err != nil {
		slog.Warn("upstream token refresh failed",
			"session_id", sessionID,
			"provider", providerName,
			"error", err,
		)
		return nil, fmt.Errorf("%w: %w", ErrRefreshFailed, err)
	}

	refreshed, ok := result.(*storage.UpstreamTokens)
	if !ok || refreshed == nil {
		return nil, ErrRefreshFailed
	}

	return &UpstreamCredential{
		AccessToken: refreshed.AccessToken,
		Status:      StatusValid,
	}, nil
}

func statusFromError(err error) UpstreamCredentialStatus {
	switch {
	case errors.Is(err, ErrNoRefreshToken):
		return StatusNoRefreshToken
	case errors.Is(err, ErrInvalidBinding):
		return StatusInvalidBinding
	case errors.Is(err, ErrRefreshFailed):
		return StatusRefreshFailed
	default:
		return StatusRefreshFailed
	}
}
