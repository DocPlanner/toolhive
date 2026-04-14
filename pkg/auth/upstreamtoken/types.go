// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamtoken provides a service for managing upstream IDP token
// lifecycle, including transparent refresh of expired access tokens.
package upstreamtoken

//go:generate go run go.uber.org/mock/mockgen -destination=mocks/mock_token_reader.go -package=mocks github.com/stacklok/toolhive/pkg/auth/upstreamtoken TokenReader

import "context"

// TokenSessionIDClaimKey is the JWT claim key for the token session ID.
// This links JWT access tokens to stored upstream IDP tokens.
// We use "tsid" instead of "sid" to avoid confusion with OIDC session management
// which defines "sid" for different purposes (RFC 7519, OIDC Session Management).
const TokenSessionIDClaimKey = "tsid"

// UpstreamCredentialStatus describes the current state of an upstream credential.
// StatusValid means AccessToken is present and usable. The other statuses mean
// the provider still exists in session storage, but the caller must not treat the
// access token as usable without user re-authentication.
type UpstreamCredentialStatus string

const (
	// StatusValid indicates the access token is present and usable.
	StatusValid UpstreamCredentialStatus = "valid"
	// StatusNoRefreshToken indicates the access token expired and no refresh token exists.
	StatusNoRefreshToken UpstreamCredentialStatus = "no_refresh_token"
	// StatusRefreshFailed indicates the refresh token existed, but refresh failed.
	StatusRefreshFailed UpstreamCredentialStatus = "refresh_failed"
	// StatusInvalidBinding indicates the stored upstream token no longer matches
	// the authenticated session (subject/client mismatch).
	StatusInvalidBinding UpstreamCredentialStatus = "invalid_binding"
)

// RequiresReauthentication reports whether the credential state means the caller
// must perform a fresh upstream login to recover.
func (s UpstreamCredentialStatus) RequiresReauthentication() bool {
	switch s {
	case StatusNoRefreshToken, StatusRefreshFailed, StatusInvalidBinding:
		return true
	default:
		return false
	}
}

// UpstreamCredential is the opaque result of GetValidTokens/GetAllValidTokens.
// The caller only needs the access token for upstream injection, but the status
// is preserved so authz can distinguish between a missing provider and an
// upstream session that now requires re-authentication.
type UpstreamCredential struct {
	AccessToken string
	Status      UpstreamCredentialStatus
}

// TokenReader retrieves upstream provider access tokens for a session.
// This narrow interface decouples the auth middleware from storage internals.
type TokenReader interface {
	// GetAllValidTokens returns the current upstream credential state for all
	// providers in a session. Expired access tokens are refreshed transparently
	// when possible. If refresh fails, the provider remains in the result with a
	// non-valid status so downstream middleware can surface a precise error
	// instead of silently acting as if the provider never existed.
	// Returns an empty map (not error) for unknown sessions.
	GetAllValidTokens(ctx context.Context, sessionID string) (map[string]UpstreamCredential, error)
}

// Service owns the upstream token lifecycle: read, refresh, error handling.
type Service interface {
	// GetValidTokens returns a valid upstream credential for a session and provider.
	// It transparently refreshes expired access tokens using the refresh token.
	// The providerName identifies which upstream provider's tokens to retrieve.
	//
	// Returns:
	//   - *UpstreamCredential on success
	//   - ErrSessionNotFound if no upstream tokens exist for the session/provider
	//   - ErrNoRefreshToken if the access token is expired and no refresh token is available
	//   - ErrRefreshFailed if the refresh attempt fails (e.g., revoked refresh token)
	GetValidTokens(ctx context.Context, sessionID, providerName string) (*UpstreamCredential, error)
}
