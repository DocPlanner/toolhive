// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/ory/fosite"
	"github.com/stacklok/toolhive/pkg/authserver/server"
	"github.com/stacklok/toolhive/pkg/authserver/server/session"
)

// TokenHandler handles POST /oauth/token requests.
// It processes token requests using fosite's access request/response flow.
func (h *Handler) TokenHandler(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// Create a placeholder session for the token request.
	// All parameters are empty because Fosite's NewAccessRequest will:
	// 1. Extract the authorization code from the request
	// 2. Retrieve the stored authorize session from storage (created in CallbackHandler)
	// 3. Use the stored session's claims (subject, tsid, client_id) for token generation
	// This session object is only used as a deserialization template.
	sess := session.New("", "", "", session.UserClaims{})

	// Parse and validate the access request
	accessRequest, err := h.provider.NewAccessRequest(ctx, req, sess)
	if err != nil {
		logTokenEndpointError("request_validation", req, err)
		h.provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// RFC 8707: Handle resource parameter for audience claim.
	// The resource parameter allows clients to specify which protected resource (MCP server)
	// the token is intended for. This value becomes the "aud" claim in the JWT.
	//
	// Note: RFC 8707 allows multiple resource parameters, but we explicitly reject them
	// for security reasons (simpler audience model, clearer token scope).
	resources := accessRequest.GetRequestForm()["resource"]
	if len(resources) > 1 {
		slog.Debug("multiple resource parameters not supported", //nolint:gosec // G706: count is an integer
			"count", len(resources),
		)
		h.provider.WriteAccessError(ctx, w, accessRequest,
			server.ErrInvalidTarget.WithHint("Multiple resource parameters are not supported"))
		return
	}
	switch {
	case len(resources) == 1:
		resource := resources[0]
		// Validate URI format per RFC 8707
		if err := server.ValidateAudienceURI(resource); err != nil {
			slog.Debug("invalid resource URI format", //nolint:gosec // G706: resource URI from token request
				"resource", resource,
				"error", err,
			)
			h.provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		// Validate against allowed audiences list
		if err := server.ValidateAudienceAllowed(resource, h.config.AllowedAudiences); err != nil {
			slog.Debug("resource not in allowed audiences", //nolint:gosec // G706: resource URI from token request
				"resource", resource,
				"error", err,
			)
			h.provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		slog.Debug("granting audience from resource parameter", //nolint:gosec // G706: resource URI from token request
			"resource", resource,
		)
		accessRequest.GrantAudience(resource)
	case len(h.config.AllowedAudiences) == 1:
		defaultAudience := h.config.AllowedAudiences[0]
		slog.Debug("granting default audience for token request without resource", //nolint:gosec // G706: configured audience URI
			"audience", defaultAudience,
		)
		accessRequest.GrantAudience(defaultAudience)
	case len(h.config.AllowedAudiences) > 1:
		slog.Debug("resource parameter required when multiple audiences are configured", //nolint:gosec // G706: count is an integer
			"count", len(h.config.AllowedAudiences),
		)
		h.provider.WriteAccessError(ctx, w, accessRequest,
			server.ErrInvalidTarget.WithHint("Token request must include resource when multiple audiences are configured"))
		return
	}

	// Generate the access response (tokens)
	response, err := h.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		logTokenEndpointError("response_generation", req, err)
		h.provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Write the token response
	h.provider.WriteAccessResponse(ctx, w, accessRequest, response)
}

func logTokenEndpointError(phase string, req *http.Request, err error) {
	oauthErr := fosite.ErrorToRFC6749Error(err)
	grantType := req.PostFormValue("grant_type")

	attrs := []any{
		"phase", phase,
		"error", err,
		"oauth_error", oauthErr.ErrorField,
	}
	if grantType != "" {
		attrs = append(attrs, "grant_type", grantType)
	}
	if clientID := req.PostFormValue("client_id"); clientID != "" {
		attrs = append(attrs, "client_id", clientID)
	}
	if oauthErr.HintField != "" {
		attrs = append(attrs, "oauth_hint", oauthErr.HintField)
	}
	if oauthErr.DebugField != "" {
		attrs = append(attrs, "oauth_debug", oauthErr.DebugField)
	}
	if grantType == "refresh_token" {
		attrs = append(attrs, "refresh_failure_classification", classifyRefreshTokenFailure(oauthErr))
	}

	slog.Error("token endpoint request failed", attrs...)
}

func classifyRefreshTokenFailure(err *fosite.RFC6749Error) string {
	if err == nil {
		return "unknown"
	}

	hint := strings.ToLower(err.HintField)
	switch {
	case strings.Contains(hint, "already used"):
		return "rotated_or_replayed"
	case strings.Contains(hint, "malformed or not valid"):
		return "storage_lookup_miss"
	case strings.Contains(hint, "expired"):
		return "expired"
	case strings.Contains(hint, "does not match the id during the initial token issuance"):
		return "client_mismatch"
	case strings.Contains(hint, "multiple concurrent requests"):
		return "concurrent_refresh_race"
	case strings.Contains(hint, "failed to refresh token"):
		return "refresh_rotation_retryable_failure"
	case err.ErrorField != "":
		return err.ErrorField
	default:
		return "unknown"
	}
}
