// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"errors"
	"net/http"

	"github.com/stacklok/toolhive/pkg/authz/authorizers"
)

const upstreamAuthRequiredDescription = "upstream token is no longer valid; re-authentication required"

var errForbiddenAuthorization = errors.New("forbidden authorization request")

type forbiddenAuthorizationError struct {
	message string
}

func (e *forbiddenAuthorizationError) Error() string {
	if e == nil || e.message == "" {
		return "Unauthorized"
	}
	return e.message
}

func (e *forbiddenAuthorizationError) Unwrap() error {
	return errForbiddenAuthorization
}

func newForbiddenAuthorizationError(message string) error {
	return &forbiddenAuthorizationError{message: message}
}

func isForbiddenAuthorizationError(err error) bool {
	return errors.Is(err, errForbiddenAuthorization)
}

func bearerInvalidTokenChallenge(description string) string {
	return `Bearer error="invalid_token", error_description="` + description + `"`
}

func classifyAuthorizationError(err error) (httpStatus int, rpcCode int, message string, wwwAuthenticate string) {
	if authorizers.IsUpstreamAuthenticationRequired(err) {
		return http.StatusUnauthorized,
			http.StatusUnauthorized,
			upstreamAuthRequiredDescription,
			bearerInvalidTokenChallenge(upstreamAuthRequiredDescription)
	}
	if isForbiddenAuthorizationError(err) {
		return http.StatusForbidden, http.StatusForbidden, err.Error(), ""
	}
	if err != nil {
		return http.StatusInternalServerError, http.StatusInternalServerError, err.Error(), ""
	}
	return http.StatusForbidden, http.StatusForbidden, "Unauthorized", ""
}
