// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authorizers

import (
	"errors"
	"fmt"
)

var errUpstreamAuthenticationRequired = errors.New("upstream authentication required")

// UpstreamAuthenticationRequiredError indicates that authorization depends on
// an upstream identity provider token that is no longer usable and must be
// re-established via a fresh login.
type UpstreamAuthenticationRequiredError struct {
	Provider string
	Reason   string
}

func (e *UpstreamAuthenticationRequiredError) Error() string {
	if e == nil {
		return errUpstreamAuthenticationRequired.Error()
	}
	if e.Provider == "" && e.Reason == "" {
		return errUpstreamAuthenticationRequired.Error()
	}
	if e.Reason == "" {
		return fmt.Sprintf("%s for provider %q", errUpstreamAuthenticationRequired, e.Provider)
	}
	if e.Provider == "" {
		return fmt.Sprintf("%s: %s", errUpstreamAuthenticationRequired, e.Reason)
	}
	return fmt.Sprintf("%s for provider %q: %s", errUpstreamAuthenticationRequired, e.Provider, e.Reason)
}

func (e *UpstreamAuthenticationRequiredError) Unwrap() error {
	return errUpstreamAuthenticationRequired
}

// NewUpstreamAuthenticationRequiredError creates a typed authorization error
// that callers can translate into a 401 re-authentication challenge.
func NewUpstreamAuthenticationRequiredError(provider, reason string) error {
	return &UpstreamAuthenticationRequiredError{
		Provider: provider,
		Reason:   reason,
	}
}

// IsUpstreamAuthenticationRequired reports whether err indicates an upstream
// provider session that now requires re-authentication.
func IsUpstreamAuthenticationRequired(err error) bool {
	return errors.Is(err, errUpstreamAuthenticationRequired)
}
