// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"net/http"

	healthcontext "github.com/stacklok/toolhive/pkg/vmcp/health/context"
)

const (
	// ProbeHeader marks wire-level health probe requests between vMCPs so the
	// receiving spoke can skip heavyweight session creation.
	ProbeHeader = healthcontext.ProbeHeader

	// ProbeHeaderValue is the canonical truthy value for ProbeHeader.
	ProbeHeaderValue = healthcontext.ProbeHeaderValue
)

// HasProbeHeader reports whether the incoming HTTP request is marked as an
// inter-vMCP health probe.
func HasProbeHeader(r *http.Request) bool {
	if r == nil {
		return false
	}
	return r.Header.Get(ProbeHeader) == ProbeHeaderValue
}
