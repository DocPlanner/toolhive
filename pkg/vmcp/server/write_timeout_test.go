// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEffectiveWriteTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{name: "unset uses default", configured: 0, want: defaultWriteTimeout},
		{name: "below default is raised", configured: defaultWriteTimeout - time.Second, want: defaultWriteTimeout},
		{name: "above default wins", configured: 130 * time.Second, want: 130 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, effectiveWriteTimeout(tt.configured))
		})
	}
}
