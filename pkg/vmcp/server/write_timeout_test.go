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

	assert.Equal(t, defaultWriteTimeout, effectiveWriteTimeout(0))
	assert.Equal(t, defaultWriteTimeout, effectiveWriteTimeout(30*time.Second))
	assert.Equal(t, 130*time.Second, effectiveWriteTimeout(130*time.Second))
}
