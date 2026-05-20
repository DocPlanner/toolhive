// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	authserverconfig "github.com/stacklok/toolhive/pkg/authserver"
	"github.com/stacklok/toolhive/pkg/vmcp/config"
)

func TestLoadAuthServerConfig(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when file does not exist", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		configPath := filepath.Join(dir, "vmcp-config.yaml")

		rc, err := loadAuthServerConfig(configPath)

		require.NoError(t, err)
		assert.Nil(t, rc)
	})

	t.Run("returns populated RunConfig for valid YAML", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		configPath := filepath.Join(dir, "vmcp-config.yaml")

		want := &authserverconfig.RunConfig{
			Issuer:        "https://test-issuer.example.com",
			SchemaVersion: "1",
		}

		data, err := yaml.Marshal(want)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "authserver-config.yaml"),
			data,
			0o600,
		))

		rc, err := loadAuthServerConfig(configPath)

		require.NoError(t, err)
		require.NotNil(t, rc)
		assert.Equal(t, "https://test-issuer.example.com", rc.Issuer)
		assert.Equal(t, "1", rc.SchemaVersion)
	})

	t.Run("returns error for invalid YAML", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		configPath := filepath.Join(dir, "vmcp-config.yaml")

		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "authserver-config.yaml"),
			[]byte(":::not valid yaml"),
			0o600,
		))

		rc, err := loadAuthServerConfig(configPath)

		require.Error(t, err)
		assert.Nil(t, rc)
		assert.Contains(t, err.Error(), "failed to parse")
	})

}

func TestResolveSessionOwnerAdvertiseURL(t *testing.T) {
	t.Parallel()

	t.Run("uses explicit URL when configured", func(t *testing.T) {
		t.Parallel()

		got := resolveSessionOwnerAdvertiseURL(" https://owner.example.com/mcp ", "10.0.0.12", 4483)
		assert.Equal(t, "https://owner.example.com/mcp", got)
	})

	t.Run("builds pod-local URL from pod IP", func(t *testing.T) {
		t.Parallel()

		got := resolveSessionOwnerAdvertiseURL("", "10.0.0.12", 4483)
		assert.Equal(t, "http://10.0.0.12:4483/mcp", got)
	})

	t.Run("returns empty string without explicit URL or pod IP", func(t *testing.T) {
		t.Parallel()

		got := resolveSessionOwnerAdvertiseURL("", "", 4483)
		assert.Empty(t, got)
	})
}

func TestBackendInitTimeoutFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
		want time.Duration
	}{
		{
			name: "returns zero for nil config",
			cfg:  nil,
			want: 0,
		},
		{
			name: "uses health check timeout when configured",
			cfg: &config.Config{
				Operational: &config.OperationalConfig{
					Timeouts: &config.TimeoutConfig{
						Default: config.Duration(60 * time.Second),
					},
					FailureHandling: &config.FailureHandlingConfig{
						HealthCheckTimeout: config.Duration(10 * time.Second),
					},
				},
			},
			want: 10 * time.Second,
		},
		{
			name: "falls back to default timeout",
			cfg: &config.Config{
				Operational: &config.OperationalConfig{
					Timeouts: &config.TimeoutConfig{
						Default: config.Duration(45 * time.Second),
					},
				},
			},
			want: 45 * time.Second,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := backendInitTimeoutFromConfig(tt.cfg)

			assert.Equal(t, tt.want, got)
		})
	}
}
