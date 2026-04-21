// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

type clusterRoleManifest struct {
	Rules []rbacv1.PolicyRule `yaml:"rules"`
}

func TestMCPServerControllerManagerRBACMarkerIncludesPodsDelete(t *testing.T) {
	t.Parallel()

	controllerPath := filepath.Join("mcpserver_controller.go")
	content, err := os.ReadFile(controllerPath)
	require.NoError(t, err)

	assert.Contains(t,
		string(content),
		`// +kubebuilder:rbac:groups="",resources=pods,verbs=delete;get;list;watch`,
		"manager RBAC marker must include pods.delete so the operator can grant proxyrunner cleanup permissions")
}

func TestOperatorClusterRoleManifestIncludesPodsDelete(t *testing.T) {
	t.Parallel()

	manifestPath := filepath.Join("..", "..", "..", "deploy", "charts", "operator", "templates", "clusterrole", "role.yaml")
	content, err := os.ReadFile(manifestPath)
	require.NoError(t, err)

	var manifest clusterRoleManifest
	require.NoError(t, yaml.Unmarshal(content, &manifest))

	for _, rule := range manifest.Rules {
		if len(rule.APIGroups) == 1 && rule.APIGroups[0] == "" && len(rule.Resources) == 1 && rule.Resources[0] == "pods" {
			assert.Contains(t, rule.Verbs, "delete", "operator ClusterRole must include pods.delete")
			return
		}
	}

	t.Fatalf("pods rule not found in %s", strings.TrimPrefix(manifestPath, "./"))
}
