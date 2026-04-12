// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/stacklok/toolhive/cmd/thv-operator/api/v1alpha1"
	ctrlutil "github.com/stacklok/toolhive/cmd/thv-operator/pkg/controllerutil"
	vmcpconfig "github.com/stacklok/toolhive/pkg/vmcp/config"
)

func TestDeploymentForMCPServer_WithRedisCredentials(t *testing.T) {
	t.Parallel()

	usernameRef := &mcpv1alpha1.SecretKeyRef{Name: "redis-session-user", Key: "username"}
	passwordRef := &mcpv1alpha1.SecretKeyRef{Name: "redis-secret", Key: "password"}

	mcpServer := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mcp-redis",
			Namespace: "default",
		},
		Spec: mcpv1alpha1.MCPServerSpec{
			Image:     "test-image:latest",
			Transport: "sse",
			ProxyPort: 8080,
			SessionStorage: &mcpv1alpha1.SessionStorageConfig{
				Provider:    mcpv1alpha1.SessionStorageProviderRedis,
				Address:     "redis:6379",
				UsernameRef: usernameRef,
				PasswordRef: passwordRef,
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, mcpv1alpha1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mcpServer).
		WithStatusSubresource(&mcpv1alpha1.MCPServer{}).
		Build()

	r := &MCPServerReconciler{
		Client:           fakeClient,
		Scheme:           scheme,
		PlatformDetector: ctrlutil.NewSharedPlatformDetector(),
	}

	deployment := r.deploymentForMCPServer(t.Context(), mcpServer, "test-checksum")
	require.NotNil(t, deployment)
	require.Len(t, deployment.Spec.Template.Spec.Containers, 1)

	var usernameEnvVarFound bool
	var passwordEnvVarFound bool
	for _, envVar := range deployment.Spec.Template.Spec.Containers[0].Env {
		switch envVar.Name {
		case vmcpconfig.RedisUsernameEnvVar:
			usernameEnvVarFound = true
			assert.Empty(t, envVar.Value)
			require.NotNil(t, envVar.ValueFrom)
			require.NotNil(t, envVar.ValueFrom.SecretKeyRef)
			assert.Equal(t, usernameRef.Name, envVar.ValueFrom.SecretKeyRef.Name)
			assert.Equal(t, usernameRef.Key, envVar.ValueFrom.SecretKeyRef.Key)
		case vmcpconfig.RedisPasswordEnvVar:
			passwordEnvVarFound = true
			assert.Empty(t, envVar.Value)
			require.NotNil(t, envVar.ValueFrom)
			require.NotNil(t, envVar.ValueFrom.SecretKeyRef)
			assert.Equal(t, passwordRef.Name, envVar.ValueFrom.SecretKeyRef.Name)
			assert.Equal(t, passwordRef.Key, envVar.ValueFrom.SecretKeyRef.Key)
		}
	}

	assert.True(t, usernameEnvVarFound, "deployment should contain redis username env var")
	assert.True(t, passwordEnvVarFound, "deployment should contain redis password env var")
}

func TestBuildSessionRedisCredentialEnvVars(t *testing.T) {
	t.Parallel()

	r := &MCPServerReconciler{}
	usernameRef := &mcpv1alpha1.SecretKeyRef{Name: "redis-session-user", Key: "username"}
	passwordRef := &mcpv1alpha1.SecretKeyRef{Name: "redis-secret", Key: "password"}

	tests := []struct {
		name            string
		storage         *mcpv1alpha1.SessionStorageConfig
		expectEnvVarNum int
	}{
		{
			name:            "nil sessionStorage produces no env var",
			storage:         nil,
			expectEnvVarNum: 0,
		},
		{
			name:            "memory provider produces no env var",
			storage:         &mcpv1alpha1.SessionStorageConfig{Provider: "memory"},
			expectEnvVarNum: 0,
		},
		{
			name:            "redis without credentials produces no env var",
			storage:         &mcpv1alpha1.SessionStorageConfig{Provider: mcpv1alpha1.SessionStorageProviderRedis, Address: "redis:6379"},
			expectEnvVarNum: 0,
		},
		{
			name:            "redis with passwordRef produces redis password env var",
			storage:         &mcpv1alpha1.SessionStorageConfig{Provider: mcpv1alpha1.SessionStorageProviderRedis, Address: "redis:6379", PasswordRef: passwordRef},
			expectEnvVarNum: 1,
		},
		{
			name: "redis with usernameRef and passwordRef produces both redis credential env vars",
			storage: &mcpv1alpha1.SessionStorageConfig{
				Provider:    mcpv1alpha1.SessionStorageProviderRedis,
				Address:     "redis:6379",
				UsernameRef: usernameRef,
				PasswordRef: passwordRef,
			},
			expectEnvVarNum: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mcpServer := &mcpv1alpha1.MCPServer{
				ObjectMeta: metav1.ObjectMeta{Name: "test-mcp", Namespace: "default"},
				Spec:       mcpv1alpha1.MCPServerSpec{SessionStorage: tc.storage},
			}

			env := r.buildSessionRedisCredentialEnvVars(mcpServer)
			require.Len(t, env, tc.expectEnvVarNum)

			if tc.expectEnvVarNum == 0 {
				return
			}

			assert.Equal(t, vmcpconfig.RedisPasswordEnvVar, env[len(env)-1].Name)
			assert.Empty(t, env[len(env)-1].Value)
			require.NotNil(t, env[len(env)-1].ValueFrom)
			require.NotNil(t, env[len(env)-1].ValueFrom.SecretKeyRef)
			assert.Equal(t, passwordRef.Name, env[len(env)-1].ValueFrom.SecretKeyRef.Name)
			assert.Equal(t, passwordRef.Key, env[len(env)-1].ValueFrom.SecretKeyRef.Key)

			if tc.expectEnvVarNum == 2 {
				assert.Equal(t, vmcpconfig.RedisUsernameEnvVar, env[0].Name)
				assert.Empty(t, env[0].Value)
				require.NotNil(t, env[0].ValueFrom)
				require.NotNil(t, env[0].ValueFrom.SecretKeyRef)
				assert.Equal(t, usernameRef.Name, env[0].ValueFrom.SecretKeyRef.Name)
				assert.Equal(t, usernameRef.Key, env[0].ValueFrom.SecretKeyRef.Key)
			}
		})
	}
}
