// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcpv1alpha1 "github.com/stacklok/toolhive/cmd/thv-operator/api/v1alpha1"
	"github.com/stacklok/toolhive/pkg/container/kubernetes"
)

func TestMCPServerReconciler_cleanupLegacyMCPServerResources(t *testing.T) {
	t.Parallel()

	const (
		name      = "aws-mcp"
		namespace = testNamespaceDefault
	)

	scheme := createTestScheme()
	mcpServer := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	legacyLabels := labelsForMCPServer(name)
	legacyStatefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    legacyLabels,
		},
	}
	legacyHeadlessService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-" + name + "-headless",
			Namespace: namespace,
			Labels:    legacyLabels,
		},
	}
	legacyService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mcp-" + name,
			Namespace: namespace,
			Labels:    legacyLabels,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mcpServer, legacyStatefulSet, legacyHeadlessService, legacyService).
		Build()

	reconciler := newTestMCPServerReconciler(fakeClient, scheme, kubernetes.PlatformKubernetes)
	deleted, err := reconciler.cleanupLegacyMCPServerResources(context.Background(), mcpServer)
	require.NoError(t, err)
	assert.True(t, deleted)

	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: namespace}, &appsv1.StatefulSet{})
	assert.True(t, apierrors.IsNotFound(err), "expected %s StatefulSet to be deleted", name)

	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "mcp-" + name + "-headless", Namespace: namespace}, &corev1.Service{})
	assert.True(t, apierrors.IsNotFound(err), "expected legacy headless Service to be deleted")

	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "mcp-" + name, Namespace: namespace}, &corev1.Service{})
	assert.True(t, apierrors.IsNotFound(err), "expected legacy Service to be deleted")
}

func TestMCPServerReconciler_cleanupLegacyMCPServerResources_SkipsForeignObjects(t *testing.T) {
	t.Parallel()

	const (
		name      = "aws-mcp"
		namespace = testNamespaceDefault
	)

	scheme := createTestScheme()
	mcpServer := &mcpv1alpha1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	foreignLabels := map[string]string{
		"app": "unrelated",
	}
	foreignStatefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    foreignLabels,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(mcpServer, foreignStatefulSet).
		Build()

	reconciler := newTestMCPServerReconciler(fakeClient, scheme, kubernetes.PlatformKubernetes)
	deleted, err := reconciler.cleanupLegacyMCPServerResources(context.Background(), mcpServer)
	require.NoError(t, err)
	assert.False(t, deleted)

	stillThere := &appsv1.StatefulSet{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{Name: name, Namespace: namespace}, stillThere)
	require.NoError(t, err)
}
