// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	mcpv1beta1 "github.com/stacklok/toolhive/cmd/thv-operator/api/v1beta1"
	"github.com/stacklok/toolhive/cmd/thv-operator/api/v1beta1/v1beta1test"
	"github.com/stacklok/toolhive/cmd/thv-operator/internal/testutil"
	"github.com/stacklok/toolhive/pkg/container/kubernetes"
)

// TestReconcileKeepsOwnedStatefulSet guards against a regression of fork patch
// 3a8e50139: since upstream #6379 the MCPServer owns the workload StatefulSet
// named after it, so the reconcile loop must never delete that StatefulSet.
func TestReconcileKeepsOwnedStatefulSet(t *testing.T) {
	t.Parallel()

	const name = "owned-sts"
	namespace := testNamespaceDefault

	testScheme := testutil.NewScheme(t)
	mcpServer := v1beta1test.NewMCPServer(name, namespace, v1beta1test.WithTransport("streamable-http"))
	mcpServer.UID = types.UID("owned-sts-uid")

	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labelsForMCPServer(name),
		},
	}
	require.NoError(t, controllerutil.SetControllerReference(mcpServer, statefulSet, testScheme))

	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithObjects(mcpServer, statefulSet, ownedStatefulSetTestDeployment(name, namespace), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("mcp-%s-proxy", name), Namespace: namespace},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
		}).
		WithStatusSubresource(&mcpv1beta1.MCPServer{}).
		Build()

	reconciler := newTestMCPServerReconciler(fakeClient, testScheme, kubernetes.PlatformKubernetes)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: namespace}}

	// Reconcile more than once: the old cleanup deleted and then requeued.
	for range 3 {
		_, err := reconciler.Reconcile(t.Context(), req)
		require.NoError(t, err)
	}

	require.NoError(t, fakeClient.Get(t.Context(), req.NamespacedName, &appsv1.StatefulSet{}),
		"MCPServer-owned StatefulSet %q must survive the reconcile loop", name)
}

func ownedStatefulSetTestDeployment(name, namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{MatchLabels: labelsForMCPServer(name)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labelsForMCPServer(name)},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "mcp", Image: "test-image:latest"}},
				},
			},
		},
	}
}
