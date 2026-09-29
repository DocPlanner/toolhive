// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	mcpv1beta1 "github.com/stacklok/toolhive/cmd/thv-operator/api/v1beta1"
)

// newMinimalMCPServer creates a minimal MCPServer with the given name and optional
// AuthzConfigRef for CEL validation testing.
func newMinimalMCPServer(name string, authz *mcpv1beta1.AuthzConfigRef) *mcpv1beta1.MCPServer {
	return &mcpv1beta1.MCPServer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: mcpv1beta1.MCPServerSpec{
			Image:       "example/mcp-server:latest",
			AuthzConfig: authz,
		},
	}
}

var _ = Describe("CEL Validation for AuthzConfigRef", Label("k8s", "cel", "validation"), func() {
	Context("AuthzConfigRef CEL validation", func() {
		Context("type=configMap", func() {
			It("should reject when configMap field is missing", func() {
				server := newMinimalMCPServer("authz-cm-missing", &mcpv1beta1.AuthzConfigRef{
					Type: "configMap",
				})
				err := k8sClient.Create(ctx, server)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("configMap must be set when type is 'configMap'"))
			})

			It("should reject when inline field is also set", func() {
				server := newMinimalMCPServer("authz-cm-with-inline", &mcpv1beta1.AuthzConfigRef{
					Type: "configMap",
					ConfigMap: &mcpv1beta1.ConfigMapAuthzRef{
						Name: "test-cm",
					},
					Inline: &mcpv1beta1.InlineAuthzConfig{
						Policies: []string{"permit(principal, action, resource);"},
					},
				})
				err := k8sClient.Create(ctx, server)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("inline must be set when type is 'inline'"))
			})

			It("should accept when only configMap field is set", func() {
				server := newMinimalMCPServer("authz-cm-valid", &mcpv1beta1.AuthzConfigRef{
					Type: "configMap",
					ConfigMap: &mcpv1beta1.ConfigMapAuthzRef{
						Name: "test-cm",
					},
				})
				err := k8sClient.Create(ctx, server)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("type=inline", func() {
			It("should reject when inline field is missing", func() {
				server := newMinimalMCPServer("authz-inline-missing", &mcpv1beta1.AuthzConfigRef{
					Type: "inline",
				})
				err := k8sClient.Create(ctx, server)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("inline must be set when type is 'inline'"))
			})

			It("should reject when configMap field is also set", func() {
				server := newMinimalMCPServer("authz-inline-with-cm", &mcpv1beta1.AuthzConfigRef{
					Type: "inline",
					Inline: &mcpv1beta1.InlineAuthzConfig{
						Policies: []string{"permit(principal, action, resource);"},
					},
					ConfigMap: &mcpv1beta1.ConfigMapAuthzRef{
						Name: "test-cm",
					},
				})
				err := k8sClient.Create(ctx, server)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("configMap must be set when type is 'configMap'"))
			})

			It("should accept when only inline field is set", func() {
				server := newMinimalMCPServer("authz-inline-valid", &mcpv1beta1.AuthzConfigRef{
					Type: "inline",
					Inline: &mcpv1beta1.InlineAuthzConfig{
						Policies: []string{"permit(principal, action, resource);"},
					},
				})
				err := k8sClient.Create(ctx, server)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Context("AuthzConfigRef multi-violation CEL validation", func() {
		It("should report both missing-configMap and extra-inline when type=configMap but only inline is set", func() {
			server := newMinimalMCPServer("authz-cm-only-inline", &mcpv1beta1.AuthzConfigRef{
				Type: "configMap",
				Inline: &mcpv1beta1.InlineAuthzConfig{
					Policies: []string{"permit(principal, action, resource);"},
				},
			})
			err := k8sClient.Create(ctx, server)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(And(
				ContainSubstring("configMap must be set when type is 'configMap'"),
				ContainSubstring("inline must be set when type is 'inline'"),
			))
		})
	})

	Context("groupRef transition shim", func() {
		createRaw := func(name string, groupRef any) error {
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "toolhive.stacklok.dev/v1beta1",
				"kind":       "MCPServer",
				"metadata":   map[string]any{"name": name, "namespace": "default"},
				"spec":       map[string]any{"image": "example/mcp-server:latest", "groupRef": groupRef},
			}}
			return k8sClient.Create(ctx, obj)
		}

		It("should accept and decode the legacy string form", func() {
			Expect(createRaw("groupref-string", "platform")).To(Succeed())

			server := &mcpv1beta1.MCPServer{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "groupref-string", Namespace: "default"}, server)).To(Succeed())
			Expect(server.Spec.GroupRef.GetName()).To(Equal("platform"))
		})

		It("should accept the object form", func() {
			server := newMinimalMCPServer("groupref-object", nil)
			server.Spec.GroupRef = &mcpv1beta1.MCPGroupRef{Name: "platform"}
			Expect(k8sClient.Create(ctx, server)).To(Succeed())

			fetched := &mcpv1beta1.MCPServer{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "groupref-object", Namespace: "default"}, fetched)).To(Succeed())
			Expect(fetched.Spec.GroupRef.GetName()).To(Equal("platform"))
		})

		It("should accept the legacy string form through v1alpha1", func() {
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "toolhive.stacklok.dev/v1alpha1",
				"kind":       "MCPServer",
				"metadata":   map[string]any{"name": "groupref-string-v1alpha1", "namespace": "default"},
				"spec":       map[string]any{"image": "example/mcp-server:latest", "groupRef": "platform"},
			}}
			Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		})

		It("should decode an unexpected groupRef shape to an empty name without failing", func() {
			Expect(createRaw("groupref-number", int64(42))).To(Succeed())

			list := &mcpv1beta1.MCPServerList{}
			Expect(k8sClient.List(ctx, list)).To(Succeed())
			server := &mcpv1beta1.MCPServer{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "groupref-number", Namespace: "default"}, server)).To(Succeed())
			Expect(server.Spec.GroupRef.GetName()).To(BeEmpty())
		})
	})

	Context("SecretRef schema validation", func() {
		It("should accept multiple keys from the same Kubernetes Secret", func() {
			server := newMinimalMCPServer("secret-ref-multi-key", nil)
			server.Spec.Secrets = []mcpv1beta1.SecretRef{
				{Name: "shared-credentials", Key: "username", TargetEnvName: "API_USERNAME"},
				{Name: "shared-credentials", Key: "password", TargetEnvName: "API_PASSWORD"},
			}

			err := k8sClient.Create(ctx, server)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should still reject an exact duplicate secret reference", func() {
			server := newMinimalMCPServer("secret-ref-duplicate-key", nil)
			server.Spec.Secrets = []mcpv1beta1.SecretRef{
				{Name: "shared-credentials", Key: "token", TargetEnvName: "API_TOKEN"},
				{Name: "shared-credentials", Key: "token", TargetEnvName: "SECOND_API_TOKEN"},
			}

			err := k8sClient.Create(ctx, server)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Duplicate value"))
		})
	})
})
