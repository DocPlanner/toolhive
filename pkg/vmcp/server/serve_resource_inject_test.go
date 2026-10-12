// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
)

// fakeSDKResourceSession adds a per-session resource store to fakeSDKSession.
type fakeSDKResourceSession struct {
	fakeSDKSession
	resources map[string]server.ServerResource
}

var _ server.SessionWithResources = (*fakeSDKResourceSession)(nil)

func (f *fakeSDKResourceSession) GetSessionResources() map[string]server.ServerResource {
	return f.resources
}

func (f *fakeSDKResourceSession) SetSessionResources(r map[string]server.ServerResource) {
	f.resources = r
}

// TestServeLazyInjectsResourcesForRehydratedSession covers a session registered on
// another pod: its SDK session on this pod has an empty resource store, which the
// before-list/before-read resource hooks fill from the core.
func TestServeLazyInjectsResourcesForRehydratedSession(t *testing.T) {
	t.Parallel()

	const uri = "file:///doc.txt"
	ctrl := gomock.NewController(t)
	factory, _ := newToolSessionFactory(t, ctrl, nil)
	fc := &fakeCore{resources: []vmcp.Resource{{URI: uri, Name: "doc"}}}
	srv, err := Serve(context.Background(), fc, &ServerConfig{
		SessionTTL:           time.Minute,
		SessionManagerConfig: &sessionmanager.FactoryConfig{Base: factory},
		BackendRegistry:      vmcp.NewImmutableRegistry([]vmcp.Backend{}),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	preexisting := map[string]server.ServerResource{"file:///other": {Resource: mcp.Resource{URI: "file:///other"}}}
	tests := []struct {
		name      string
		ctx       context.Context
		resources map[string]server.ServerResource
		wantURI   bool
	}{
		{"empty store is filled from the core", context.Background(), map[string]server.ServerResource{}, true},
		{"populated store is left unchanged", context.Background(), preexisting, false},
		{"health probe gets no resources", context.WithValue(context.Background(), peerProbeKey{}, true), map[string]server.ServerResource{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sess := &fakeSDKResourceSession{fakeSDKSession: fakeSDKSession{id: "s"}, resources: tc.resources}
			srv.lazyInjectSessionResources(srv.mcpServer.WithContext(tc.ctx, sess))
			_, got := sess.resources[uri]
			assert.Equal(t, tc.wantURI, got)
		})
	}
}
