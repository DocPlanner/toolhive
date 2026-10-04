// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sessionmanager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/vmcp"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessionfactorymocks "github.com/stacklok/toolhive/pkg/vmcp/session/mocks"
)

func TestSessionManager_RestoreRunsWithTheCallersIdentityAndOutlivesItsCancellation(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	caller := &auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: tokenlessRestoreSubject}, Token: "live-token"}
	restored := newMetadataTestSession(ctrl, fullStoredMetadata(), caller)

	var restoreIdentity *auth.Identity
	var restoreErr error
	factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
	factory.EXPECT().
		RestoreSession(gomock.Any(), tokenlessRestoreSessionID, gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _ map[string]string, _ []*vmcp.Backend) (vmcpsession.MultiSession, error) {
			restoreIdentity, _ = auth.IdentityFromContext(ctx)
			restoreErr = ctx.Err()
			return restored, nil
		}).Times(1)

	sm, storage := newTestSessionManager(t, factory, newFakeRegistry())
	_, err := storage.Create(context.Background(), tokenlessRestoreSessionID, fullStoredMetadata())
	require.NoError(t, err)

	requestCtx, cancel := context.WithCancel(auth.WithIdentity(context.Background(), caller))
	cancel()

	_, ok := sm.GetMultiSession(requestCtx, tokenlessRestoreSessionID)
	require.True(t, ok)
	assert.Same(t, caller, restoreIdentity)
	assert.NoError(t, restoreErr)
}
