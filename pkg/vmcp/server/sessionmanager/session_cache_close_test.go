// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sessionmanager

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive/pkg/auth"
	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessionfactorymocks "github.com/stacklok/toolhive/pkg/vmcp/session/mocks"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
	sessionmocks "github.com/stacklok/toolhive/pkg/vmcp/session/types/mocks"
)

// newBoundSessionManager returns a Manager whose factory builds one bound
// (Phase 2) session and records when that session is closed.
func newBoundSessionManager(
	t *testing.T, idleTTL time.Duration,
) (*Manager, transportsession.DataStorage, *atomic.Bool) {
	t.Helper()
	ctrl := gomock.NewController(t)
	closed := &atomic.Bool{}
	meta := map[string]string{sessiontypes.MetadataKeyIdentityBinding: "unauthenticated"}

	factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
	factory.EXPECT().
		MakeSessionWithID(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, id string, _ *auth.Identity, _ []*vmcp.Backend, _ vmcpsession.ListChangedSink) (vmcpsession.MultiSession, error) {
			sess := sessionmocks.NewMockMultiSession(ctrl)
			sess.EXPECT().ID().Return(id).AnyTimes()
			sess.EXPECT().GetMetadata().Return(meta).AnyTimes()
			sess.EXPECT().Close().DoAndReturn(func() error {
				closed.Store(true)
				return nil
			}).Times(1)
			return sess, nil
		}).Times(1)

	storage := newTestSessionDataStorage(t)
	sm, cleanup, err := New(storage, &FactoryConfig{Base: factory, IdleTTL: idleTTL}, newFakeRegistry())
	require.NoError(t, err)
	t.Cleanup(func() { _ = cleanup(context.Background()) })
	return sm, storage, closed
}

func TestTerminate_ClosesCachedSessionWhenStorageIsAlreadyGone(t *testing.T) {
	t.Parallel()

	sm, storage, closed := newBoundSessionManager(t, 0)
	sessionID := sm.Generate()
	_, err := sm.CreateSession(context.Background(), sessionID, nil)
	require.NoError(t, err)

	// Another replica served the DELETE (or the storage TTL expired).
	require.NoError(t, storage.Delete(context.Background(), sessionID))

	_, err = sm.Terminate(sessionID)
	require.NoError(t, err)
	assert.True(t, closed.Load(), "the cached copy must be closed even when storage has no record")
}

func TestIdleSweep_ClosesIdleSessionWithoutTouchingStorage(t *testing.T) {
	t.Parallel()

	sm, storage, closed := newBoundSessionManager(t, 50*time.Millisecond)
	sessionID := sm.Generate()
	_, err := sm.CreateSession(context.Background(), sessionID, nil)
	require.NoError(t, err)

	require.Eventually(t, closed.Load, 5*time.Second, 10*time.Millisecond,
		"the idle sweep must close the cached session")

	// The sweep is node-local: the stored record stays for other replicas.
	_, err = storage.Load(context.Background(), sessionID)
	assert.NoError(t, err)
}
