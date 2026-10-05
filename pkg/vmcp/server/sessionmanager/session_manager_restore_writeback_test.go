// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sessionmanager

import (
	"context"
	"errors"
	"sync"
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

// deleteBeforeUpdateStorage deletes the key on the first Update call,
// simulating a Terminate / TTL expiry racing with loadSession's write-back.
type deleteBeforeUpdateStorage struct {
	transportsession.DataStorage
	deleted bool
}

func (s *deleteBeforeUpdateStorage) Update(ctx context.Context, id string, metadata map[string]string) (bool, error) {
	if !s.deleted {
		s.deleted = true
		_ = s.Delete(ctx, id)
	}
	return s.DataStorage.Update(ctx, id, metadata)
}

// errorOnUpdateStorage fails the first Update call, simulating a transient
// Redis write failure during loadSession's write-back.
type errorOnUpdateStorage struct {
	transportsession.DataStorage
	errored bool
}

func (s *errorOnUpdateStorage) Update(ctx context.Context, id string, metadata map[string]string) (bool, error) {
	if !s.errored {
		s.errored = true
		return false, errors.New("injected Update failure")
	}
	return s.DataStorage.Update(ctx, id, metadata)
}

func newRestoredMockSession(
	ctrl *gomock.Controller,
	sessionID string,
	metadata map[string]string,
) *sessionmocks.MockMultiSession {
	sess := sessionmocks.NewMockMultiSession(ctrl)
	sess.EXPECT().ID().Return(sessionID).AnyTimes()
	sess.EXPECT().Type().Return(transportsession.SessionType("")).AnyTimes()
	sess.EXPECT().CreatedAt().Return(time.Time{}).AnyTimes()
	sess.EXPECT().UpdatedAt().Return(time.Time{}).AnyTimes()
	sess.EXPECT().GetData().Return(nil).AnyTimes()
	sess.EXPECT().SetData(gomock.Any()).AnyTimes()
	sess.EXPECT().GetMetadata().Return(metadata).AnyTimes()
	sess.EXPECT().SetMetadata(gomock.Any(), gomock.Any()).AnyTimes()
	sess.EXPECT().BackendSessions().Return(nil).AnyTimes()
	sess.EXPECT().GetRoutingTable().Return(nil).AnyTimes()
	sess.EXPECT().Prompts().Return(nil).AnyTimes()
	sess.EXPECT().Tools().Return(nil).AnyTimes()
	return sess
}

func TestSessionManager_LoadSessionPersistsRestoredMetadata(t *testing.T) {
	t.Parallel()

	t.Run("restored metadata is written back to storage", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
		sessionID := "restore-metadata-persist-session"
		freshMeta := map[string]string{
			sessiontypes.MetadataKeyIdentityBinding:                   "unauthenticated",
			vmcpsession.MetadataKeyBackendIDs:                         "backend-a",
			vmcpsession.MetadataKeyBackendSessionPrefix + "backend-a": "fresh-session-id",
		}
		factory.EXPECT().
			RestoreSession(gomock.Any(), sessionID, gomock.Any(), gomock.Any()).
			Return(newRestoredMockSession(ctrl, sessionID, freshMeta), nil).Times(1)

		sm, storage := newTestSessionManager(t, factory, newFakeRegistry())
		_, err := storage.Create(context.Background(), sessionID, map[string]string{
			sessiontypes.MetadataKeyIdentityBinding:                   "unauthenticated",
			vmcpsession.MetadataKeyBackendIDs:                         "backend-a",
			vmcpsession.MetadataKeyBackendSessionPrefix + "backend-a": "stale-session-id",
		})
		require.NoError(t, err)

		multiSess, ok := sm.GetMultiSession(context.Background(), sessionID)
		require.True(t, ok)
		require.NotNil(t, multiSess)

		stored, err := storage.Load(context.Background(), sessionID)
		require.NoError(t, err)
		assert.Equal(t, freshMeta, stored)
	})

	t.Run("session deleted before write-back is not served", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
		sessionID := "restore-concurrent-delete-session"
		restored := newRestoredMockSession(ctrl, sessionID, map[string]string{sessiontypes.MetadataKeyIdentityBinding: "unauthenticated"})
		restored.EXPECT().Close().Return(nil).Times(1)
		factory.EXPECT().
			RestoreSession(gomock.Any(), sessionID, gomock.Any(), gomock.Any()).
			Return(restored, nil).Times(1)

		inner := newTestSessionDataStorage(t)
		sm, cleanup, err := New(&deleteBeforeUpdateStorage{DataStorage: inner}, &FactoryConfig{Base: factory}, newFakeRegistry(), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cleanup(context.Background()) })

		_, err = inner.Create(context.Background(), sessionID, map[string]string{sessiontypes.MetadataKeyIdentityBinding: "unauthenticated"})
		require.NoError(t, err)

		multiSess, ok := sm.GetMultiSession(context.Background(), sessionID)
		assert.False(t, ok)
		assert.Nil(t, multiSess)
	})

	t.Run("transient write-back error still serves the session", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
		sessionID := "restore-update-error-session"
		factory.EXPECT().
			RestoreSession(gomock.Any(), sessionID, gomock.Any(), gomock.Any()).
			Return(newRestoredMockSession(ctrl, sessionID, map[string]string{sessiontypes.MetadataKeyIdentityBinding: "unauthenticated"}), nil).
			Times(1)

		inner := newTestSessionDataStorage(t)
		sm, cleanup, err := New(&errorOnUpdateStorage{DataStorage: inner}, &FactoryConfig{Base: factory}, newFakeRegistry(), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cleanup(context.Background()) })

		_, err = inner.Create(context.Background(), sessionID, map[string]string{sessiontypes.MetadataKeyIdentityBinding: "unauthenticated"})
		require.NoError(t, err)

		multiSess, ok := sm.GetMultiSession(context.Background(), sessionID)
		assert.True(t, ok)
		require.NotNil(t, multiSess)
		assert.Equal(t, sessionID, multiSess.ID())
	})
}

type metadataTestSession struct {
	sessiontypes.MultiSession
	mu       sync.Mutex
	metadata map[string]string
	identity *auth.Identity
}

func (s *metadataTestSession) GetMetadata() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneStringMap(s.metadata)
}

func (s *metadataTestSession) SetMetadata(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metadata[key] = value
}

func (s *metadataTestSession) CreatorIdentity() *auth.Identity {
	if s.identity == nil {
		return nil
	}
	cloned := *s.identity
	return &cloned
}

func newMetadataTestSession(
	ctrl *gomock.Controller,
	metadata map[string]string,
	identity *auth.Identity,
) *metadataTestSession {
	base := sessionmocks.NewMockMultiSession(ctrl)
	base.EXPECT().ID().Return(tokenlessRestoreSessionID).AnyTimes()
	base.EXPECT().Type().Return(transportsession.SessionType("")).AnyTimes()
	base.EXPECT().CreatedAt().Return(time.Time{}).AnyTimes()
	base.EXPECT().UpdatedAt().Return(time.Time{}).AnyTimes()
	base.EXPECT().GetData().Return(nil).AnyTimes()
	base.EXPECT().SetData(gomock.Any()).AnyTimes()
	base.EXPECT().BackendSessions().Return(nil).AnyTimes()
	base.EXPECT().GetRoutingTable().Return(nil).AnyTimes()
	base.EXPECT().Prompts().Return(nil).AnyTimes()
	base.EXPECT().Tools().Return(nil).AnyTimes()
	base.EXPECT().Close().Return(nil).AnyTimes()
	return &metadataTestSession{MultiSession: base, metadata: cloneStringMap(metadata), identity: identity}
}

const (
	tokenlessRestoreSessionID = "550e8400-e29b-41d4-a716-446655440900"
	tokenlessRestoreSubject   = "user-123"
	// tokenlessRestoreBinding is binding.Format("https://idp.example", tokenlessRestoreSubject).
	tokenlessRestoreBinding = "https://idp.example\x00" + tokenlessRestoreSubject
)

func fullStoredMetadata() map[string]string {
	return map[string]string{
		sessiontypes.MetadataKeyIdentityBinding:                           tokenlessRestoreBinding,
		vmcpsession.MetadataKeyBackendIDs:                                 "global,global_memory-mcp,p2",
		vmcpsession.MetadataKeyBackendSessionPrefix + "global":            "global-session",
		vmcpsession.MetadataKeyBackendSessionPrefix + "global_memory-mcp": "memory-session",
		vmcpsession.MetadataKeyBackendSessionPrefix + "p2":                "p2-session",
	}
}

func tokenlessRestoredMetadata() map[string]string {
	return map[string]string{
		sessiontypes.MetadataKeyIdentityBinding:                tokenlessRestoreBinding,
		vmcpsession.MetadataKeyBackendIDs:                      "global,p2",
		vmcpsession.MetadataKeyBackendSessionPrefix + "global": "global-session-restored",
		vmcpsession.MetadataKeyBackendSessionPrefix + "p2":     "p2-session-restored",
	}
}

func restoringFactory(
	ctrl *gomock.Controller,
	restored vmcpsession.MultiSession,
	times int,
) *sessionfactorymocks.MockMultiSessionFactory {
	factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
	factory.EXPECT().
		RestoreSession(gomock.Any(), tokenlessRestoreSessionID, gomock.Any(), gomock.Any()).
		Return(restored, nil).Times(times)
	return factory
}

func TestSessionManager_TokenlessRestoreKeepsStoredBackendIDs(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	restored := newMetadataTestSession(ctrl, tokenlessRestoredMetadata(),
		&auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: tokenlessRestoreSubject}})
	sm, storage := newTestSessionManager(t, restoringFactory(ctrl, restored, 1), newFakeRegistry())
	_, err := storage.Create(context.Background(), tokenlessRestoreSessionID, fullStoredMetadata())
	require.NoError(t, err)

	first, ok := sm.GetMultiSession(context.Background(), tokenlessRestoreSessionID)
	require.True(t, ok)

	stored, err := storage.Load(context.Background(), tokenlessRestoreSessionID)
	require.NoError(t, err)
	assert.Equal(t, "global,global_memory-mcp,p2", stored[vmcpsession.MetadataKeyBackendIDs])
	assert.Equal(t, "memory-session", stored[vmcpsession.MetadataKeyBackendSessionPrefix+"global_memory-mcp"])
	assert.Equal(t, "global-session-restored", stored[vmcpsession.MetadataKeyBackendSessionPrefix+"global"])
	assert.NotContains(t, stored, metadataKeyRestoredFromBackendIDs)

	second, ok := sm.GetMultiSession(context.Background(), tokenlessRestoreSessionID)
	require.True(t, ok)
	assert.Same(t, first, second)
}

func TestSessionManager_TokenlessRestoreOnOtherReplicaKeepsOwnerSession(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	storage := newTestSessionDataStorage(t)

	owner, ownerCleanup, err := New(storage, &FactoryConfig{Base: sessionfactorymocks.NewMockMultiSessionFactory(ctrl)}, newFakeRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ownerCleanup(context.Background()) })

	ownerSession := newMetadataTestSession(ctrl, fullStoredMetadata(),
		&auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: tokenlessRestoreSubject}, Token: "bearer"})
	require.NoError(t, owner.StoreSession(ownerSession))

	restored := newMetadataTestSession(ctrl, tokenlessRestoredMetadata(),
		&auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: tokenlessRestoreSubject}})
	other, otherCleanup, err := New(storage, &FactoryConfig{Base: restoringFactory(ctrl, restored, 1)}, newFakeRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = otherCleanup(context.Background()) })

	_, ok := other.GetMultiSession(context.Background(), tokenlessRestoreSessionID)
	require.True(t, ok)

	ownerView, ok := owner.GetMultiSession(context.Background(), tokenlessRestoreSessionID)
	require.True(t, ok)
	assert.Same(t, vmcpsession.MultiSession(ownerSession), ownerView)
}

func TestSessionManager_OwnershipClaimOnTokenlessRestoreKeepsStoredBackendIDs(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	restored := newMetadataTestSession(ctrl, tokenlessRestoredMetadata(),
		&auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: tokenlessRestoreSubject}})
	sm, storage := newTestSessionManager(t, restoringFactory(ctrl, restored, 1), newFakeRegistry())
	_, err := storage.Create(context.Background(), tokenlessRestoreSessionID, fullStoredMetadata())
	require.NoError(t, err)

	live, ok := sm.GetMultiSession(context.Background(), tokenlessRestoreSessionID)
	require.True(t, ok)
	require.NoError(t, sm.SetSessionMetadataValue(context.Background(), tokenlessRestoreSessionID, live,
		sessiontypes.MetadataKeyOwnerURL, "http://10.0.0.2:4483"))

	stored, err := storage.Load(context.Background(), tokenlessRestoreSessionID)
	require.NoError(t, err)
	assert.Equal(t, "global,global_memory-mcp,p2", stored[vmcpsession.MetadataKeyBackendIDs])
	assert.Equal(t, "http://10.0.0.2:4483", stored[sessiontypes.MetadataKeyOwnerURL])
	assert.NotContains(t, stored, metadataKeyRestoredFromBackendIDs)
}

func TestSessionManager_RefreshSessionNeverDowngradesBoundSession(t *testing.T) {
	t.Parallel()

	t.Run("bound session without caller token is left untouched", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
		factory.EXPECT().MakeSessionWithID(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
		sm, _ := newTestSessionManager(t, factory, &fakeBackendRegistry{backends: []vmcp.Backend{{ID: "global_memory-mcp"}}})

		restored := newMetadataTestSession(ctrl, tokenlessRestoredMetadata(),
			&auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: tokenlessRestoreSubject}})
		require.NoError(t, sm.StoreSession(restored))

		_, err := sm.RefreshSession(context.Background(), tokenlessRestoreSessionID)
		require.ErrorIs(t, err, errRefreshWithoutCallerToken)

		live, ok := sm.GetMultiSession(context.Background(), tokenlessRestoreSessionID)
		require.True(t, ok)
		assert.Same(t, vmcpsession.MultiSession(restored), live)
	})

	t.Run("anonymous session is still rebuilt", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		anonymousMeta := map[string]string{
			sessiontypes.MetadataKeyIdentityBinding: "unauthenticated",
			vmcpsession.MetadataKeyBackendIDs:       "global",
		}
		rebuilt := newMetadataTestSession(ctrl, anonymousMeta, nil)
		factory := sessionfactorymocks.NewMockMultiSessionFactory(ctrl)
		factory.EXPECT().
			MakeSessionWithID(gomock.Any(), tokenlessRestoreSessionID, gomock.Nil(), gomock.Any()).
			Return(rebuilt, nil).Times(1)
		sm, _ := newTestSessionManager(t, factory, newFakeRegistry())

		require.NoError(t, sm.StoreSession(newMetadataTestSession(ctrl, anonymousMeta, nil)))

		refreshed, err := sm.RefreshSession(context.Background(), tokenlessRestoreSessionID)
		require.NoError(t, err)
		assert.Same(t, vmcpsession.MultiSession(rebuilt), refreshed)
	})
}
