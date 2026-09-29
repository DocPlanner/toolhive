// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sessionmanager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
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
			sessiontypes.MetadataKeyTokenHash:                         "",
			vmcpsession.MetadataKeyBackendIDs:                         "backend-a",
			vmcpsession.MetadataKeyBackendSessionPrefix + "backend-a": "fresh-session-id",
		}
		factory.EXPECT().
			RestoreSession(gomock.Any(), sessionID, gomock.Any(), gomock.Any()).
			Return(newRestoredMockSession(ctrl, sessionID, freshMeta), nil).Times(1)

		sm, storage := newTestSessionManager(t, factory, newFakeRegistry())
		_, err := storage.Create(context.Background(), sessionID, map[string]string{
			sessiontypes.MetadataKeyTokenHash:                         "",
			vmcpsession.MetadataKeyBackendIDs:                         "backend-a",
			vmcpsession.MetadataKeyBackendSessionPrefix + "backend-a": "stale-session-id",
		})
		require.NoError(t, err)

		multiSess, ok := sm.GetMultiSession(sessionID)
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
		restored := newRestoredMockSession(ctrl, sessionID, map[string]string{sessiontypes.MetadataKeyTokenHash: ""})
		restored.EXPECT().Close().Return(nil).Times(1)
		factory.EXPECT().
			RestoreSession(gomock.Any(), sessionID, gomock.Any(), gomock.Any()).
			Return(restored, nil).Times(1)

		inner := newTestSessionDataStorage(t)
		sm, cleanup, err := New(&deleteBeforeUpdateStorage{DataStorage: inner}, &FactoryConfig{Base: factory}, newFakeRegistry(), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cleanup(context.Background()) })

		_, err = inner.Create(context.Background(), sessionID, map[string]string{sessiontypes.MetadataKeyTokenHash: ""})
		require.NoError(t, err)

		multiSess, ok := sm.GetMultiSession(sessionID)
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
			Return(newRestoredMockSession(ctrl, sessionID, map[string]string{sessiontypes.MetadataKeyTokenHash: ""}), nil).
			Times(1)

		inner := newTestSessionDataStorage(t)
		sm, cleanup, err := New(&errorOnUpdateStorage{DataStorage: inner}, &FactoryConfig{Base: factory}, newFakeRegistry(), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cleanup(context.Background()) })

		_, err = inner.Create(context.Background(), sessionID, map[string]string{sessiontypes.MetadataKeyTokenHash: ""})
		require.NoError(t, err)

		multiSess, ok := sm.GetMultiSession(sessionID)
		assert.True(t, ok)
		require.NotNil(t, multiSess)
		assert.Equal(t, sessionID, multiSess.ID())
	})
}
