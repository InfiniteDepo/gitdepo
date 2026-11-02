// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package migrations

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"

	"code.forgejo.org/xorm/xorm/contexts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var failCollaborationUpdates atomic.Bool

// failCollaborationUpdate makes the audit entry of a new collaboration fail while failCollaborationUpdates is set.
type failCollaborationUpdate struct{}

func (failCollaborationUpdate) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if failCollaborationUpdates.Load() && strings.HasPrefix(c.SQL, "INSERT INTO `audit_event`") {
		return c.Ctx, errors.New("injected failure")
	}
	return db.TracingHook{}.BeforeProcess(c)
}

func (failCollaborationUpdate) AfterProcess(c *contexts.ContextHook) error {
	return db.TracingHook{}.AfterProcess(c)
}

func TestAddBitbucketCollaboratorRollsBack(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	engine, err := db.GetMasterEngine(db.GetEngine(db.DefaultContext))
	require.NoError(t, err)
	engine.AddHook(failCollaborationUpdate{})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: u.ID})

	// the collaboration and its audit entry are one transaction: nothing is left behind
	failCollaborationUpdates.Store(true)
	_, err = addBitbucketCollaborator(db.DefaultContext, repo, u, perm.AccessModeRead)
	failCollaborationUpdates.Store(false)
	require.ErrorContains(t, err, "injected failure")
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: u.ID})

	existed, err := addBitbucketCollaborator(db.DefaultContext, repo, u, perm.AccessModeRead)
	require.NoError(t, err)
	assert.False(t, existed)
	assert.Equal(t, perm.AccessModeRead, unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: u.ID}).Mode)

	existed, err = addBitbucketCollaborator(db.DefaultContext, repo, u, perm.AccessModeWrite)
	require.NoError(t, err)
	assert.True(t, existed, "an existing collaborator is never changed")
	assert.Equal(t, perm.AccessModeRead, unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: u.ID}).Mode)
}
