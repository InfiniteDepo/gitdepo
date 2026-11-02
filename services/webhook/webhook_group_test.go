// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package webhook

import (
	"testing"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/json"
	api "forgejo.org/modules/structs"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/services/convert"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A project hook fires for the events of the repositories in its project, after the repository's own hooks and
// before the organization's; a move switches the hooks at once.
func TestPrepareWebhooksProject(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	_, err := db.Exec(ctx, "DELETE FROM `webhook`")
	require.NoError(t, err)
	mk := func(owner, group, repo int64, system bool) int64 {
		w := &webhook_model.Webhook{OwnerID: owner, GroupID: group, RepoID: repo, IsSystemWebhook: system, URL: "http://example.com/h", HTTPMethod: "POST", ContentType: webhook_model.ContentTypeJSON, IsActive: true, Type: webhook_module.FORGEJO, Events: `{"send_everything":true}`}
		require.NoError(t, webhook_model.CreateWebhook(ctx, w, ""))
		return w.ID
	}
	repoHook := mk(0, 0, 3, false)
	projA := mk(3, 10, 0, false)
	projB := mk(3, 11, 0, false)
	mk(17, 10, 0, false) // another organization's project with the same ID
	orgHook := mk(3, 0, 0, false)
	system := mk(0, 0, 0, true)
	inactive := mk(3, 10, 0, false)
	_, err = db.GetEngine(ctx).ID(inactive).Cols("is_active").Update(&webhook_model.Webhook{})
	require.NoError(t, err)

	setGroup := func(group int64) *repo_model.Repository {
		_, err := db.Exec(ctx, "UPDATE `repository` SET group_id = ?, trashed_unix = 0 WHERE id = 3", group)
		require.NoError(t, err)
		return unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	}
	fired := func(source EventSource) []int64 {
		_, err := db.Exec(ctx, "DELETE FROM `hook_task`")
		require.NoError(t, err)
		require.NoError(t, PrepareWebhooks(ctx, source, webhook_module.HookEventPush, &api.PushPayload{Commits: []*api.PayloadCommit{{}}}))
		var tasks []*webhook_model.HookTask
		require.NoError(t, db.GetEngine(ctx).Find(&tasks))
		ids := make([]int64, 0, len(tasks))
		for _, task := range tasks {
			ids = append(ids, task.HookID)
		}
		return ids
	}

	assert.ElementsMatch(t, []int64{repoHook, projA, orgHook, system}, fired(EventSource{Repository: setGroup(10)}))
	assert.ElementsMatch(t, []int64{repoHook, projB, orgHook, system}, fired(EventSource{Repository: setGroup(11)}), "moved: the old project stops, the new one starts")
	assert.ElementsMatch(t, []int64{repoHook, orgHook, system}, fired(EventSource{Repository: setGroup(0)}), "no project, no project hooks")
	assert.ElementsMatch(t, []int64{repoHook, orgHook, system}, fired(EventSource{Repository: setGroup(12)}), "a project without hooks")

	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	assert.ElementsMatch(t, []int64{orgHook, system}, fired(EventSource{Owner: org}), "owner events don't reach project hooks")

	trashed := setGroup(10)
	_, err = db.Exec(ctx, "UPDATE `repository` SET trashed_unix = 1 WHERE id = 3")
	require.NoError(t, err)
	trashed.TrashedUnix = 1
	assert.Empty(t, fired(EventSource{Repository: trashed}), "a trashed repository fires nothing")
}

// The payload of an event of a repository in a project is what the converters always produce: the full path of the
// repository, and the same fields as for a repository at the root.
func TestProjectRepoPayload(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := db.DefaultContext
	fields := func() (map[string]any, string) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
		payload, err := (&api.PushPayload{Repo: convert.ToRepo(ctx, repo, access_model.Permission{AccessMode: perm.AccessModeNone})}).JSONPayload()
		require.NoError(t, err)
		var p struct {
			Repo map[string]any `json:"repository"`
		}
		require.NoError(t, json.Unmarshal(payload, &p))
		return p.Repo, repo.FullName()
	}
	root, rootName := fields()
	require.Equal(t, "org3/repo3", rootName)

	_, err := db.Exec(ctx, "UPDATE `repository` SET group_id = 10, group_name = 'proj' WHERE id = 3")
	require.NoError(t, err)
	inProject, name := fields()
	assert.Equal(t, "org3/proj/repo3", name)
	assert.Equal(t, "org3/proj/repo3", inProject["full_name"])
	for key := range inProject {
		if key != "project" { // added with the projects API, only for a repository in a project
			assert.Contains(t, root, key, "no new field")
		}
	}
	for key := range root {
		assert.Contains(t, inProject, key, "no field is gone")
	}
}
