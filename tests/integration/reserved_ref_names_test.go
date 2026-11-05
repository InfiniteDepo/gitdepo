// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	auth_model "forgejo.org/models/auth"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	api "forgejo.org/modules/structs"

	"github.com/stretchr/testify/require"
)

// Branch and tag names that git could read as another ref (HEAD, refs/...) are never created: not by the API, not by a push.
func TestReservedRefNames(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		token := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository)
		base := fmt.Sprintf("/api/v1/repos/%s/%s", user2.Name, repo.Name)

		for _, name := range []string{"HEAD", "refs/heads/x", "refs/tags/x"} {
			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/branches", &api.CreateBranchRepoOption{BranchName: name, OldBranchName: "master"}).AddTokenAuth(token), http.StatusUnprocessableEntity)
			MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/tags", &api.CreateTagOption{TagName: name, Target: "master"}).AddTokenAuth(token), http.StatusUnprocessableEntity)
		}
		MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/branches", &api.CreateBranchRepoOption{BranchName: "heads-ok", OldBranchName: "master"}).AddTokenAuth(token), http.StatusCreated)
		MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/tags", &api.CreateTagOption{TagName: "tag-ok", Target: "master"}).AddTokenAuth(token), http.StatusCreated)

		empty := git.Sha1ObjectFormat.EmptyObjectID().String()
		hook := func(ref git.RefName, old string) error {
			return private.HookPreReceive(t.Context(), repo.ID, private.HookOptions{
				OldCommitIDs: []string{old},
				NewCommitIDs: []string{"65f1bf27bc3bf70f64657658635e66094edbcb4d"},
				RefFullNames: []git.RefName{ref},
				UserID:       user2.ID,
			}).Error
		}
		for _, ref := range []git.RefName{git.RefNameFromBranch("HEAD"), git.RefNameFromBranch("refs/heads/y"), git.RefNameFromTag("HEAD"), git.RefNameFromTag("refs/tags/y")} {
			require.ErrorContains(t, hook(ref, empty), "status=403", ref)
			// a ref of that name that exists is not refused for its name
			require.NoError(t, hook(ref, "65f1bf27bc3bf70f64657658635e66094edbcb4d"), ref)
		}
		require.NoError(t, hook(git.RefNameFromBranch("fine"), empty))
		require.NoError(t, hook(git.RefNameFromTag("fine"), empty))
	})
}

// A branch can't be renamed to a reserved name either.
func TestReservedRefNameRename(t *testing.T) {
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		token := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository)
		base := fmt.Sprintf("/api/v1/repos/%s/%s", user2.Name, repo.Name)
		MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/branches", &api.CreateBranchRepoOption{BranchName: "to-rename", OldBranchName: "master"}).AddTokenAuth(token), http.StatusCreated)
		for _, name := range []string{"HEAD", "refs/tags/v99"} {
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", base+"/branches/to-rename", &api.UpdateBranchRepoOption{Name: name}).AddTokenAuth(token), http.StatusUnprocessableEntity)
		}
		MakeRequest(t, NewRequest(t, "GET", base+"/branches/to-rename").AddTokenAuth(token), http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", base+"/branches/to-rename", &api.UpdateBranchRepoOption{Name: "renamed-ok"}).AddTokenAuth(token), http.StatusNoContent)
	})
}
