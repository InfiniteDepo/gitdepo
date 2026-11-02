// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit_test

import (
	"slices"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertSearchRows inserts entries across two owners, a project, a repository that moved from owner 3 to 17,
// a trashed repository and every credential type, and returns their IDs by label.
func insertSearchRows(t *testing.T) map[string]int64 {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	rows := map[string]*audit_model.Entry{
		"a": {CreatedUnix: 1000, OwnerID: 3, RepoID: 3, ActorType: "user", ActorID: 2, CredentialType: "access_token", CredentialID: 1, CredentialOwnerID: 2, Category: "credential", Action: "credential.access_token.created", Result: "success", IP: "10.0.0.1", RequestID: "r1", TargetType: "access_token", TargetID: 1},
		"b": {CreatedUnix: 2000, OwnerID: 3, GroupID: 5, RepoID: 30, ActorType: "user", ActorID: 4, SudoByID: 1, CredentialType: "session", CredentialOwnerID: 4, Category: "repo", Action: "repo.settings.updated", Result: "success", IP: "10.0.0.2", RequestID: "r2"},
		"c": {CreatedUnix: 3000, OwnerID: 3, RepoID: 40, ActorType: "deploy_key", ActorID: 2, CredentialType: "deploy_key", CredentialID: 7, CredentialOwnerID: 3, Category: "activity", Action: "git.push", Result: "refused", IP: "2001:db8::1", RequestID: "r3"},
		"d": {CreatedUnix: 4000, OwnerID: 17, RepoID: 40, ActorType: "user", ActorID: 5, CredentialType: "ssh_key", CredentialID: 3, CredentialOwnerID: 5, Category: "activity", Action: "git.push", Result: "success"},
		"e": {CreatedUnix: 5000, OwnerID: 17, RepoID: 50, ActorType: "user", ActorID: 2, SubjectUserID: 5, CredentialType: "oauth2_grant", CredentialID: 9, CredentialOwnerID: 2, Category: "auth", Action: "auth.signin", Result: "failure"},
		"f": {CreatedUnix: 6000, ActorType: "system", CredentialType: "system", Category: "admin", Action: "credential_x.test", Result: "success"},
	}
	for i, ct := range audit_model.CredentialTypes {
		rows["cred:"+ct] = &audit_model.Entry{CreatedUnix: timeutil.TimeStamp(7000 + i), ActorType: "system", CredentialType: ct, CredentialID: int64(100 + i), Category: "audit", Action: "audit.instance.started", Result: "success"}
	}
	ids := map[string]int64{}
	// insert in a fixed order, so that IDs grow with created_unix
	for _, label := range append([]string{"a", "b", "c", "d", "e", "f"}, credLabels()...) {
		require.NoError(t, db.Insert(t.Context(), rows[label]))
		ids[label] = rows[label].ID
	}
	return ids
}

func credLabels() []string {
	labels := make([]string, 0, len(audit_model.CredentialTypes))
	for _, ct := range audit_model.CredentialTypes {
		labels = append(labels, "cred:"+ct)
	}
	return labels
}

func TestFindEntries(t *testing.T) {
	ids := insertSearchRows(t)
	find := func(o audit_model.SearchOptions) []int64 {
		entries, err := audit_model.FindEntries(t.Context(), &o, 100)
		require.NoError(t, err)
		got := make([]int64, 0, len(entries))
		for _, e := range entries {
			got = append(got, e.ID)
		}
		return got
	}
	want := func(labels ...string) []int64 {
		out := make([]int64, 0, len(labels))
		for _, label := range slices.Backward(labels) { // newest first
			out = append(out, ids[label])
		}
		return out
	}

	for name, tc := range map[string]struct {
		opts audit_model.SearchOptions
		want []string
	}{
		"org":                 {audit_model.SearchOptions{OwnerID: 3}, []string{"a", "b", "c"}},
		"other org":           {audit_model.SearchOptions{OwnerID: 17}, []string{"d", "e"}},
		"project":             {audit_model.SearchOptions{GroupID: 5}, []string{"b"}},
		"transferred repo":    {audit_model.SearchOptions{RepoID: 40}, []string{"c", "d"}},
		"trashed repo":        {audit_model.SearchOptions{RepoID: 50}, []string{"e"}},
		"user as actor":       {audit_model.SearchOptions{UserID: 2}, []string{"a", "e"}}, // not c: deploy key 2 is no user
		"user as subject":     {audit_model.SearchOptions{UserID: 5}, []string{"d", "e"}},
		"user behind sudo":    {audit_model.SearchOptions{UserID: 1}, []string{"b"}},
		"credential owner":    {audit_model.SearchOptions{CredentialOwnerID: 3}, []string{"c"}},
		"credential":          {audit_model.SearchOptions{CredentialType: "deploy_key", CredentialID: 7}, []string{"c"}},
		"credential types":    {audit_model.SearchOptions{CredentialTypes: []string{"ssh_key", "oauth2_grant"}, OwnerID: 17}, []string{"d", "e"}},
		"action":              {audit_model.SearchOptions{Action: "git.push"}, []string{"c", "d"}},
		"action prefix":       {audit_model.SearchOptions{Action: "credential", ActionPrefix: true}, []string{"a"}},
		"action prefix _":     {audit_model.SearchOptions{Action: "credential_x", ActionPrefix: true}, []string{"f"}},
		"no partial word":     {audit_model.SearchOptions{Action: "git.pus", ActionPrefix: true}, nil},
		"category":            {audit_model.SearchOptions{Categories: []string{"activity"}}, []string{"c", "d"}},
		"categories":          {audit_model.SearchOptions{Categories: []string{"auth", "repo"}}, []string{"b", "e"}},
		"result":              {audit_model.SearchOptions{Result: "refused"}, []string{"c"}},
		"ip":                  {audit_model.SearchOptions{IP: "2001:db8::1"}, []string{"c"}},
		"request":             {audit_model.SearchOptions{RequestID: "r2"}, []string{"b"}},
		"time":                {audit_model.SearchOptions{Since: 2000, Before: 4000}, []string{"b", "c"}},
		"target":              {audit_model.SearchOptions{TargetType: "access_token", TargetID: 1}, []string{"a"}},
		"org and category":    {audit_model.SearchOptions{OwnerID: 3, Categories: []string{"activity"}}, []string{"c"}},
		"repo and user":       {audit_model.SearchOptions{RepoID: 40, UserID: 5}, []string{"d"}},
		"org, result, time":   {audit_model.SearchOptions{OwnerID: 17, Result: "success", Since: 3000}, []string{"d"}},
		"credential, no rows": {audit_model.SearchOptions{CredentialType: "deploy_key", CredentialID: 8}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, want(tc.want...), find(tc.opts))
		})
	}

	t.Run("every credential type", func(t *testing.T) {
		for _, ct := range audit_model.CredentialTypes {
			got := find(audit_model.SearchOptions{CredentialTypes: []string{ct}, Categories: []string{"audit"}})
			assert.Equal(t, []int64{ids["cred:"+ct]}, got, ct)
		}
	})

	t.Run("keyset", func(t *testing.T) {
		page := func(o audit_model.SearchOptions) []int64 {
			entries, err := audit_model.FindEntries(t.Context(), &o, 2)
			require.NoError(t, err)
			var got []int64
			for _, e := range entries {
				got = append(got, e.ID)
			}
			return got
		}
		older := page(audit_model.SearchOptions{OwnerID: 3, BeforeID: ids["c"]})
		assert.Equal(t, []int64{ids["b"], ids["a"]}, older)
		newer := page(audit_model.SearchOptions{OwnerID: 3, AfterID: ids["a"]})
		assert.Equal(t, []int64{ids["c"], ids["b"]}, newer)
		assert.Empty(t, page(audit_model.SearchOptions{OwnerID: 3, AfterID: ids["c"]}))
	})

	t.Run("iterate", func(t *testing.T) {
		var got []int64
		require.NoError(t, audit_model.IterateEntries(t.Context(), audit_model.SearchOptions{OwnerID: 3, MaxID: ids["b"]}, func(e *audit_model.Entry) error {
			got = append(got, e.ID)
			return nil
		}))
		assert.Equal(t, []int64{ids["a"], ids["b"]}, got)

		e, err := audit_model.NthEntry(t.Context(), &audit_model.SearchOptions{OwnerID: 3}, 1)
		require.NoError(t, err)
		assert.Equal(t, ids["b"], e.ID)
		e, err = audit_model.NthEntry(t.Context(), &audit_model.SearchOptions{OwnerID: 3}, 3)
		require.NoError(t, err)
		assert.Nil(t, e)
	})
}
