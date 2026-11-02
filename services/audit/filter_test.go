// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package audit

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func parse(t *testing.T, query string) (*Filter, error) {
	t.Helper()
	q, err := url.ParseQuery(query)
	require.NoError(t, err)
	return ParseFilter(t.Context(), q.Get)
}

func TestParseFilter(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	project := &repo_model.RepoGroup{OwnerID: 3, Name: "proj", LowerName: "proj"}
	require.NoError(t, db.Insert(t.Context(), project))
	pid := project.ID
	// repo 1 is user2/repo1; repo 3 is org3/repo3, trashed below
	_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = 3")
	require.NoError(t, err)

	t.Run("names and ids", func(t *testing.T) {
		f, err := parse(t, "org=org3&repo=user2/repo1&user=user2&credential_owner=org17")
		require.NoError(t, err)
		assert.Equal(t, audit_model.SearchOptions{OwnerID: 3, RepoID: 1, UserID: 2, CredentialOwnerID: 17, Categories: Tabs["changes"]}, f.Opts)

		f, err = parse(t, "org=3&repo=3&user=999&project="+itoa(pid))
		require.NoError(t, err)
		assert.EqualValues(t, 3, f.Opts.OwnerID)
		assert.EqualValues(t, 3, f.Opts.RepoID, "a trashed repository is found by ID")
		assert.EqualValues(t, 999, f.Opts.UserID, "an ID needs no current user")
		assert.Equal(t, pid, f.Opts.GroupID)
	})

	t.Run("unknown names", func(t *testing.T) {
		for _, q := range []string{
			"org=nope", "org=user2", "repo=org3/repo3", "repo=user2/nope", "repo=a/b/c/d", "user=nope", "credential_owner=nope",
			"org=org17&project=" + itoa(pid), // a project of another organization
		} {
			_, err := parse(t, q)
			var fe *FilterError
			require.ErrorAs(t, err, &fe, q)
			assert.True(t, fe.Unknown, q)
		}
		_, err := parse(t, "org=nope")
		assert.EqualError(t, err, `no organization named "nope"`)
	})

	t.Run("invalid values", func(t *testing.T) {
		for _, q := range []string{
			"ip=10.0.0", "ip=x", "request_id=a-b", "request_id=" + strings.Repeat("a", 33), "credential_type=password,magic",
			"category=nope", "category=auth,nope", "result=ok", "credential=session", "credential=magic:1", "credential=ssh_key:x",
			"action=git.%25", "action=Git.push", "action=git.*.x", "since=yesterday", "before=2026-01-01",
			"project=abc", "target_type=a b", "target_id=-1", "before_id=0", "after_id=x",
		} {
			_, err := parse(t, q)
			var fe *FilterError
			require.ErrorAs(t, err, &fe, q)
			assert.False(t, fe.Unknown, q)
		}
	})

	t.Run("values", func(t *testing.T) {
		f, err := parse(t, "category=all&action=credential.access_token.*&ip=2001:DB8::1&request_id=Ab12&result=refused"+
			"&credential_type=ssh_key,deploy_key&credential=access_token:5&since=2026-01-02T03:04:05Z&before=2026-01-03T00:00:00%2B01:00"+
			"&target_type=access_token&target_id=5&before_id=10&after_id=2")
		require.NoError(t, err)
		assert.Equal(t, audit_model.SearchOptions{
			Action: "credential.access_token", ActionPrefix: true, IP: "2001:db8::1", RequestID: "Ab12", Result: "refused",
			CredentialTypes: []string{"ssh_key", "deploy_key"}, CredentialType: "access_token", CredentialID: 5,
			Since: 1767323045, Before: 1767394800, TargetType: "access_token", TargetID: 5, BeforeID: 10, AfterID: 2,
		}, f.Opts)
		assert.Equal(t, []string{
			"category=all", "credential_type=ssh_key,deploy_key", "credential=access_token:5", "action=credential.access_token.*",
			"result=refused", "ip=2001:DB8::1", "request_id=Ab12", "since=2026-01-02T03:04:05Z", "before=2026-01-03T00:00:00+01:00",
			"target_type=access_token", "target_id=5", "before_id=10", "after_id=2",
		}, f.List())

		f, err = parse(t, "category=auth,repo&action=git.push")
		require.NoError(t, err)
		assert.Equal(t, []string{"auth", "repo"}, f.Opts.Categories)
		assert.Equal(t, "git.push", f.Opts.Action)
		assert.False(t, f.Opts.ActionPrefix)

		f, err = parse(t, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"category=changes"}, f.List())
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestPage(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	var ids []int64
	for range 5 {
		e := &audit_model.Entry{Category: "credential", Action: "credential.x"}
		require.NoError(t, db.Insert(t.Context(), e))
		ids = append(ids, e.ID)
	}
	page := func(q string) ([]int64, bool, bool) {
		f, err := parse(t, q)
		require.NoError(t, err)
		entries, newer, older, err := Page(t.Context(), f, 2)
		require.NoError(t, err)
		var got []int64
		for _, e := range entries {
			got = append(got, e.ID)
		}
		return got, newer, older
	}
	got, newer, older := page("")
	assert.Equal(t, []int64{ids[4], ids[3]}, got)
	assert.False(t, newer)
	assert.True(t, older)
	got, newer, older = page("before_id=" + itoa(ids[3]))
	assert.Equal(t, []int64{ids[2], ids[1]}, got)
	assert.True(t, newer)
	assert.True(t, older)
	got, newer, older = page("before_id=" + itoa(ids[1]))
	assert.Equal(t, []int64{ids[0]}, got)
	assert.True(t, newer)
	assert.False(t, older)
	got, newer, older = page("after_id=" + itoa(ids[0]))
	assert.Equal(t, []int64{ids[2], ids[1]}, got)
	assert.True(t, newer)
	assert.True(t, older)
	got, newer, older = page("after_id=" + itoa(ids[2]))
	assert.Equal(t, []int64{ids[4], ids[3]}, got)
	assert.False(t, newer)
	assert.True(t, older)
}
