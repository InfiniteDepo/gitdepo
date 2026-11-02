// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"fmt"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"forgejo.org/models/db"
	issues_model "forgejo.org/models/issues"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/avatar"
	"forgejo.org/modules/json"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type repoGroupWebFixture struct {
	org            *user_model.User
	pub, priv, hid *repo_model.Repository
	privOrg        *user_model.User
}

// prepareRepoGroupWeb creates in org3 (members user2 (owner), user4, user28) the project "proj" with a public and a
// private repository, the project "secret" with only a private repository, and in the private privated_org
// (member user5) the project "pp" with a public repository.
func prepareRepoGroupWeb(t *testing.T) *repoGroupWebFixture {
	t.Helper()
	ctx := db.DefaultContext
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	f := &repoGroupWebFixture{
		org:     unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3}),
		privOrg: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 23}),
	}
	create := func(owner *user_model.User, groupName, name string, private bool) *repo_model.Repository {
		group, err := repo_model.GetRepoGroupByName(ctx, owner.ID, groupName)
		if err != nil {
			group, err = repo_model.CreateRepoGroup(ctx, owner, groupName, "the "+groupName+" project")
			require.NoError(t, err)
		}
		repo, err := repo_service.CreateRepository(ctx, user2, owner, repo_service.CreateRepoOptions{
			Name:          name,
			IsPrivate:     private,
			Readme:        "Default",
			AutoInit:      true,
			DefaultBranch: "main",
			GroupID:       group.ID,
		})
		require.NoError(t, err)
		return repo
	}
	f.pub = create(f.org, "proj", "pub", false)
	f.priv = create(f.org, "proj", "priv", true)
	f.hid = create(f.org, "secret", "hid", true)
	create(f.privOrg, "pp", "ppub", false)
	return f
}

func repoGroupRequest(t *testing.T, session *TestSession, req *RequestWrapper, status int) *httptest.ResponseRecorder {
	t.Helper()
	if session == nil {
		return MakeRequest(t, req, status)
	}
	return session.MakeRequest(t, req, status)
}

// comparableResponse is the status, headers and body of a response, with the request path replaced, and the
// headers that differ per request (date, cookies) left out. The ticking parts (page time, stopwatch seconds) are masked.
func comparableResponse(t *testing.T, session *TestSession, method, path string) string {
	t.Helper()
	var req *RequestWrapper
	if method == "POST" {
		req = NewRequestWithValues(t, method, path, map[string]string{"title": "x", "content": "y"})
	} else {
		req = NewRequest(t, method, path)
	}
	req.Header.Set("Accept", "text/html")
	resp := repoGroupRequest(t, session, req, NoExpectedStatus)
	pairs := []string{}
	for _, p := range []string{path, strings.Replace(path, "/-", "", 1)} {
		escaped := url.QueryEscape(p)
		pairs = append(pairs, p, "PATH", escaped, "PATH", strings.ReplaceAll(escaped, "%2F", "%2f"), "PATH")
	}
	replace := strings.NewReplacer(pairs...)
	timing := regexp.MustCompile(`<strong>\d+ms</strong>`)
	stopwatch := regexp.MustCompile(`data-seconds="\d+"`)
	header := resp.Header().Clone()
	header.Del("Date")
	header.Del("Set-Cookie")
	if loc := header.Get("Location"); loc != "" {
		header.Set("Location", replace.Replace(loc))
	}
	return fmt.Sprintf("%d\n%v\n%s", resp.Code, header, stopwatch.ReplaceAllString(timing.ReplaceAllString(replace.Replace(resp.Body.String()), "TIME"), `data-seconds="SECONDS"`))
}

// assertSameResponse compares two comparableResponse results and reports the first line that differs.
func assertSameResponse(t *testing.T, expected, actual string, msgAndArgs ...any) {
	t.Helper()
	if expected == actual {
		return
	}
	e, a := strings.Split(expected, "\n"), strings.Split(actual, "\n")
	for i := 0; i < len(e) && i < len(a); i++ {
		if e[i] != a[i] {
			assert.Fail(t, fmt.Sprintf("responses differ at line %d:\n%s\n%s", i+1, e[i], a[i]), msgAndArgs...)
			return
		}
	}
	assert.Fail(t, fmt.Sprintf("responses differ in length: %d and %d lines", len(e), len(a)), msgAndArgs...)
}

func TestRepoGroupWeb(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := prepareRepoGroupWeb(t)

	owner := loginUser(t, "user2")
	member := loginUser(t, "user4")
	nonMember := loginUser(t, "user5")

	noInternalForm := func(t *testing.T, resp *httptest.ResponseRecorder) {
		t.Helper()
		assert.NotContains(t, resp.Body.String(), "/@", "internal form in the body")
		assert.NotContains(t, resp.Header().Get("Location"), "@")
	}

	t.Run("serves a repository in a project", func(t *testing.T) {
		for _, session := range []*TestSession{owner, member, nonMember, nil} {
			for _, path := range []string{
				"/org3/proj/pub", "/org3/proj/pub/-", "/org3/proj/pub/-/issues", "/org3/proj/pub/issues",
				"/org3/PROJ/Pub/-/src/branch/main/README.md", "/org3/proj/pub/src/branch/main/README.md",
				"/org3/proj/pub/-/summary-card", "/org3/proj/pub/-/branches", "/org3/proj/pub/issues?page=2",
			} {
				resp := repoGroupRequest(t, session, NewRequest(t, "GET", path), http.StatusOK)
				noInternalForm(t, resp)
			}
		}
		resp := repoGroupRequest(t, nil, NewRequest(t, "GET", "/org3/proj/pub"), http.StatusOK)
		assert.Contains(t, resp.Body.String(), `href="/org3/proj/pub/issues"`)
		assert.Contains(t, resp.Body.String(), "org3/proj/pub")
	})

	t.Run("private repository", func(t *testing.T) {
		repoGroupRequest(t, owner, NewRequest(t, "GET", "/org3/proj/priv/-/issues"), http.StatusOK)
		// a member sees the project, but a private repository only through a team
		repoGroupRequest(t, member, NewRequest(t, "GET", "/org3/proj/priv"), http.StatusNotFound)
		repoGroupRequest(t, nonMember, NewRequest(t, "GET", "/org3/proj/priv"), http.StatusNotFound)
		repoGroupRequest(t, nil, NewRequest(t, "GET", "/org3/proj/priv"), http.StatusNotFound)
	})

	t.Run("project home", func(t *testing.T) {
		for _, path := range []string{"/org3/proj", "/org3/proj/-", "/org3/Proj"} {
			for _, session := range []*TestSession{owner, member, nonMember, nil} {
				resp := repoGroupRequest(t, session, NewRequest(t, "GET", path), http.StatusOK)
				assert.Contains(t, resp.Body.String(), "the proj project")
				noInternalForm(t, resp)
			}
		}
		// only members see a project of private repositories
		repoGroupRequest(t, owner, NewRequest(t, "GET", "/org3/secret"), http.StatusOK)
		repoGroupRequest(t, member, NewRequest(t, "GET", "/org3/secret"), http.StatusOK)
		repoGroupRequest(t, nonMember, NewRequest(t, "GET", "/org3/secret"), http.StatusNotFound)
		repoGroupRequest(t, nil, NewRequest(t, "GET", "/org3/secret"), http.StatusNotFound)
		repoGroupRequest(t, loginUser(t, "user5"), NewRequest(t, "GET", "/privated_org/pp"), http.StatusOK)
		repoGroupRequest(t, member, NewRequest(t, "GET", "/privated_org/pp"), http.StatusNotFound)
	})

	t.Run("internal routes", func(t *testing.T) {
		secret, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.org.ID, "secret")
		require.NoError(t, err)
		pp, err := repo_model.GetRepoGroupByName(db.DefaultContext, f.privOrg.ID, "pp")
		require.NoError(t, err)
		repoGroupRequest(t, member, NewRequest(t, "GET", fmt.Sprintf("/org/org3/groups/%d", secret.ID)), http.StatusOK)
		// another org's project, a hidden one and a missing one answer alike
		missing := comparableResponse(t, nonMember, "GET", "/org/org3/groups/999999")
		assertSameResponse(t, missing, comparableResponse(t, nonMember, "GET", fmt.Sprintf("/org/org3/groups/%d", secret.ID)))
		assertSameResponse(t, missing, comparableResponse(t, nonMember, "GET", fmt.Sprintf("/org/org3/groups/%d", pp.ID)))

		// the internal repository form can't be requested
		for _, path := range []string{
			fmt.Sprintf("/org3/@%d", f.pub.ID), fmt.Sprintf("/org3/%%40%d", f.pub.ID),
			fmt.Sprintf("/org3/@%d/issues", f.pub.ID), fmt.Sprintf("/org3/proj/@%d", f.pub.ID),
		} {
			repoGroupRequest(t, owner, NewRequest(t, "GET", path), http.StatusNotFound)
		}
	})

	t.Run("refused segments", func(t *testing.T) {
		for _, path := range []string{
			"/org3/proj%2Fpub", "/org3/proj%2fpub/issues", "/org3/proj/pub%2F..", "/org3/proj/pub%252F",
			"/org3/proj%5Cpub", "/org3/proj/%2E%2E", "/org3%2Fproj/pub", "/org3%2E/proj", "/org3/proj/..",
			"/user2/repo1%2F", "/org3/proj/pub@x",
		} {
			resp := repoGroupRequest(t, owner, NewRequest(t, "GET", path), http.StatusNotFound)
			assert.Equal(t, "Not found.\n", resp.Body.String(), path)
		}
	})

	t.Run("single segment stays root", func(t *testing.T) {
		// the leaf of a repository in a project is not a root repository
		repoGroupRequest(t, owner, NewRequest(t, "GET", "/org3/pub"), http.StatusNotFound)
		// and a root repository with the same name is served at the root
		_, err := repo_service.CreateRepository(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), f.org, repo_service.CreateRepoOptions{Name: "pub", Description: "the root pub"})
		require.NoError(t, err)
		resp := repoGroupRequest(t, owner, NewRequest(t, "GET", "/org3/pub"), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "the root pub")
		resp = repoGroupRequest(t, owner, NewRequest(t, "GET", "/org3/proj/pub"), http.StatusOK)
		assert.NotContains(t, resp.Body.String(), "the root pub")
	})

	t.Run("root repositories accept /-/", func(t *testing.T) {
		a := comparableResponse(t, owner, "GET", "/user2/repo1/issues")
		b := comparableResponse(t, owner, "GET", "/user2/repo1/-/issues")
		assertSameResponse(t, a, strings.ReplaceAll(b, "/user2/repo1/issues", "PATH"))
		repoGroupRequest(t, nil, NewRequest(t, "GET", "/user2/repo1/-"), http.StatusOK)
		repoGroupRequest(t, nil, NewRequest(t, "GET", "/user2/repo1/-/summary-card"), http.StatusOK)
	})

	t.Run("hidden answers like missing", func(t *testing.T) {
		// trash a repository of the visible project
		trashed, err := repo_service.CreateRepository(db.DefaultContext, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), f.org, repo_service.CreateRepoOptions{Name: "gone", GroupID: f.pub.GroupID})
		require.NoError(t, err)
		_, err = db.GetEngine(db.DefaultContext).Exec("UPDATE repository SET trashed_unix = 1 WHERE id = ?", trashed.ID)
		require.NoError(t, err)

		shapes := []struct{ method, rest string }{
			{"GET", ""},
			{"GET", "/-"},
			{"GET", "/-/issues"},
			{"GET", "/issues"},
			{"GET", "/issues/new"},
			{"GET", "/-/settings"},
			{"POST", "/-/settings"},
			{"POST", "/issues/new"},
			{"GET", "/-/nonsense"},
			{"GET", "/src/branch/main"},
		}
		for _, session := range []*TestSession{nonMember, nil} {
			for _, s := range shapes {
				// a hidden project and a missing one
				missing := comparableResponse(t, session, s.method, "/org3/nothing/hid"+s.rest)
				assertSameResponse(t, missing, comparableResponse(t, session, s.method, "/org3/secret/hid"+s.rest), s)
				// a hidden repository, a trashed one and a missing one in a visible project
				missing = comparableResponse(t, session, s.method, "/org3/proj/nothing"+s.rest)
				assertSameResponse(t, missing, comparableResponse(t, session, s.method, "/org3/proj/priv"+s.rest), s)
				assertSameResponse(t, missing, comparableResponse(t, session, s.method, "/org3/proj/gone"+s.rest), s)
			}
		}
		// user4 is not a member of privated_org
		for _, session := range []*TestSession{member, nil} {
			for _, s := range shapes {
				missing := comparableResponse(t, session, s.method, "/privated_org/nothing/ppub"+s.rest)
				assertSameResponse(t, missing, comparableResponse(t, session, s.method, "/privated_org/pp/ppub"+s.rest), s)
			}
			for _, rest := range []string{"", "/-", "/-/settings"} {
				missing := comparableResponse(t, session, "GET", "/privated_org/nothing"+rest)
				assertSameResponse(t, missing, comparableResponse(t, session, "GET", "/privated_org/pp"+rest), rest)
			}
		}
		for _, session := range []*TestSession{nonMember, nil} {
			for _, rest := range []string{"", "/-", "/-/settings"} {
				missing := comparableResponse(t, session, "GET", "/org3/nothing"+rest)
				assertSameResponse(t, missing, comparableResponse(t, session, "GET", "/org3/secret"+rest), rest)
			}
		}
	})

	t.Run("two-factor page", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).ID(f.org.ID).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: true})
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).ID(f.org.ID).Cols("require_two_factor").Update(&user_model.User{RequireTwoFactor: false})
			require.NoError(t, err)
		}()
		// user4 is a member without two-factor authentication, so no longer an acting member: the project of private
		// repositories answers like a missing name (the two-factor page), its paths like missing ones
		missing := comparableResponse(t, member, "GET", "/org3/nothing")
		assert.True(t, strings.HasPrefix(missing, "403\n"))
		assertSameResponse(t, missing, comparableResponse(t, member, "GET", "/org3/secret"))
		missing = comparableResponse(t, member, "GET", "/org3/nothing/hid")
		for _, path := range []string{"/org3/secret/hid", "/org3/proj/nothing", "/org3/proj/priv"} {
			assertSameResponse(t, missing, comparableResponse(t, member, "GET", path), path)
		}
	})

	t.Run("hidden answers like missing in read-only maintenance", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		for _, session := range []*TestSession{nonMember, nil} {
			for _, rest := range []string{"/-/issues/new", "/issues/new", "/-/settings"} {
				missing := comparableResponse(t, session, "POST", "/org3/nothing/hid"+rest)
				assertSameResponse(t, missing, comparableResponse(t, session, "POST", "/org3/secret/hid"+rest), rest)
				missing = comparableResponse(t, session, "POST", "/org3/proj/nothing"+rest)
				assertSameResponse(t, missing, comparableResponse(t, session, "POST", "/org3/proj/priv"+rest), rest)
			}
		}
	})

	t.Run("login redirect keeps the external path", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/org3/proj/pub/-/issues/new"), http.StatusSeeOther)
		assert.Equal(t, "/user/login", resp.Header().Get("Location"))
		var redirectTo string
		for _, c := range resp.Result().Cookies() {
			if c.Name == "redirect_to" {
				redirectTo, _ = url.QueryUnescape(c.Value)
			}
		}
		assert.Equal(t, "/org3/proj/pub/issues/new", redirectTo)
	})

	t.Run("cross-origin post is refused once", func(t *testing.T) {
		before := unittest.GetCount(t, &issues_model.Issue{RepoID: f.pub.ID})
		req := NewRequestWithValues(t, "POST", "/org3/proj/pub/-/issues/new", map[string]string{"title": "cross"})
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		resp := owner.MakeRequest(t, req, http.StatusForbidden)
		noInternalForm(t, resp)
		assert.Equal(t, before, unittest.GetCount(t, &issues_model.Issue{RepoID: f.pub.ID}))
	})
}

// The second pass of a request gets its body: a form, a multipart upload and a JSON body.
func TestRepoGroupWebPostBodies(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := prepareRepoGroupWeb(t)
	session := loginUser(t, "user2")

	t.Run("form", func(t *testing.T) {
		req := NewRequestWithValues(t, "POST", "/org3/proj/pub/-/settings", map[string]string{
			"action":      "update",
			"repo_name":   "pub",
			"description": "set through a nested path",
			"template":    "on",
		})
		session.MakeRequest(t, req, http.StatusSeeOther)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: f.pub.ID})
		assert.Equal(t, "set through a nested path", repo.Description)
		assert.True(t, repo.IsTemplate)
	})

	t.Run("multipart", func(t *testing.T) {
		img, err := avatar.RandomImage([]byte("seed"))
		require.NoError(t, err)
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		require.NoError(t, writer.WriteField("source", "local"))
		part, err := writer.CreateFormFile("avatar", "avatar.png")
		require.NoError(t, err)
		require.NoError(t, png.Encode(part, img))
		require.NoError(t, writer.Close())
		req := NewRequestWithBody(t, "POST", "/org3/proj/pub/settings/avatar", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		session.MakeRequest(t, req, http.StatusSeeOther)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: f.pub.ID})
		assert.NotEmpty(t, repo.CustomAvatarRelativePath())
	})

	t.Run("json", func(t *testing.T) {
		for _, title := range []string{"first", "second"} {
			session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/proj/pub/issues/new", map[string]string{"title": title}), http.StatusOK)
		}
		first := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: f.pub.ID, Title: "first"})
		resp := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/org3/proj/pub/issues/%d", first.Index)), http.StatusOK)
		assert.Contains(t, resp.Body.String(), `id="repolink" value="org3/proj/pub"`)
		second := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{RepoID: f.pub.ID, Title: "second"})
		for _, issue := range []*issues_model.Issue{first, second} {
			session.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/org3/proj/pub/issues/%d/pin", issue.Index)), http.StatusOK)
		}
		second = unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: second.ID})
		require.Equal(t, 2, second.PinOrder)

		body, err := json.Marshal(map[string]int64{"id": second.ID, "position": 1})
		require.NoError(t, err)
		req := NewRequestWithBody(t, "POST", "/org3/proj/pub/-/issues/move_pin", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		session.MakeRequest(t, req, http.StatusNoContent)
		second = unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: second.ID})
		assert.Equal(t, 1, second.PinOrder)
	})
}

// Route-pattern checks (maintenance, archived organization, rate limits) see the repository route of a request in
// a project.
func TestRepoGroupWebRouteChecks(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	f := prepareRepoGroupWeb(t)
	session := loginUser(t, "user2")

	t.Run("archived organization", func(t *testing.T) {
		_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_archived = ? WHERE id = ?", true, f.org.ID)
		require.NoError(t, err)
		defer func() {
			_, err := db.GetEngine(db.DefaultContext).Exec("UPDATE `user` SET is_archived = ? WHERE id = ?", false, f.org.ID)
			require.NoError(t, err)
		}()
		session.MakeRequest(t, NewRequest(t, "GET", "/org3/proj/pub/-/issues"), http.StatusOK)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/proj/pub/-/issues/new", map[string]string{"title": "x"}), http.StatusForbidden)
		assert.Zero(t, unittest.GetCount(t, &issues_model.Issue{RepoID: f.pub.ID}))
	})

	t.Run("maintenance", func(t *testing.T) {
		defer setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})()
		resp := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/proj/pub/-/issues/new", map[string]string{"title": "x"}), http.StatusSeeOther)
		assert.NotContains(t, resp.Header().Get("Location"), "@")
		assertMaintenanceFlash(t, session)
		assert.Zero(t, unittest.GetCount(t, &issues_model.Issue{RepoID: f.pub.ID}))
		// a POST that only reads is allowed, through the route of the repository
		resp = session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/proj/pub/-/markup", map[string]string{"text": "**x**", "mode": "gfm"}), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "<strong>x</strong>")
	})

	t.Run("rate limit", func(t *testing.T) {
		mockRateLimit(t, map[string]setting.RateLimitClass{
			ratelimit.Web:   {AuthenticatedRate: slow, AuthenticatedBurst: 2, AnonymousRate: slow, AnonymousBurst: 2},
			ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		}, "")
		// a page in a project takes one token of the web class
		resp := MakeRequest(t, fromIP(NewRequest(t, "GET", "/org3/proj/pub/-/issues"), "198.51.100.30"), http.StatusOK)
		assert.Equal(t, "2", resp.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "1", resp.Header().Get("X-RateLimit-Remaining"))
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/org3/proj/pub"), "198.51.100.30"), http.StatusOK)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/org3/proj/pub"), "198.51.100.30"), http.StatusTooManyRequests)
		// a failed basic sign-in takes one token of the auth class: the first pass answers 401 itself
		mockRateLimit(t, map[string]setting.RateLimitClass{
			ratelimit.Auth: {AuthenticatedRate: slow, AuthenticatedBurst: 2},
		}, "")
		failedBasic := func(status int) {
			t.Helper()
			req := fromIP(NewRequest(t, "GET", "/org3/proj/pub/-/raw/branch/main/README.md"), "198.51.100.32")
			req.SetBasicAuth("user4", "wrong")
			MakeRequest(t, req, status)
		}
		failedBasic(http.StatusUnauthorized)
		failedBasic(http.StatusUnauthorized)
		failedBasic(http.StatusTooManyRequests)
		mockRateLimit(t, map[string]setting.RateLimitClass{
			ratelimit.Heavy: {AuthenticatedRate: slow, AuthenticatedBurst: 1, AnonymousRate: slow, AnonymousBurst: 1},
		}, "")
		// and a heavy page one of the heavy class
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/org3/proj/pub/-/blame/branch/main/README.md"), "198.51.100.31"), http.StatusOK)
		MakeRequest(t, fromIP(NewRequest(t, "GET", "/org3/proj/pub/-/blame/branch/main/README.md"), "198.51.100.31"), http.StatusTooManyRequests)
	})
}
