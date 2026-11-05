// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	actions_model "forgejo.org/models/actions"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/test"
	actions_web "forgejo.org/routers/web/repo/actions"
	"forgejo.org/services/mailer"
	"forgejo.org/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deploymentMails records the mails the deployment code sends.
type deploymentMails struct {
	mu   sync.Mutex
	sent []*mailer.Message
}

func (m *deploymentMails) to(subjectPart string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var to []string
	for _, msg := range m.sent {
		if strings.Contains(msg.Subject, subjectPart) {
			to = append(to, msg.To)
		}
	}
	return to
}

func (m *deploymentMails) body(subjectPart string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, msg := range m.sent {
		if strings.Contains(msg.Subject, subjectPart) {
			return msg.Body
		}
	}
	return ""
}

// The run page's Deployments panel, the review through the web, the mails and the deployments view, each through the
// real Actions, web and mail code: who sees the button, who may review, what is refused and what is recorded.
func TestActionsDeploymentsWeb(t *testing.T) {
	if !setting.Database.Type.IsSQLite3() {
		t.Skip()
	}
	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		mails := &deploymentMails{}
		defer test.MockVariableValue(&mailer.SendAsync, func(msgs ...*mailer.Message) {
			mails.mu.Lock()
			defer mails.mu.Unlock()
			mails.sent = append(mails.sent, msgs...)
		})()

		user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		user4 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		ownerToken := getUserToken(t, user2.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		apiRepo := createActionsTestRepo(t, ownerToken, "actions-deploy-web", false)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: apiRepo.ID})
		ctx := audit_model.WithSystem(t.Context(), "test")
		MakeRequest(t, NewRequestWithJSON(t, "PUT", fmt.Sprintf("/api/v1/repos/%s/%s/collaborators/%s", user2.Name, repo.Name, user4.Name),
			&api.AddCollaboratorOption{Permission: new("read")}).AddTokenAuth(ownerToken), http.StatusNoContent)
		env := &actions_model.ActionEnvironment{RepoID: repo.ID, Name: "prod"}
		require.NoError(t, actions_model.CreateEnvironment(ctx, env, nil))
		require.NoError(t, setEnvironmentReviewers(ctx, env, []int64{user4.ID}, nil))

		owner := loginUser(t, user2.Name)
		reviewer := loginUser(t, user4.Name)
		stranger := loginUser(t, "user5") // a signed-in user who only reads the public repository
		anonymous := emptyTestSession(t)

		files := 0
		pushJob := func(t *testing.T, message string) (*actions_model.ActionRun, *actions_model.ActionRunJob) {
			files++
			path := fmt.Sprintf(".gitea/workflows/deploy%d.yml", files)
			content := fmt.Sprintf("name: deploy%d\non:\n  push:\n    paths:\n      - '%s'\njobs:\n  deploy:\n    runs-on: dw-%d\n    environment: prod\n    steps:\n      - run: echo hi\n", files, path, files)
			fileResp := createWorkflowFile(t, ownerToken, user2.Name, repo.Name, path, getWorkflowCreateFileOptions(user2, repo.DefaultBranch, message, content))
			run := new(actions_model.ActionRun)
			require.Eventually(t, func() bool {
				has, err := db.GetEngine(db.DefaultContext).Where("repo_id = ? AND commit_sha = ?", repo.ID, fileResp.Commit.SHA).Get(run)
				return err == nil && has
			}, 10*time.Second, 100*time.Millisecond)
			jobs, err := actions_model.GetRunJobsByRunID(t.Context(), run.ID)
			require.NoError(t, err)
			require.Len(t, jobs, 1)
			require.Eventually(t, func() bool {
				d, err := actions_model.GetDeployment(db.DefaultContext, jobs[0].ID, 1)
				return err == nil && d != nil && d.Status == actions_model.DeploymentWaitingReview
			}, 10*time.Second, 100*time.Millisecond)
			return run, jobs[0]
		}
		deployment := func(t *testing.T, job *actions_model.ActionRunJob) *actions_model.ActionDeployment {
			j := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: job.ID})
			d, err := actions_model.GetDeployment(t.Context(), j.ID, j.Attempt)
			require.NoError(t, err)
			require.NotNil(t, d)
			return d
		}
		runLink := func(run *actions_model.ActionRun) string {
			return fmt.Sprintf("/%s/%s/actions/runs/%d", user2.Name, repo.Name, run.Index)
		}
		panel := func(t *testing.T, s *TestSession, run *actions_model.ActionRun, attempt int64) *actions_web.ViewDeployments {
			t.Helper()
			resp := s.MakeRequest(t, NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/jobs/0/attempt/%d", runLink(run), attempt), map[string]any{"logCursors": []any{}}), http.StatusOK)
			var out actions_web.ViewResponse
			DecodeJSON(t, resp, &out)
			return out.State.Run.Deployments
		}
		review := func(t *testing.T, s *TestSession, run *actions_model.ActionRun, state, comment string, status int, jobIDs ...int64) {
			t.Helper()
			values := url.Values{"state": {state}, "comment": {comment}}
			for _, id := range jobIDs {
				values.Add("job_ids", strconv.FormatInt(id, 10))
			}
			req := NewRequestWithBody(t, "POST", runLink(run)+"/deployments/review", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			s.MakeRequest(t, req, status)
		}
		flash := flashMessage
		auditSince := func(t *testing.T, since int64, action string) int {
			n, err := db.GetEngine(t.Context()).Where("id > ? AND action LIKE ?", since, action+"%").Count(new(audit_model.Entry))
			require.NoError(t, err)
			return int(n)
		}
		auditNow := func(t *testing.T) int64 {
			var id int64
			_, err := db.GetEngine(t.Context()).Table("audit_event").Select("COALESCE(MAX(id), 0)").Get(&id)
			require.NoError(t, err)
			return id
		}

		run, job := pushJob(t, "<b>deploy</b> now")
		// the eligible reviewers are mailed once, after the change committed, with a link to the run and no markup
		require.Eventually(t, func() bool { return len(mails.to("waiting for your review")) == 1 }, 10*time.Second, 50*time.Millisecond)
		assert.Equal(t, []string{user4.EmailTo()}, mails.to("waiting for your review"))
		body := mails.body("waiting for your review")
		assert.Contains(t, body, setting.AppURL+runLink(run)[1:])
		assert.Contains(t, body, "&lt;b&gt;deploy&lt;/b&gt; now")
		assert.NotContains(t, body, "<b>deploy")

		t.Run("the panel shows the button only to an eligible reviewer", func(t *testing.T) {
			p := panel(t, reviewer, run, 1)
			require.NotNil(t, p)
			assert.Equal(t, "waiting", p.State)
			assert.True(t, p.CanReview)
			require.Len(t, p.Items, 1)
			assert.True(t, p.Items[0].Reviewable)
			assert.Equal(t, "prod", p.Items[0].Environment)
			assert.Equal(t, runLink(run)+"/deployments/review", p.ReviewURL)

			for name, s := range map[string]*TestSession{"owner": owner, "stranger": stranger, "anonymous": anonymous} {
				p := panel(t, s, run, 1)
				require.NotNil(t, p, name)
				assert.False(t, p.CanReview, name)
				assert.False(t, p.Items[0].Reviewable, name)
				assert.Equal(t, "Waiting for a reviewer: "+user4.GetDisplayName(), p.Items[0].Text, name)
			}
		})

		t.Run("a user who may not review is refused with no change and no record", func(t *testing.T) {
			since := auditNow(t)
			review(t, owner, run, "approved", "", http.StatusForbidden, job.ID)
			review(t, stranger, run, "rejected", "no", http.StatusForbidden, job.ID)
			review(t, anonymous, run, "approved", "", http.StatusSeeOther, job.ID) // to the sign-in page
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(t, job).Status)
			assert.Zero(t, auditSince(t, since, "repo.actions_deployment."))
		})

		t.Run("another run's job or another repository's run is not found", func(t *testing.T) {
			other, otherJob := pushJob(t, "other")
			review(t, reviewer, run, "approved", "", http.StatusNotFound, otherJob.ID)
			review(t, reviewer, run, "approved", "", http.StatusNotFound, job.ID, otherJob.ID)
			review(t, reviewer, run, "approved", "", http.StatusNotFound, 0)
			// user2/repo1 has no run of that index
			req := NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/actions/runs/%d/deployments/review", other.Index+1000),
				map[string]string{"state": "approved", "job_ids": strconv.FormatInt(job.ID, 10)})
			reviewer.MakeRequest(t, req, http.StatusNotFound)
			review(t, reviewer, run, "maybe", "", http.StatusUnprocessableEntity, job.ID)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(t, job).Status)
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(t, otherJob).Status)
		})

		t.Run("archived repositories and maintenance mode refuse a review", func(t *testing.T) {
			_, err := db.GetEngine(t.Context()).Exec("UPDATE repository SET is_archived = ? WHERE id = ?", true, repo.ID)
			require.NoError(t, err)
			review(t, reviewer, run, "approved", "", http.StatusNotFound, job.ID)
			_, err = db.GetEngine(t.Context()).Exec("UPDATE repository SET is_archived = ? WHERE id = ?", false, repo.ID)
			require.NoError(t, err)

			restore := setMaintenance(t, setting.MaintenanceReadOnly, time.Time{})
			review(t, reviewer, run, "approved", "", http.StatusSeeOther, job.ID)
			assert.Contains(t, flash(t, reviewer), "read-only mode")
			restore()
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(t, job).Status)
		})

		t.Run("a rejection needs a comment, is recorded and mails the user who started the attempt", func(t *testing.T) {
			since := auditNow(t)
			review(t, reviewer, run, "rejected", "  ", http.StatusSeeOther, job.ID)
			assert.Contains(t, flash(t, reviewer), "A comment is required to reject.")
			assert.Equal(t, actions_model.DeploymentWaitingReview, deployment(t, job).Status)
			review(t, reviewer, run, "rejected", "", http.StatusSeeOther)
			assert.Contains(t, flash(t, reviewer), "Choose at least one deployment to review.")

			review(t, reviewer, run, "rejected", "not <b>now</b>", http.StatusSeeOther, job.ID)
			assert.Contains(t, flash(t, reviewer), "The deployments were rejected.")
			d := deployment(t, job)
			assert.Equal(t, actions_model.DeploymentRejected, d.Status)
			assert.Equal(t, user4.ID, d.ReviewedBy)
			assert.Equal(t, "not <b>now</b>", d.ReviewComment)
			assert.Equal(t, 1, auditSince(t, since, "repo.actions_deployment.rejected"))
			require.Eventually(t, func() bool { return len(mails.to("prod rejected")) == 1 }, 10*time.Second, 50*time.Millisecond)
			assert.Equal(t, []string{user2.EmailTo()}, mails.to("prod rejected"))
			assert.Contains(t, mails.body("prod rejected"), "not &lt;b&gt;now&lt;/b&gt;")

			// a second review of it is not a review any more
			review(t, reviewer, run, "approved", "", http.StatusSeeOther, job.ID)
			assert.Contains(t, flash(t, reviewer), "no longer waiting")

			p := panel(t, owner, run, 1)
			assert.Equal(t, "failed", p.State)
			assert.Equal(t, "Rejected by "+user4.GetDisplayName(), p.Items[0].Text)
			assert.Equal(t, "not <b>now</b>", p.Items[0].Comment, "plain text, escaped by the page")
		})

		t.Run("a rerun asks again, mails again, and an approval releases the job", func(t *testing.T) {
			owner.MakeRequest(t, NewRequest(t, "POST", runLink(run)+"/jobs/0/rerun"), http.StatusOK)
			require.Eventually(t, func() bool {
				j := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: job.ID})
				d, err := actions_model.GetDeployment(db.DefaultContext, j.ID, j.Attempt)
				return j.Attempt == 2 && err == nil && d != nil && d.Status == actions_model.DeploymentWaitingReview
			}, 10*time.Second, 100*time.Millisecond)
			require.Eventually(t, func() bool { return len(mails.to("waiting for your review")) == 3 }, 10*time.Second, 50*time.Millisecond,
				"the first run, the other run and the new attempt")

			since := auditNow(t)
			review(t, reviewer, run, "approved", "", http.StatusSeeOther, job.ID)
			assert.Contains(t, flash(t, reviewer), "The deployments were approved.")
			d := deployment(t, job)
			assert.Equal(t, actions_model.DeploymentReleased, d.Status)
			assert.Equal(t, user4.ID, d.ReviewedBy)
			assert.Equal(t, 1, auditSince(t, since, "repo.actions_deployment.approved"))
			assert.Len(t, mails.to("waiting for your review"), 3, "a gate pass after the approval mails nobody")
			assert.Empty(t, mails.to("expired"))
		})

		t.Run("the deployments view lists the last deployment of each environment and one environment's history", func(t *testing.T) {
			link := fmt.Sprintf("/%s/%s/actions/deployments", user2.Name, repo.Name)
			for _, s := range []*TestSession{anonymous, stranger, owner} {
				doc := NewHTMLParser(t, s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK).Body)
				assert.Equal(t, 1, doc.Find("#deployment-list .deployment-item").Length())
				assert.Contains(t, text(doc, "#deployments-menu"), "prod")
			}
			doc := NewHTMLParser(t, anonymous.MakeRequest(t, NewRequest(t, "GET", link+"?environment=prod"), http.StatusOK).Body)
			assert.Equal(t, 3, doc.Find("#deployment-list .deployment-item").Length(), "two attempts of one job and the other run")
			assert.Contains(t, text(doc, "#deployment-list"), "<b>deploy</b> now", "titles are text")
			assert.Contains(t, text(doc, ".deployment-comment"), "not <b>now</b>")
			assert.Zero(t, doc.Find("#deployment-list b").Length(), "nothing stored renders as markup")

			count := func(query string) int {
				doc := NewHTMLParser(t, anonymous.MakeRequest(t, NewRequest(t, "GET", link+"?environment=prod&"+query), http.StatusOK).Body)
				return doc.Find("#deployment-list .deployment-item").Length()
			}
			assert.Equal(t, 1, count("status=rejected"))
			assert.Equal(t, 1, count("status=released"))
			assert.Equal(t, 1, count("status=waiting"))
			assert.Equal(t, 3, count("status=bogus"), "an unknown status is no filter")
			assert.Equal(t, 3, count("actor="+strconv.FormatInt(user2.ID, 10)))
			assert.Equal(t, 0, count("actor="+strconv.FormatInt(user4.ID, 10)))
			assert.Equal(t, 3, count("ref=main"))
			assert.Equal(t, 0, count("ref=other"))

			doc = NewHTMLParser(t, anonymous.MakeRequest(t, NewRequest(t, "GET", link+"?environment=%3Cb%3Egone"), http.StatusOK).Body)
			assert.Contains(t, text(doc, "#deployments-unknown"), `named "<b>gone"`)
			assert.Zero(t, doc.Find("#deployments-unknown b").Length())

			// the Actions tab links to it
			doc = NewHTMLParser(t, anonymous.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/%s/%s/actions", user2.Name, repo.Name)), http.StatusOK).Body)
			assert.Equal(t, 1, doc.Find(`#deployments-menu a[href="`+link+`?environment=prod"]`).Length())
		})

		t.Run("the last reviewer of an environment is named to a site administrator", func(t *testing.T) {
			admin := loginUser(t, "user1")
			doc := NewHTMLParser(t, admin.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/admin/users/%d/edit", user4.ID)), http.StatusOK).Body)
			box := text(doc, ".last-approver-warnings")
			assert.Contains(t, box, fmt.Sprintf("Environment prod of %s/%s (Deployment environment)", user2.Name, repo.Name))
			assert.Equal(t, 1, doc.Find(fmt.Sprintf(`.last-approver-warnings a[href="/%s/%s/settings/actions/environments/%d"]`, user2.Name, repo.Name, env.ID)).Length())
		})

		t.Run("a private repository's view and panel are not found for non-readers", func(t *testing.T) {
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/%s/%s", user2.Name, repo.Name), &api.EditRepoOption{Private: new(true)}).AddTokenAuth(ownerToken), http.StatusOK)
			defer MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/%s/%s", user2.Name, repo.Name), &api.EditRepoOption{Private: new(false)}).AddTokenAuth(ownerToken), http.StatusOK)
			// a user's repository going private doesn't recalculate the access table (only an organization's does), so
			// the read collaborator's row, dropped while the repository was public, is restored here
			require.NoError(t, access_model.RecalculateAccesses(t.Context(), repo))
			link := fmt.Sprintf("/%s/%s/actions/deployments", user2.Name, repo.Name)
			for _, s := range []*TestSession{anonymous, stranger} {
				s.MakeRequest(t, NewRequest(t, "GET", link), http.StatusNotFound)
				s.MakeRequest(t, NewRequestWithJSON(t, "POST", runLink(run)+"/jobs/0/attempt/1", map[string]any{"logCursors": []any{}}), http.StatusNotFound)
			}
			reviewer.MakeRequest(t, NewRequest(t, "GET", link), http.StatusOK)
		})
	})
}

// The deployments view runs a fixed number of queries, whatever the number of deployments, runs, jobs and users.
func TestActionsDeploymentsWebQueries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ctx := audit_model.WithSystem(t.Context(), "test")
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	session := loginUser(t, "user2")

	n := 0
	add := func(k int) {
		for range k {
			n++
			u := &user_model.User{Name: fmt.Sprintf("dq-%d", n), Email: fmt.Sprintf("dq-%d@example.com", n), IsActive: true}
			require.NoError(t, user_model.CreateUser(db.DefaultContext, u))
			run := &actions_model.ActionRun{RepoID: repo.ID, OwnerID: repo.OwnerID, Index: int64(9000 + n), Title: fmt.Sprintf("run %d", n), TriggerUserID: u.ID, Status: actions_model.StatusBlocked}
			require.NoError(t, db.Insert(db.DefaultContext, run))
			job := &actions_model.ActionRunJob{RunID: run.ID, RepoID: repo.ID, OwnerID: repo.OwnerID, Name: "deploy", Attempt: 1, Status: actions_model.StatusBlocked, Handle: fmt.Sprintf("dq-%d", n)}
			require.NoError(t, db.Insert(db.DefaultContext, job))
			env, err := actions_model.GetRepoEnvironmentByName(ctx, repo.ID, "prod")
			require.NoError(t, err)
			require.NoError(t, db.Insert(db.DefaultContext, &actions_model.ActionDeployment{
				RepoID: repo.ID, RunID: run.ID, JobID: job.ID, Attempt: 1, EnvironmentID: env.ID, Status: actions_model.DeploymentRejected,
				Ref: "refs/heads/main", TriggerUserID: u.ID, ReviewedBy: u.ID, ReviewComment: "no",
			}))
		}
	}
	require.NoError(t, actions_model.CreateEnvironment(ctx, &actions_model.ActionEnvironment{RepoID: repo.ID, Name: "prod"}, nil))
	counts := func() []int64 {
		var out []int64
		for _, l := range []string{"/user2/repo1/actions/deployments", "/user2/repo1/actions/deployments?environment=prod"} {
			session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) // generated avatars are saved once
			out = append(out, stableQueryCount(t, func() { session.MakeRequest(t, NewRequest(t, "GET", l), http.StatusOK) }))
		}
		return out
	}
	add(1)
	one := counts()
	add(20)
	assert.Equal(t, one, counts())
}
