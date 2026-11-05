// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/actions"
	"forgejo.org/modules/base"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	actions_service "forgejo.org/services/actions"
	app_context "forgejo.org/services/context"
)

const tplDeployments base.TplName = "repo/actions/deployments"

// ViewDeployments is the Deployments panel of the run page: the deployment of the current attempt of each job of the
// run that names an environment. Every text is plain, shown escaped; the review comment is the only stored text. The
// texts of the review dialog come from the page (data-locale-*), not with every poll.
type ViewDeployments struct {
	Title     string            `json:"title"`
	State     string            `json:"state"`     // "waiting", "failed" or "": the colour of the panel
	CanReview bool              `json:"canReview"` // the doer may review at least one of them now
	ReviewURL string            `json:"reviewURL"`
	Items     []*ViewDeployment `json:"items"`
}

type ViewDeployment struct {
	JobID           int64  `json:"jobID"`
	JobName         string `json:"jobName"`
	Environment     string `json:"environment"`
	EnvironmentLink string `json:"environmentLink"`
	Status          string `json:"status"` // a job status, for the icon
	Text            string `json:"text"`
	Pane            string `json:"pane"` // the subtitle of the job's pane
	Detail          string `json:"detail"`
	Comment         string `json:"comment"`
	Gate            bool   `json:"gate"`       // the job has no log: its pane shows the deployment instead
	Waiting         bool   `json:"waiting"`    // it waits for a review: the review dialog lists it
	Reviewable      bool   `json:"reviewable"` // the doer may review it now (ReviewChecker.May)
	NotReviewable   string `json:"notReviewable,omitempty"`
}

// maxReviewerNames is how many reviewers "Waiting for a reviewer" names.
const maxReviewerNames = 10

// viewerLocation is the time zone of the doer (their setting), else the server's.
func viewerLocation(ctx *app_context.Context) *time.Location {
	if ctx.Doer == nil {
		return time.Local
	}
	return user_model.GetUserLocation(ctx, ctx.Doer.ID)
}

// formatTime shows t in loc with its zone, in characters that don't break the line.
func formatTime(t timeutil.TimeStamp, loc *time.Location) string {
	return strings.NewReplacer("-", "‑", " ", " ").Replace(t.AsTimeInLocation(loc).Format("2006-01-02 15:04 MST"))
}

// deploymentsLink is the deployments view of the repository, of one environment if name isn't empty.
func deploymentsLink(ctx *app_context.Context, name string) string {
	link := ctx.Repo.RepoLink + "/actions/deployments"
	if name != "" {
		link += "?environment=" + url.QueryEscape(name)
	}
	return link
}

// refusalText is the message of a deployment the gate refused, by its reason code through a fixed switch: never the
// stored text.
func refusalText(ctx *app_context.Context, d *actions_model.ActionDeployment) string {
	switch d.Reason {
	case actions_model.DeploymentReasonRefNotAllowed:
		return ctx.Locale.TrString("actions.deployments.refused.ref_not_allowed", git.RefName(d.Ref).ShortName())
	case actions_model.DeploymentReasonWorkflowNotAllowed:
		return ctx.Locale.TrString("actions.deployments.refused.workflow_not_allowed")
	case actions_model.DeploymentReasonEnvironmentLimit:
		return ctx.Locale.TrString("actions.deployments.refused.environment_limit")
	case actions_model.DeploymentReasonEnvironmentDeleted:
		return ctx.Locale.TrString("actions.deployments.refused.environment_deleted")
	case actions_model.DeploymentReasonInvalidName:
		return ctx.Locale.TrString("actions.deployments.refused.invalid_name")
	case actions_model.DeploymentReasonNotFound:
		return ctx.Locale.TrString("actions.deployments.refused.environment_not_found")
	case actions_model.DeploymentReasonUnsupported:
		return ctx.Locale.TrString("actions.deployments.refused.environment_unsupported")
	}
	return ctx.Locale.TrString("actions.deployments.refused.other")
}

func userName(users map[int64]*user_model.User, id int64) string {
	_, u := user_model.GetUserFromMap(id, users)
	return u.GetDisplayName()
}

// seesReviewers tells if the doer is shown who may review the run's deployments, and that nobody can: those who may
// change the repository's Actions. Everyone else, readers of a public repository included, learns nothing about the
// reviewers, their accounts or their memberships.
func seesReviewers(ctx *app_context.Context) bool {
	return ctx.Doer != nil && ctx.Repo.CanWrite(unit.TypeActions)
}

// viewDeployments builds the Deployments panel of the run, nil if no job of it names an environment, with a fixed
// number of queries however many jobs wait. Who may review is decided by the checker of the review itself.
func viewDeployments(ctx *app_context.Context, run *actions_model.ActionRun, jobs []*actions_model.ActionRunJob) (*ViewDeployments, error) {
	all, err := actions_model.FindRunDeployments(ctx, run.ID)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	current := map[int64]*actions_model.ActionDeployment{}
	var userIDs []int64
	for _, d := range all {
		current[d.JobID] = d // by job and attempt: the last attempt wins
		userIDs = append(userIDs, d.ReviewedBy)
	}
	users, err := actions_service.VisibleUsers(ctx, ctx.Doer, userIDs)
	if err != nil {
		return nil, err
	}
	checker, err := actions_service.NewReviewChecker(ctx, ctx.Doer, run)
	if err != nil {
		return nil, err
	}
	reviewable, err := actions_model.FindReviewableDeployments(ctx, run.ID, actions_service.ReviewCutoff())
	if err != nil {
		return nil, err
	}
	tasks, err := actions_model.FindDeploymentTasks(ctx, run.RepoID, all)
	if err != nil {
		return nil, err
	}
	loc := viewerLocation(ctx)

	type shown struct {
		item *ViewDeployment
		d    *actions_model.ActionDeployment
		env  *actions_model.ActionEnvironment
	}
	var items []shown
	waitingEnvs := map[int64]*actions_model.ActionEnvironment{}
	envReviewers := map[int64][]*actions_model.ActionEnvironmentReviewer{}
	for _, job := range jobs {
		d := current[job.ID]
		if d == nil || d.Attempt != job.Attempt {
			continue
		}
		env, rs, err := checker.Environment(ctx, d.EnvironmentID)
		if err != nil {
			return nil, err
		}
		item := &ViewDeployment{JobID: job.ID, JobName: job.Name, Comment: d.ReviewComment, Status: "blocked", Gate: true}
		if env != nil {
			item.Environment, item.EnvironmentLink = env.Name, deploymentsLink(ctx, env.Name)
			if d.Status == actions_model.DeploymentWaitingReview {
				waitingEnvs[env.ID], envReviewers[env.ID] = env, rs
			}
		}
		items = append(items, shown{item, d, env})
	}
	if len(items) == 0 {
		return nil, nil //nolint:nilnil // nil means no job of the current attempts names an environment
	}
	var runReviewers *actions_service.RunReviewers
	if len(waitingEnvs) > 0 && seesReviewers(ctx) {
		envs := slices.Collect(maps.Values(waitingEnvs))
		if runReviewers, err = actions_service.LoadRunReviewers(ctx, ctx.Doer, run, envs, envReviewers); err != nil {
			return nil, err
		}
	}

	v := &ViewDeployments{ReviewURL: run.Link() + "/deployments/review"}
	waiting, failed := 0, ""
	for _, s := range items {
		item, d, env := s.item, s.d, s.env
		switch d.Status {
		case actions_model.DeploymentWaitingReview:
			waiting++
			item.Waiting, item.Status = true, "waiting"
			if slices.ContainsFunc(reviewable, func(r *actions_model.ActionDeployment) bool { return r.ID == d.ID }) {
				if item.Reviewable, err = checker.May(ctx, d); err != nil {
					return nil, err
				}
			}
			waitingText(ctx, run, env, d, item, runReviewers, loc)
			if env != nil {
				item.Pane = ctx.Locale.TrString("actions.deployments.pane_waiting", env.Name)
			}
		case actions_model.DeploymentWaitingTimer:
			item.Status = "waiting"
			item.Text = ctx.Locale.TrString("actions.deployments.timer", formatTime(d.ReleaseAfterUnix, loc))
			if d.ReviewedBy != 0 {
				item.Text = ctx.Locale.TrString("actions.deployments.approved_timer", userName(users, d.ReviewedBy), formatTime(d.ReleaseAfterUnix, loc))
			}
		case actions_model.DeploymentReleased:
			item.Gate, item.Status = false, "waiting"
			if t := tasks[d.ID]; t != nil {
				item.Status = t.Status.String()
			}
			item.Text = ctx.Locale.TrString("actions.deployments.released")
			if d.ReviewedBy != 0 {
				item.Text = ctx.Locale.TrString("actions.deployments.approved", userName(users, d.ReviewedBy))
				item.Detail = ctx.Locale.TrString("actions.deployments.approved_at", formatTime(d.ReviewedUnix, loc))
			}
		case actions_model.DeploymentRejected:
			item.Status, failed = "failure", ctx.Locale.TrString("actions.deployments.title_rejected")
			item.Text = ctx.Locale.TrString("actions.deployments.rejected", userName(users, d.ReviewedBy))
			item.Detail = ctx.Locale.TrString("actions.deployments.rerun_asks_again", formatTime(d.ReviewedUnix, loc))
		case actions_model.DeploymentExpired:
			item.Status = "failure"
			if failed == "" {
				failed = ctx.Locale.TrString("actions.deployments.title_expired")
			}
			item.Text = ctx.Locale.TrString("actions.deployments.expired")
			item.Detail = ctx.Locale.TrString("actions.deployments.expired_detail", formatTime(d.Created, loc), formatTime(d.Updated, loc))
		case actions_model.DeploymentRefused:
			item.Status = "failure"
			if failed == "" {
				failed = ctx.Locale.TrString("actions.deployments.title_refused")
			}
			item.Text = refusalText(ctx, d)
		case actions_model.DeploymentCancelled:
			item.Gate, item.Status = false, "cancelled"
			item.Text = ctx.Locale.TrString("actions.deployments.cancelled")
		}
		if item.Pane == "" {
			item.Pane = item.Text
		}
		v.CanReview = v.CanReview || item.Reviewable
		v.Items = append(v.Items, item)
	}
	switch {
	case waiting > 0:
		v.State, v.Title = "waiting", string(ctx.Locale.TrPluralString(waiting, "actions.deployments.title_waiting", waiting))
	case failed != "":
		v.State, v.Title = "failed", failed
	default:
		v.Title = ctx.Locale.TrString("actions.deployments.title")
	}
	return v, nil
}

// waitingText says who the deployment waits for. A doer who may review it is asked to; one who may change the
// repository's Actions is shown the listed reviewers, or that nobody can approve; anyone else sees that it waits for a
// review, and the user the self-review rule bars is told so.
func waitingText(ctx *app_context.Context, run *actions_model.ActionRun, env *actions_model.ActionEnvironment, d *actions_model.ActionDeployment, item *ViewDeployment, reviewers *actions_service.RunReviewers, loc *time.Location) {
	item.Detail = ctx.Locale.TrString("actions.deployments.waiting_detail", formatTime(d.Created, loc),
		formatTime(d.Created.AddDuration(setting.Actions.DeploymentApprovalTimeout), loc))
	if item.Reviewable {
		item.Text = ctx.Locale.TrString("actions.deployments.waiting_review")
		return
	}
	item.Text = ctx.Locale.TrString("actions.deployments.waiting_reviewer")
	if env == nil {
		return
	}
	item.NotReviewable = ctx.Locale.TrString("actions.deployments.not_reviewer", env.Name)
	barred := ctx.Doer != nil && env.PreventSelfReview && (ctx.Doer.ID == run.TriggerUserID || ctx.Doer.ID == d.TriggerUserID)
	if barred {
		item.NotReviewable = ctx.Locale.TrString("actions.deployments.self_review", env.Name)
	}
	if reviewers != nil {
		if nobody, selfReview := reviewers.Nobody(env, d); nobody {
			item.Text = ctx.Locale.TrString("actions.deployments.no_reviewer")
			if selfReview && barred { // one message: there is no other reviewer to wait for
				item.Text = ctx.Locale.TrString("actions.deployments.no_reviewer_self", env.Name)
			}
			return
		}
		if names := reviewers.Names(env.ID); len(names) > 0 {
			item.Text = ctx.Locale.TrString("actions.deployments.waiting_for", strings.Join(names[:min(len(names), maxReviewerNames)], ", "))
		}
	}
	if barred {
		item.Detail = item.NotReviewable + " " + item.Detail
	}
}

// ReviewDeploymentsPost approves or rejects deployments of the run with the service of the API (who may review, all or
// nothing, a comment to reject). The jobs must be jobs of the run of this repository.
func ReviewDeploymentsPost(ctx *app_context.Context) {
	_, jobs := getRunJobs(ctx, ctx.ParamsInt64("run"), -1)
	if ctx.Written() {
		return
	}
	run := jobs[0].Run
	state := ctx.FormString("state") // parses the form, also when it isn't multipart
	var jobIDs []int64
	for _, s := range ctx.FormStrings("job_ids") {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil || !slices.ContainsFunc(jobs, func(j *actions_model.ActionRunJob) bool { return j.ID == id }) {
			ctx.NotFound("job_ids", nil)
			return
		}
		jobIDs = append(jobIDs, id)
	}
	if state != "approved" && state != "rejected" {
		ctx.Error(http.StatusUnprocessableEntity)
		return
	}
	// back to the page of the job, not the run's link: its redirect to the latest attempt would take the flash
	page := jobs[0]
	if len(jobIDs) > 0 {
		page = jobs[slices.IndexFunc(jobs, func(j *actions_model.ActionRunJob) bool { return j.ID == jobIDs[0] })]
	}
	link, err := page.HTMLURL(ctx)
	if err != nil {
		ctx.ServerError("HTMLURL", err)
		return
	}
	if len(jobIDs) == 0 || len(jobIDs) > 100 {
		ctx.Flash.Error(ctx.Tr("actions.deployments.flash.no_jobs"))
		ctx.Redirect(link)
		return
	}
	jobIDs = slices.Compact(slices.Sorted(slices.Values(jobIDs)))
	_, err = actions_service.ReviewDeployments(ctx, ctx.Doer, run, jobIDs, state == "approved", ctx.FormString("comment"))
	switch {
	case err == nil && state == "approved":
		ctx.Flash.Success(ctx.Locale.TrPluralString(len(jobIDs), "actions.deployments.flash.approved", len(jobIDs)))
	case err == nil:
		ctx.Flash.Success(ctx.Locale.TrPluralString(len(jobIDs), "actions.deployments.flash.rejected", len(jobIDs)))
	case errors.Is(err, actions_service.ErrReviewForbidden):
		ctx.Error(http.StatusForbidden)
		return
	case errors.Is(err, actions_service.ErrReviewNotWaiting):
		ctx.Flash.Error(ctx.Tr("actions.deployments.flash.not_waiting"))
	case errors.Is(err, actions_service.ErrReviewCommentMissing):
		ctx.Flash.Error(ctx.Tr("actions.deployments.dialog.comment_required"))
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Flash.Error(ctx.Tr("actions.deployments.flash.invalid"))
	default:
		ctx.ServerError("ReviewDeployments", err)
		return
	}
	ctx.Redirect(link)
}

// deploymentRow is a deployment as the deployments view shows it; its fields are those of the settings pages'
// environmentDeployment, so repo/settings/environment_deployment renders its status.
type deploymentRow struct {
	*actions_model.ActionDeployment
	RefName     string
	RunLink     string
	RunTitle    string
	RunIndex    int64
	CommitLink  string
	ShortSHA    string
	Task        *actions_model.ActionTask
	When        timeutil.TimeStamp
	Environment string
	Job         string
	TriggerUser *user_model.User
	Reviewer    *user_model.User
}

// deploymentRows turns a page of deployments into rows with a fixed number of queries.
func deploymentRows(ctx *app_context.Context, ds []*actions_model.ActionDeployment) ([]*deploymentRow, error) {
	repo := ctx.Repo.Repository
	data, err := actions_service.LoadDeploymentData(ctx, ctx.Doer, repo.ID, ds)
	if err != nil {
		return nil, err
	}
	tasks, err := actions_model.FindDeploymentTasks(ctx, repo.ID, ds)
	if err != nil {
		return nil, err
	}
	rows := make([]*deploymentRow, 0, len(ds))
	for _, d := range ds {
		row := &deploymentRow{ActionDeployment: d, RefName: git.RefName(d.Ref).ShortName(), Task: tasks[d.ID], When: d.Updated}
		if row.Task != nil && row.Task.Updated > row.When {
			row.When = row.Task.Updated
		}
		if r := data.Runs[d.RunID]; r != nil {
			row.RunLink, row.RunTitle, row.RunIndex = repo.Link()+"/actions/runs/"+strconv.FormatInt(r.Index, 10), r.Title, r.Index
		}
		if d.CommitSHA != "" {
			row.CommitLink, row.ShortSHA = repo.Link()+"/commit/"+url.PathEscape(d.CommitSHA), base.ShortSha(d.CommitSHA)
		}
		if e := data.Envs[d.EnvironmentID]; e != nil {
			row.Environment = e.Name
		}
		if j := data.Jobs[d.JobID]; j != nil {
			row.Job = j.Name
		}
		if d.TriggerUserID != 0 {
			_, row.TriggerUser = user_model.GetUserFromMap(d.TriggerUserID, data.Users)
		}
		if d.ReviewedBy != 0 {
			_, row.Reviewer = user_model.GetUserFromMap(d.ReviewedBy, data.Users)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// workflowEntries are the workflows of the default branch, for the workflow menu of the deployments view.
func workflowEntries(ctx *app_context.Context) ([]Workflow, error) {
	if empty, err := ctx.Repo.GitRepo.IsEmpty(); err != nil || empty {
		return nil, err
	}
	commit, err := ctx.Repo.GitRepo.GetBranchCommit(ctx.Repo.Repository.DefaultBranch)
	if err != nil {
		return nil, err
	}
	_, entries, err := actions.ListWorkflows(commit)
	if err != nil {
		return nil, err
	}
	workflows := make([]Workflow, 0, len(entries))
	for _, entry := range entries {
		workflows = append(workflows, Workflow{Entry: *entry})
	}
	return workflows, nil
}

// deploymentStatuses are the values of the status filter of the deployments view.
var deploymentStatuses = map[string][]actions_model.DeploymentStatus{
	"waiting":   {actions_model.DeploymentWaitingReview, actions_model.DeploymentWaitingTimer},
	"released":  {actions_model.DeploymentReleased},
	"rejected":  {actions_model.DeploymentRejected},
	"expired":   {actions_model.DeploymentExpired},
	"refused":   {actions_model.DeploymentRefused},
	"cancelled": {actions_model.DeploymentCancelled},
}

// Deployments is the deployments view of the Actions tab: the last deployment of every environment, or with
// ?environment= the history of one, filtered by status, triggering user and ref. Whoever reads the repository's Actions
// sees it, as they see the runs and their logs.
func Deployments(ctx *app_context.Context) {
	ctx.Data["Title"] = ctx.Tr("actions.deployments.title")
	ctx.Data["PageIsActions"] = true
	ctx.Data["PageIsDeployments"] = true
	repo := ctx.Repo.Repository
	envs, _, err := actions_model.FindRepoEnvironments(ctx, repo.ID, db.ListOptions{ListAll: true})
	if err != nil {
		ctx.ServerError("FindRepoEnvironments", err)
		return
	}
	ctx.Data["DeploymentEnvironments"] = envs
	ctx.Data["DeploymentsLink"] = deploymentsLink(ctx, "")
	ctx.Data["RepoLink"] = repo.Link()
	ctx.Data["ActionsConfig"] = repo.MustGetUnit(ctx, unit.TypeActions).ActionsConfig()
	if ctx.Data["workflows"], err = workflowEntries(ctx); err != nil {
		ctx.ServerError("workflowEntries", err)
		return
	}

	name := ctx.FormString("environment")
	var env *actions_model.ActionEnvironment
	if name != "" {
		env, err = actions_model.GetRepoEnvironmentByName(ctx, repo.ID, name)
		if errors.Is(err, actions_model.ErrEnvironmentNotFound) {
			ctx.Data["UnknownEnvironment"] = name
		} else if err != nil {
			ctx.ServerError("GetRepoEnvironmentByName", err)
			return
		}
	}
	if env == nil {
		ids := make([]int64, 0, len(envs))
		for _, e := range envs {
			ids = append(ids, e.ID)
		}
		last, err := actions_model.FindLastDeployments(ctx, repo.ID, ids)
		if err != nil {
			ctx.ServerError("FindLastDeployments", err)
			return
		}
		var ds []*actions_model.ActionDeployment
		var idle []*actions_model.ActionEnvironment
		for _, e := range envs { // in name order
			if d := last[e.ID]; d != nil {
				ds = append(ds, d)
			} else {
				idle = append(idle, e)
			}
		}
		ctx.Data["IdleEnvironments"] = idle
		if ctx.Data["Deployments"], err = deploymentRows(ctx, ds); err != nil {
			ctx.ServerError("deploymentRows", err)
			return
		}
		ctx.HTML(http.StatusOK, tplDeployments)
		return
	}

	ctx.Data["CurEnvironment"] = env
	filter := actions_model.DeploymentFilter{EnvironmentID: env.ID, Statuses: deploymentStatuses[ctx.FormString("status")]}
	ctx.Data["CurStatus"] = ctx.FormString("status")
	if filter.Statuses == nil {
		ctx.Data["CurStatus"] = ""
	}
	filter.TriggerUserID = ctx.FormInt64("actor")
	ctx.Data["CurActor"] = filter.TriggerUserID
	if ref := strings.TrimSpace(ctx.FormString("ref")); ref != "" {
		filter.Refs = []string{ref, git.BranchPrefix + ref, git.TagPrefix + ref}
		ctx.Data["CurRef"] = ref
	}
	actorIDs, err := actions_model.FindDeploymentTriggerUsers(ctx, repo.ID, env.ID)
	if err != nil {
		ctx.ServerError("FindDeploymentTriggerUsers", err)
		return
	}
	actors, err := actions_service.VisibleUsers(ctx, ctx.Doer, actorIDs)
	if err != nil {
		ctx.ServerError("VisibleUsers", err)
		return
	}
	var visibleActors []*user_model.User
	for _, u := range actors {
		if !u.IsGhost() {
			visibleActors = append(visibleActors, u)
		}
	}
	slices.SortFunc(visibleActors, func(a, b *user_model.User) int { return strings.Compare(a.LowerName, b.LowerName) })
	ctx.Data["Actors"] = visibleActors

	page := max(ctx.FormInt("page"), 1)
	opts := db.ListOptions{Page: page, PageSize: 30}
	var ds []*actions_model.ActionDeployment
	var total int64
	// only a user the doer may see filters: one they may not finds nothing, so the filter tells nothing about them
	if filter.TriggerUserID == 0 || slices.ContainsFunc(visibleActors, func(u *user_model.User) bool { return u.ID == filter.TriggerUserID }) {
		if ds, total, err = actions_model.FindRepoDeployments(ctx, repo.ID, filter, opts); err != nil {
			ctx.ServerError("FindRepoDeployments", err)
			return
		}
	}
	if ctx.Data["Deployments"], err = deploymentRows(ctx, ds); err != nil {
		ctx.ServerError("deploymentRows", err)
		return
	}
	pager := app_context.NewPagination(int(total), opts.PageSize, page, 5)
	pager.AddParamString("environment", env.Name)
	pager.AddParamString("status", ctx.Data["CurStatus"].(string))
	if filter.TriggerUserID != 0 {
		pager.AddParamString("actor", strconv.FormatInt(filter.TriggerUserID, 10))
	}
	if ref, ok := ctx.Data["CurRef"].(string); ok {
		pager.AddParamString("ref", ref)
	}
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplDeployments)
}
