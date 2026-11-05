// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"html"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	shared_actions "forgejo.org/routers/web/shared/actions"
	shared_secrets "forgejo.org/routers/web/shared/secrets"
	actions_service "forgejo.org/services/actions"
	"forgejo.org/services/context"
	"forgejo.org/services/forms"
)

const (
	tplEnvironments base.TplName = "repo/settings/environments"
	tplEnvironment  base.TplName = "repo/settings/environment"
)

// environmentLevel is where the environments of a settings page live: the repository's own for now. The handlers and
// templates read the level only from here, so that an organization's environments can reuse them.
type environmentLevel struct {
	Repo *repo_model.Repository
	Link string // the list of environments
}

func environmentLevelOf(ctx *context.Context) *environmentLevel {
	return &environmentLevel{Repo: ctx.Repo.Repository, Link: ctx.Repo.RepoLink + "/settings/actions/environments"}
}

// RequireEnvironmentManager lets only who may manage the environments through the API (reqOwner(unit.TypeActions))
// reach the pages: the owner, for an organization its owners, and site administrators (their permission is Owner).
// Admin collaborators get the 404 the other settings give to whoever can't see them.
func RequireEnvironmentManager(ctx *context.Context) {
	if !ctx.Repo.IsOwner() {
		ctx.NotFound("RequireEnvironmentManager", nil)
		return
	}
	ctx.Data["PageIsSharedSettingsEnvironments"] = true
	ctx.Data["Title"] = ctx.Tr("actions.environments")
}

// EnvironmentAssignment finds the environment of the URL in the level; one of another repository is not found.
func EnvironmentAssignment(ctx *context.Context) {
	level := environmentLevelOf(ctx)
	env, err := actions_model.GetRepoEnvironmentByID(ctx, level.Repo.ID, ctx.ParamsInt64(":environment_id"))
	if errors.Is(err, actions_model.ErrEnvironmentNotFound) {
		ctx.NotFound("GetRepoEnvironmentByID", err)
		return
	} else if err != nil {
		ctx.ServerError("GetRepoEnvironmentByID", err)
		return
	}
	ctx.Data["Environment"] = env
	ctx.Data["EnvironmentLink"] = level.Link + "/" + strconv.FormatInt(env.ID, 10)
}

func assignedEnvironment(ctx *context.Context) (*actions_model.ActionEnvironment, string) {
	return ctx.Data["Environment"].(*actions_model.ActionEnvironment), ctx.Data["EnvironmentLink"].(string)
}

// environmentDeployment is a deployment as the pages show it.
type environmentDeployment struct {
	*actions_model.ActionDeployment
	RefName string
	RunLink string
}

// lastDeployments returns the newest deployment of each environment with the link of its run.
func lastDeployments(ctx *context.Context, repo *repo_model.Repository, ids []int64) (map[int64]*environmentDeployment, error) {
	last, err := actions_model.FindLastDeployments(ctx, repo.ID, ids)
	if err != nil {
		return nil, err
	}
	runIDs := make([]int64, 0, len(last))
	for _, d := range last {
		runIDs = append(runIDs, d.RunID)
	}
	var runs []*actions_model.ActionRun
	if len(runIDs) > 0 {
		if err := db.GetEngine(ctx).In("id", runIDs).And("repo_id = ?", repo.ID).Cols("id", "index").Find(&runs); err != nil {
			return nil, err
		}
	}
	links := make(map[int64]string, len(runs))
	for _, r := range runs {
		links[r.ID] = repo.Link() + "/actions/runs/" + strconv.FormatInt(r.Index, 10)
	}
	out := make(map[int64]*environmentDeployment, len(last))
	for id, d := range last {
		_, name := actions_model.EnvironmentRefKind(d.Ref)
		if name == "" {
			name = d.Ref
		}
		out[id] = &environmentDeployment{ActionDeployment: d, RefName: name, RunLink: links[d.RunID]}
	}
	return out, nil
}

// environmentRow is one environment of the list.
type environmentRow struct {
	*actions_model.ActionEnvironment
	Secrets    int64
	Variables  int64
	Last       *environmentDeployment
	NoReviewer bool
	Summary    template.HTML
}

// HasRules tells if the environment protects anything.
func (r *environmentRow) HasRules() bool {
	e := r.ActionEnvironment
	return e.ReviewsRequired || e.RefPolicy != actions_model.EnvironmentRefAny || e.WaitTimerMinutes > 0 ||
		len(e.RunnerLabels) > 0 || len(e.AllowedWorkflows) > 0
}

// environmentSummary is the one line of the rules of an environment with that many reviewers.
func environmentSummary(ctx *context.Context, e *actions_model.ActionEnvironment, reviewers int) template.HTML {
	var parts []string
	if e.ReviewsRequired {
		parts = append(parts, string(ctx.TrN(reviewers, "actions.environments.summary.reviewers_1", "actions.environments.summary.reviewers_n", reviewers)))
		if e.PreventSelfReview {
			parts = append(parts, string(ctx.Tr("actions.environments.prevent_self_review")))
		}
	}
	switch e.RefPolicy {
	case actions_model.EnvironmentRefProtectedBranches:
		parts = append(parts, string(ctx.Tr("actions.environments.summary.protected_branches")))
	case actions_model.EnvironmentRefPatterns:
		names := make([]string, len(e.RefPatterns))
		for i, p := range e.RefPatterns {
			names[i] = p.Pattern
		}
		parts = append(parts, html.EscapeString(strings.Join(names, ", ")))
	}
	if e.WaitTimerMinutes > 0 {
		parts = append(parts, string(ctx.Tr("actions.environments.summary.wait", e.WaitTimerMinutes)))
	}
	if len(e.RunnerLabels) > 0 {
		parts = append(parts, string(ctx.Tr("actions.environments.summary.runners", strings.Join(e.RunnerLabels, ", "))))
	}
	if len(e.AllowedWorkflows) > 0 {
		parts = append(parts, string(ctx.Tr("actions.environments.summary.workflows", strings.Join(e.AllowedWorkflows, ", "))))
	}
	if len(parts) == 0 {
		parts = append(parts, string(ctx.Tr("actions.environments.no_protection")))
	}
	return template.HTML(strings.Join(parts, " · ")) // every part is escaped above
}

// Environments lists the environments of the level.
func Environments(ctx *context.Context) {
	level := environmentLevelOf(ctx)
	envs, _, err := actions_model.FindRepoEnvironments(ctx, level.Repo.ID, db.ListOptions{})
	if err != nil {
		ctx.ServerError("FindRepoEnvironments", err)
		return
	}
	ids := make([]int64, len(envs))
	for i, e := range envs {
		ids[i] = e.ID
	}
	secrets, variables, err := actions_model.CountEnvironmentSecretsAndVariables(ctx, level.Repo.ID, ids)
	if err != nil {
		ctx.ServerError("CountEnvironmentSecretsAndVariables", err)
		return
	}
	reviewers, err := actions_model.FindReviewersOfEnvironments(ctx, ids)
	if err != nil {
		ctx.ServerError("FindReviewersOfEnvironments", err)
		return
	}
	check, err := actions_service.CheckEnvironmentReviewers(ctx, level.Repo, envs, reviewers)
	if err != nil {
		ctx.ServerError("CheckEnvironmentReviewers", err)
		return
	}
	last, err := lastDeployments(ctx, level.Repo, ids)
	if err != nil {
		ctx.ServerError("lastDeployments", err)
		return
	}
	rows := make([]*environmentRow, len(envs))
	for i, e := range envs {
		rows[i] = &environmentRow{
			ActionEnvironment: e, Secrets: secrets[e.ID], Variables: variables[e.ID], Last: last[e.ID],
			NoReviewer: check.NoReviewer[e.ID], Summary: environmentSummary(ctx, e, len(reviewers[e.ID])),
		}
	}
	ctx.Data["Environments"] = rows
	ctx.Data["EnvironmentsLink"] = level.Link
	ctx.Data["MaxEnvironments"] = actions_model.MaxEnvironmentsPerRepo
	ctx.HTML(http.StatusOK, tplEnvironments)
}

// environmentFormView holds the values of the form, from the stored environment or as posted.
type environmentFormView struct {
	Name              string
	Reviewers         string
	PreventSelfReview bool
	WaitTimer         int
	RefPolicy         int
	Patterns          []actions_model.EnvironmentRefPattern
	RunnerLabels      string
	AllowedWorkflows  string
}

// reviewerOption is one entry of the reviewer picker.
type reviewerOption struct {
	Key    string
	User   *user_model.User
	Team   *org_model.Team
	Reason string // why it can't approve now, "" if it can
}

// prepareEnvironmentForm fills the data of the new/edit page; env is nil on the new page.
func prepareEnvironmentForm(ctx *context.Context, level *environmentLevel, env *actions_model.ActionEnvironment, view *environmentFormView) {
	ctx.Data["Form"] = view
	ctx.Data["EnvironmentsLink"] = level.Link
	ctx.Data["MaxReviewers"] = actions_model.MaxEnvironmentReviewers
	ctx.Data["MaxWaitTimer"] = actions_model.MaxWaitTimerMinutes
	ctx.Data["EmptyPattern"] = actions_model.EnvironmentRefPattern{}
	repo := level.Repo

	// the picker offers the users with access to the repository and the teams of its owner, and keeps the listed
	// ones; nobody the doer can't see
	var listed []*actions_model.ActionEnvironmentReviewer
	for key := range strings.SplitSeq(view.Reviewers, ",") {
		kind, id, _ := strings.Cut(key, ":")
		n, _ := strconv.ParseInt(id, 10, 64)
		if kind == "user" && n > 0 {
			listed = append(listed, &actions_model.ActionEnvironmentReviewer{UserID: n})
		} else if kind == "team" && n > 0 {
			listed = append(listed, &actions_model.ActionEnvironmentReviewer{TeamID: n})
		}
	}
	readers, err := access_model.GetRepoReaders(ctx, repo)
	if err != nil {
		ctx.ServerError("GetRepoReaders", err)
		return
	}
	candidateIDs := make([]int64, 0, len(readers)+len(listed))
	for _, u := range readers {
		candidateIDs = append(candidateIDs, u.ID)
	}
	for _, r := range listed {
		if r.UserID > 0 {
			candidateIDs = append(candidateIDs, r.UserID)
		}
	}
	users, err := user_model.GetUsersByIDs(ctx, candidateIDs)
	if err != nil {
		ctx.ServerError("GetUsersByIDs", err)
		return
	}
	var teams []*org_model.Team
	if repo.Owner.IsOrganization() {
		if teams, err = org_model.FindOrgTeams(ctx, repo.OwnerID); err != nil {
			ctx.ServerError("FindOrgTeams", err)
			return
		}
	}
	all := make([]*actions_model.ActionEnvironmentReviewer, 0, len(users)+len(teams))
	options := make([]*reviewerOption, 0, len(users)+len(teams))
	for _, u := range users {
		if !u.IsIndividual() || !user_model.IsUserVisibleToViewer(ctx, u, ctx.Doer) {
			continue
		}
		r := &actions_model.ActionEnvironmentReviewer{UserID: u.ID}
		all = append(all, r)
		options = append(options, &reviewerOption{Key: r.Key(), User: u})
	}
	for _, t := range teams {
		r := &actions_model.ActionEnvironmentReviewer{TeamID: t.ID}
		all = append(all, r)
		options = append(options, &reviewerOption{Key: r.Key(), Team: t})
	}
	pseudo := &actions_model.ActionEnvironment{}
	check, err := actions_service.CheckEnvironmentReviewers(ctx, repo, []*actions_model.ActionEnvironment{pseudo}, map[int64][]*actions_model.ActionEnvironmentReviewer{0: all})
	if err != nil {
		ctx.ServerError("CheckEnvironmentReviewers", err)
		return
	}
	isListed := map[string]bool{}
	for _, r := range listed {
		isListed[r.Key()] = true
	}
	offered := options[:0]
	for _, o := range options {
		o.Reason = check.Ineligible[o.Key]
		// a user who can't approve is offered only while listed, so the list shows why
		if o.User == nil || o.Reason == "" || isListed[o.Key] {
			offered = append(offered, o)
		}
	}
	ctx.Data["ReviewerOptions"] = offered
	if env == nil {
		return
	}

	// the warning and the delete confirmation read the stored environment, not the form
	stored, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
	if err != nil {
		ctx.ServerError("FindEnvironmentReviewers", err)
		return
	}
	check, err = actions_service.CheckEnvironmentReviewers(ctx, repo, []*actions_model.ActionEnvironment{env}, map[int64][]*actions_model.ActionEnvironmentReviewer{env.ID: stored})
	if err != nil {
		ctx.ServerError("CheckEnvironmentReviewers", err)
		return
	}
	ctx.Data["NoReviewer"] = check.NoReviewer[env.ID]
	last, err := lastDeployments(ctx, repo, []int64{env.ID})
	if err != nil {
		ctx.ServerError("lastDeployments", err)
		return
	}
	ctx.Data["LastDeployment"] = last[env.ID]

	link := ctx.Data["EnvironmentLink"].(string)
	ctx.Data["SecretsLink"], ctx.Data["VariablesLink"] = link+"/secrets", link+"/variables"
	ctx.Data["SecretsTitle"], ctx.Data["VariablesTitle"] = ctx.Tr("actions.environments.secrets"), ctx.Tr("actions.environments.variables")
	ctx.Data["SecretsDescription"] = ctx.Tr("actions.environments.secrets.desc", env.Name)
	ctx.Data["VariablesDescription"] = ctx.Tr("actions.environments.variables.desc", env.Name)
	shared_secrets.SetSecretsContext(ctx, 0, 0, repo.ID, env.ID)
	shared_actions.SetVariablesContext(ctx, 0, 0, repo.ID, env.ID)
	if ctx.Written() {
		return
	}
	// the names the environment's values replace for its jobs
	overrides := map[string]bool{}
	repoSecrets, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{RepoID: repo.ID})
	if err != nil {
		ctx.ServerError("FindSecrets", err)
		return
	}
	repoVars, err := db.Find[actions_model.ActionVariable](ctx, actions_model.FindVariablesOpts{RepoID: repo.ID})
	if err != nil {
		ctx.ServerError("FindVariables", err)
		return
	}
	for _, s := range repoSecrets {
		overrides[s.Name] = true
	}
	for _, v := range repoVars {
		overrides[v.Name] = true
	}
	ctx.Data["OverridesRepo"] = overrides
}

// EnvironmentNew shows the form of a new environment.
func EnvironmentNew(ctx *context.Context) {
	prepareEnvironmentForm(ctx, environmentLevelOf(ctx), nil, &environmentFormView{})
	if !ctx.Written() {
		ctx.HTML(http.StatusOK, tplEnvironment)
	}
}

// EnvironmentEdit shows the form of an environment with its secrets and variables.
func EnvironmentEdit(ctx *context.Context) {
	env, _ := assignedEnvironment(ctx)
	reviewers, err := actions_model.FindEnvironmentReviewers(ctx, env.ID)
	if err != nil {
		ctx.ServerError("FindEnvironmentReviewers", err)
		return
	}
	keys := make([]string, len(reviewers))
	for i, r := range reviewers {
		keys[i] = r.Key()
	}
	prepareEnvironmentForm(ctx, environmentLevelOf(ctx), env, &environmentFormView{
		Name: env.Name, Reviewers: strings.Join(keys, ","), PreventSelfReview: env.PreventSelfReview,
		WaitTimer: env.WaitTimerMinutes, RefPolicy: env.RefPolicy, Patterns: env.RefPatterns,
		RunnerLabels: strings.Join(env.RunnerLabels, "\n"), AllowedWorkflows: strings.Join(env.AllowedWorkflows, "\n"),
	})
	if !ctx.Written() {
		ctx.HTML(http.StatusOK, tplEnvironment)
	}
}

func lines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// environmentFromForm reads the posted form into the rules of an environment of the level and the IDs of its
// reviewers. A wait timer or ref policy that is no number, or a reviewer entry that is neither a user nor a team, is
// the error of that rule.
func environmentFromForm(form *forms.EnvironmentForm, level *environmentLevel) (env *actions_model.ActionEnvironment, view *environmentFormView, userIDs, teamIDs []int64, err error) {
	view = &environmentFormView{
		Name: form.Name, Reviewers: form.Reviewers, PreventSelfReview: form.PreventSelfReview,
		RunnerLabels: form.RunnerLabels, AllowedWorkflows: form.AllowedWorkflows,
	}
	var parseErr error
	if wait := strings.TrimSpace(form.WaitTimer); wait != "" {
		if view.WaitTimer, parseErr = strconv.Atoi(wait); parseErr != nil {
			err = actions_model.ErrInvalidEnvironmentRule{Field: "wait_timer"}
		}
	}
	if view.RefPolicy, parseErr = strconv.Atoi(form.RefPolicy); parseErr != nil {
		err = actions_model.ErrInvalidEnvironmentRule{Field: "ref_policy"}
	}
	for i, p := range form.Patterns {
		if p = strings.TrimSpace(p); p != "" && i < len(form.PatternTypes) {
			view.Patterns = append(view.Patterns, actions_model.EnvironmentRefPattern{Type: form.PatternTypes[i], Pattern: p})
		}
	}
	env = &actions_model.ActionEnvironment{
		RepoID: level.Repo.ID, Name: form.Name, PreventSelfReview: form.PreventSelfReview, WaitTimerMinutes: view.WaitTimer,
		RefPolicy: view.RefPolicy, RunnerLabels: lines(form.RunnerLabels), AllowedWorkflows: lines(form.AllowedWorkflows),
	}
	if env.RefPolicy == actions_model.EnvironmentRefPatterns {
		env.RefPatterns = view.Patterns // the rows of another choice are left in the page, not saved
	}
	for key := range strings.SplitSeq(form.Reviewers, ",") {
		if key = strings.TrimSpace(key); key == "" {
			continue
		}
		kind, id, _ := strings.Cut(key, ":")
		n, parseErr := strconv.ParseInt(id, 10, 64)
		switch {
		case parseErr != nil:
			err = errBadReviewer
		case kind == "user":
			userIDs = append(userIDs, n)
		case kind == "team":
			teamIDs = append(teamIDs, n)
		default:
			err = errBadReviewer
		}
	}
	return env, view, userIDs, teamIDs, err
}

var errBadReviewer = util.NewInvalidArgumentErrorf("a reviewer is a user or a team")

// environmentError is the message of a refused save; the values the user typed go in as arguments, which Tr escapes.
func environmentError(ctx *context.Context, err error) template.HTML {
	var rule actions_model.ErrInvalidEnvironmentRule
	switch {
	case errors.As(err, &rule):
		switch rule.Field {
		case "name":
			return ctx.Tr("actions.environments.error.name", actions_model.MaxEnvironmentName)
		case "ref_policy":
			return ctx.Tr("actions.environments.error.ref_policy")
		case "ref_patterns":
			if rule.Value != "" {
				return ctx.Tr("actions.environments.error.pattern", rule.Value)
			}
			return ctx.Tr("actions.environments.error.patterns", actions_model.MaxRefPatterns)
		case "wait_timer":
			return ctx.Tr("actions.environments.error.wait_timer", actions_model.MaxWaitTimerMinutes)
		case "runner_labels":
			if rule.Value != "" {
				return ctx.Tr("actions.environments.error.runner_label", rule.Value)
			}
			return ctx.Tr("actions.environments.error.runner_labels", actions_model.MaxRunnerLabels)
		case "allowed_workflows":
			if rule.Value != "" {
				return ctx.Tr("actions.environments.error.workflow", rule.Value)
			}
			return ctx.Tr("actions.environments.error.workflows", actions_model.MaxAllowedWorkflows)
		}
	case errors.Is(err, actions_model.ErrEnvironmentExists):
		return ctx.Tr("actions.environments.error.name_taken")
	case errors.Is(err, actions_model.ErrEnvironmentLimit):
		return ctx.Tr("actions.environments.error.limit", actions_model.MaxEnvironmentsPerRepo)
	}
	return ctx.Tr("actions.environments.error.reviewers", actions_model.MaxEnvironmentReviewers)
}

// saveEnvironment saves the posted form: a new environment when env is nil, otherwise its rules.
func saveEnvironment(ctx *context.Context, env *actions_model.ActionEnvironment) {
	level := environmentLevelOf(ctx)
	form := web.GetForm(ctx).(*forms.EnvironmentForm)
	e, view, userIDs, teamIDs, err := environmentFromForm(form, level)
	if env != nil {
		e.ID, e.Name, view.Name = env.ID, env.Name, env.Name // the name is not edited
	}
	if err == nil && env == nil {
		err = actions_service.CreateEnvironment(ctx, ctx.Doer, e, userIDs, teamIDs)
	} else if err == nil {
		_, err = actions_service.SaveEnvironment(ctx, ctx.Doer, e, userIDs, teamIDs)
	}
	switch {
	case err == nil:
		ctx.Flash.Success(ctx.Tr("actions.environments.saved", e.Name))
		ctx.Redirect(level.Link + "/" + strconv.FormatInt(e.ID, 10))
		return
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Error(http.StatusForbidden)
		return
	case errors.Is(err, util.ErrNotExist): // deleted by another request meanwhile
		ctx.NotFound("SaveEnvironment", err)
		return
	case !errors.Is(err, util.ErrInvalidArgument) && !errors.Is(err, util.ErrAlreadyExist):
		ctx.ServerError("SaveEnvironment", err)
		return
	}
	prepareEnvironmentForm(ctx, level, env, view)
	if ctx.Written() {
		return
	}
	ctx.RenderWithErr(ctx.Tr("actions.environments.error", environmentError(ctx, err)), tplEnvironment, nil)
}

// EnvironmentNewPost creates an environment.
func EnvironmentNewPost(ctx *context.Context) {
	saveEnvironment(ctx, nil)
}

// EnvironmentEditPost saves the rules of an environment.
func EnvironmentEditPost(ctx *context.Context) {
	env, _ := assignedEnvironment(ctx)
	saveEnvironment(ctx, env)
}

// EnvironmentDeletePost deletes an environment once its name is typed.
func EnvironmentDeletePost(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if strings.TrimSpace(ctx.Req.FormValue("confirm_name")) != env.Name {
		ctx.Flash.Error(ctx.Tr("actions.environments.delete.mismatch"))
		ctx.Redirect(link)
		return
	}
	err := actions_service.DeleteEnvironment(ctx, env)
	switch {
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.Error(http.StatusForbidden)
		return
	case errors.Is(err, util.ErrNotExist):
		ctx.NotFound("DeleteEnvironment", err)
		return
	case err != nil:
		ctx.ServerError("DeleteEnvironment", err)
		return
	}
	ctx.Flash.Success(ctx.Tr("actions.environments.deleted", env.Name))
	ctx.Redirect(environmentLevelOf(ctx).Link)
}

// EnvironmentSecretCreate adds a secret to the environment.
func EnvironmentSecretCreate(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_secrets.CreateSecretPost(ctx, 0, 0, env.RepoID, env.ID, link)
}

// EnvironmentSecretEdit changes a secret of the environment.
func EnvironmentSecretEdit(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_secrets.EditSecretPost(ctx, 0, 0, env.RepoID, env.ID, ctx.ParamsInt64(":secret_id"), link)
}

// EnvironmentSecretDelete deletes a secret of the environment.
func EnvironmentSecretDelete(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	shared_secrets.DeleteSecretPost(ctx, 0, 0, env.RepoID, env.ID, ctx.ParamsInt64(":secret_id"), link)
}

// EnvironmentVariableCreate adds a variable to the environment.
func EnvironmentVariableCreate(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_actions.CreateVariable(ctx, 0, 0, env.RepoID, env.ID, link)
}

// EnvironmentVariableUpdate changes a variable of the environment.
func EnvironmentVariableUpdate(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_actions.UpdateVariable(ctx, 0, 0, env.RepoID, env.ID, link)
}

// EnvironmentVariableDelete deletes a variable of the environment.
func EnvironmentVariableDelete(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	shared_actions.DeleteVariable(ctx, 0, 0, env.RepoID, env.ID, link)
}
