// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"errors"
	"html"
	"html/template"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	org_model "forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	secret_model "forgejo.org/models/secret"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/timeutil"
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

// environmentLevel is who the environments of a page belong to: a repository, or an organization (Repo nil), whose
// settings pages share these handlers and templates.
type environmentLevel struct {
	Repo  *repo_model.Repository
	Owner *user_model.User // the organization, or the owner of the repository
	Link  string           // the list of the environments
}

// levelOf returns the level of the page: the repository of the URL, else the organization of its settings.
func levelOf(ctx *context.Context) environmentLevel {
	if repo := ctx.Repo.Repository; repo != nil {
		return environmentLevel{Repo: repo, Owner: repo.Owner, Link: ctx.Repo.RepoLink + "/settings/actions/environments"}
	}
	return environmentLevel{Owner: ctx.Org.Organization.AsUser(), Link: ctx.Org.OrgLink + "/settings/actions/environments"}
}

// scope returns the owner and repository IDs of the level's environments (one of them is 0).
func (l environmentLevel) scope() (ownerID, repoID int64) {
	if l.Repo != nil {
		return 0, l.Repo.ID
	}
	return l.Owner.ID, 0
}

// RequireEnvironmentManager lets only who may manage the environments through the API reach the pages: for a
// repository (reqOwner(unit.TypeActions)) the owner, for an organization its owners, and site administrators (their
// permission is Owner); admin collaborators get the 404 the other settings give to whoever can't see them. The
// organization's own pages are behind OrgAssignment(true, true): its acting owners and site administrators.
func RequireEnvironmentManager(ctx *context.Context) {
	if ctx.Repo.Repository != nil && !ctx.Repo.IsOwner() {
		ctx.NotFound("RequireEnvironmentManager", nil)
		return
	}
	l := levelOf(ctx)
	ctx.Data["PageIsSharedSettingsEnvironments"] = true
	ctx.Data["Title"] = ctx.Tr("actions.environments")
	ctx.Data["EnvironmentOwner"] = l.Owner
	ctx.Data["EnvironmentsArchived"] = l.Owner.IsArchived || l.Repo != nil && l.Repo.IsArchived
}

// EnvironmentAssignment finds the environment of the URL at the page's level; one of another repository or
// organization, or an inherited one on a repository's page, is not found.
func EnvironmentAssignment(ctx *context.Context) {
	l := levelOf(ctx)
	ownerID, repoID := l.scope()
	env, err := actions_model.GetEnvironmentByID(ctx, ownerID, repoID, ctx.ParamsInt64(":environment_id"))
	if errors.Is(err, actions_model.ErrEnvironmentNotFound) {
		ctx.NotFound("GetRepoEnvironmentByID", err)
		return
	} else if err != nil {
		ctx.ServerError("GetRepoEnvironmentByID", err)
		return
	}
	ctx.Data["Environment"] = env
	ctx.Data["EnvironmentLink"] = l.Link + "/" + strconv.FormatInt(env.ID, 10)
}

func assignedEnvironment(ctx *context.Context) (*actions_model.ActionEnvironment, string) {
	return ctx.Data["Environment"].(*actions_model.ActionEnvironment), ctx.Data["EnvironmentLink"].(string)
}

// environmentDeployment is a deployment as the pages show it.
type environmentDeployment struct {
	*actions_model.ActionDeployment
	RefName string
	RunLink string
	Task    *actions_model.ActionTask // the outcome of a released deployment, nil until a runner takes the job
	When    timeutil.TimeStamp        // the last change: of the task, else of the deployment
}

// lastDeployments returns the newest deployment of each environment with the link of its run and, once released,
// its job attempt's task.
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
	ds := make([]*actions_model.ActionDeployment, 0, len(last))
	for _, d := range last {
		ds = append(ds, d)
	}
	tasks, err := actions_model.FindDeploymentTasks(ctx, repo.ID, ds)
	if err != nil {
		return nil, err
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
		row := &environmentDeployment{ActionDeployment: d, RefName: name, RunLink: links[d.RunID], Task: tasks[d.ID], When: d.Updated}
		if row.Task != nil && row.Task.Updated > row.When {
			row.When = row.Task.Updated
		}
		out[id] = row
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

// environmentSummary is the one line of the rules of an environment with that many reviewers ("" without rules).
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
	return template.HTML(strings.Join(parts, " · ")) // every part is escaped above
}

// checkReviewers decides the reviewers of the environments for the page's level: for a repository by the access to it
// (its inherited environments included), for an organization by the rules that don't depend on a repository.
func checkReviewers(ctx *context.Context, l environmentLevel, envs []*actions_model.ActionEnvironment, reviewers map[int64][]*actions_model.ActionEnvironmentReviewer) (*actions_service.EnvironmentReviewerCheck, error) {
	if l.Repo != nil {
		return actions_service.CheckEnvironmentReviewers(ctx, l.Repo, ctx.Doer, envs, reviewers)
	}
	return actions_service.CheckOrgEnvironmentReviewers(ctx, l.Owner, envs, reviewers)
}

// Environments lists the environments of the repository, with those it inherits from its organization apart and
// read-only, or of the organization. The number of queries doesn't depend on the number of environments.
func Environments(ctx *context.Context) {
	l := levelOf(ctx)
	ownerID, repoID := l.scope()
	var envs []*actions_model.ActionEnvironment
	var err error
	if l.Repo != nil {
		envs, _, err = actions_model.FindEnvironmentsOfRepo(ctx, l.Repo.ID, db.ListOptions{})
	} else {
		envs, _, err = actions_model.FindEnvironments(ctx, ownerID, 0, db.ListOptions{})
	}
	if err != nil {
		ctx.ServerError("FindEnvironments", err)
		return
	}
	ids := make([]int64, len(envs))
	inherited := false
	for i, e := range envs {
		ids[i] = e.ID
		inherited = inherited || e.RepoID != repoID
	}
	secrets, variables, err := actions_model.CountEnvironmentSecretsAndVariables(ctx, ownerID, repoID, ids)
	if err == nil && inherited {
		var s, v map[int64]int64
		s, v, err = actions_model.CountEnvironmentSecretsAndVariables(ctx, l.Owner.ID, 0, ids)
		maps.Copy(secrets, s)
		maps.Copy(variables, v)
	}
	if err != nil {
		ctx.ServerError("CountEnvironmentSecretsAndVariables", err)
		return
	}
	reviewers, err := actions_model.FindReviewersOfEnvironments(ctx, ids)
	if err != nil {
		ctx.ServerError("FindReviewersOfEnvironments", err)
		return
	}
	check, err := checkReviewers(ctx, l, envs, reviewers)
	if err != nil {
		ctx.ServerError("CheckEnvironmentReviewers", err)
		return
	}
	last := map[int64]*environmentDeployment{}
	if l.Repo != nil {
		if last, err = lastDeployments(ctx, l.Repo, ids); err != nil {
			ctx.ServerError("lastDeployments", err)
			return
		}
	}
	var rows, inheritedRows []*environmentRow
	for _, e := range envs {
		row := &environmentRow{
			ActionEnvironment: e, Secrets: secrets[e.ID], Variables: variables[e.ID], Last: last[e.ID],
			NoReviewer: check.NoReviewer[e.ID], Summary: environmentSummary(ctx, e, len(reviewers[e.ID])),
		}
		if e.RepoID != repoID {
			inheritedRows = append(inheritedRows, row)
		} else {
			rows = append(rows, row)
		}
	}
	if len(inheritedRows) > 0 {
		// only who may change them gets the link to the organization's page (OrgAssignment(true, true))
		isOwner, err := org_model.OrgFromUser(l.Owner).IsActingOwner(ctx, ctx.Doer)
		if err != nil {
			ctx.ServerError("IsActingOwner", err)
			return
		}
		ctx.Data["InheritedEnvironments"] = inheritedRows
		ctx.Data["OrgEnvironmentsLink"] = l.Owner.OrganisationLink() + "/settings/actions/environments"
		ctx.Data["CanEditInherited"] = isOwner || ctx.Doer.IsAdmin
	}
	ctx.Data["Environments"] = rows
	ctx.Data["EnvironmentsLink"] = l.Link
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
	// Unknown is a listed reviewer that no longer exists or the doer can't see: shown only to be removed
	Unknown bool
}

// parseReviewers reads the listed reviewers of the form ("user:<id>" and "team:<id>", comma separated): at most
// MaxEnvironmentReviewers of them, with ErrTooManyReviewers for more and errBadReviewer for an entry that is neither.
func parseReviewers(keys string) (listed []*actions_model.ActionEnvironmentReviewer, err error) {
	for key := range strings.SplitSeq(keys, ",") {
		if key = strings.TrimSpace(key); key == "" {
			continue
		}
		kind, id, _ := strings.Cut(key, ":")
		n, parseErr := strconv.ParseInt(id, 10, 64)
		r := &actions_model.ActionEnvironmentReviewer{}
		switch {
		case parseErr != nil || n <= 0:
			err = errBadReviewer
			continue
		case kind == "user":
			r.UserID = n
		case kind == "team":
			r.TeamID = n
		default:
			err = errBadReviewer
			continue
		}
		if len(listed) == actions_model.MaxEnvironmentReviewers {
			return listed, actions_service.ErrTooManyReviewers
		}
		listed = append(listed, r)
	}
	return listed, err
}

// prepareEnvironmentForm fills the data of the new/edit page; env is nil on the new page, stored are its reviewers.
func prepareEnvironmentForm(ctx *context.Context, env *actions_model.ActionEnvironment, stored []*actions_model.ActionEnvironmentReviewer, view *environmentFormView) {
	l := levelOf(ctx)
	ownerID, repoID := l.scope()
	ctx.Data["Form"] = view
	ctx.Data["EnvironmentsLink"] = l.Link
	ctx.Data["MaxReviewers"] = actions_model.MaxEnvironmentReviewers
	ctx.Data["MaxWaitTimer"] = actions_model.MaxWaitTimerMinutes
	ctx.Data["MaxWaitTimerDays"] = actions_model.MaxWaitTimerMinutes / (24 * 60)
	ctx.Data["EmptyPattern"] = actions_model.EnvironmentRefPattern{}
	ctx.Data["ReviewerTeams"] = l.Owner.IsOrganization()

	// The picker offers the users who can approve through their access to the repository (the members of the
	// organization for its own environments) and the teams of the organization, and keeps the listed entries (one it can't name is an unknown reviewer, to be removed); nobody the doer
	// can't see. One bulk check decides them all, and the stored reviewers for the warning.
	listed, _ := parseReviewers(view.Reviewers) // the error is the page's already

	var teams []*org_model.Team
	if l.Owner.IsOrganization() {
		var err error
		if teams, err = org_model.FindOrgTeams(ctx, l.Owner.ID); err != nil {
			ctx.ServerError("FindOrgTeams", err)
			return
		}
	}
	offered := slices.Clone(listed)
	for _, t := range teams {
		offered = append(offered, &actions_model.ActionEnvironmentReviewer{TeamID: t.ID})
	}
	envs := []*actions_model.ActionEnvironment{{}} // the form's reviewers, under ID 0
	reviewers := map[int64][]*actions_model.ActionEnvironmentReviewer{0: offered}
	if env != nil {
		// the warning and the delete confirmation read the stored environment, not the form
		envs = append(envs, env)
		reviewers[env.ID] = stored
	}
	check, err := checkReviewers(ctx, l, envs, reviewers)
	if err != nil {
		ctx.ServerError("CheckEnvironmentReviewers", err)
		return
	}
	users := slices.Clone(check.Readers)
	for _, r := range listed {
		if u := check.Users[r.UserID]; u != nil && !slices.ContainsFunc(users, func(x *user_model.User) bool { return x.ID == u.ID }) {
			users = append(users, u)
		}
	}
	visible, err := user_model.VisibleToViewer(ctx, users, ctx.Doer)
	if err != nil {
		ctx.ServerError("VisibleToViewer", err)
		return
	}
	options := make([]*reviewerOption, 0, len(users)+len(teams))
	known := map[string]bool{}
	for _, u := range users {
		if u.IsIndividual() && visible.Contains(u.ID) {
			key := (&actions_model.ActionEnvironmentReviewer{UserID: u.ID}).Key()
			options = append(options, &reviewerOption{Key: key, User: u, Reason: check.Ineligible[key]})
			known[key] = true
		}
	}
	for _, t := range teams {
		key := (&actions_model.ActionEnvironmentReviewer{TeamID: t.ID}).Key()
		options = append(options, &reviewerOption{Key: key, Team: t, Reason: check.Ineligible[key]})
		known[key] = true
	}
	for _, r := range listed {
		if key := r.Key(); !known[key] {
			options = append(options, &reviewerOption{Key: key, Unknown: true})
			known[key] = true
		}
	}
	ctx.Data["ReviewerOptions"] = options
	if env == nil {
		return
	}
	ctx.Data["NoReviewer"] = check.NoReviewer[env.ID]
	if l.Repo != nil {
		last, err := lastDeployments(ctx, l.Repo, []int64{env.ID})
		if err != nil {
			ctx.ServerError("lastDeployments", err)
			return
		}
		ctx.Data["LastDeployment"] = last[env.ID]
	}

	link := ctx.Data["EnvironmentLink"].(string)
	ctx.Data["SecretsLink"], ctx.Data["VariablesLink"] = link+"/secrets", link+"/variables"
	ctx.Data["ActionsReadOnly"] = ctx.Data["EnvironmentsArchived"]
	ctx.Data["SecretsTitle"], ctx.Data["VariablesTitle"] = ctx.Tr("actions.environments.secrets"), ctx.Tr("actions.environments.variables")
	if l.Repo != nil {
		ctx.Data["SecretsDescription"] = ctx.Tr("actions.environments.secrets.desc", env.Name)
		ctx.Data["VariablesDescription"] = ctx.Tr("actions.environments.variables.desc", template.HTML("<code>vars.NAME</code>"), env.Name)
	} else {
		ctx.Data["SecretsDescription"] = ctx.Tr("actions.environments.org.secrets.desc", env.Name)
		ctx.Data["VariablesDescription"] = ctx.Tr("actions.environments.org.variables.desc", template.HTML("<code>vars.NAME</code>"), env.Name)
	}
	shared_secrets.SetSecretsContext(ctx, ownerID, 0, repoID, env.ID)
	shared_actions.SetVariablesContext(ctx, ownerID, 0, repoID, env.ID)
	if ctx.Written() {
		return
	}
	// the names the environment's values replace for its jobs, of the repository or the organization
	overrides := map[string]bool{}
	repoSecrets, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{OwnerID: ownerID, RepoID: repoID})
	if err != nil {
		ctx.ServerError("FindSecrets", err)
		return
	}
	repoVars, err := db.Find[actions_model.ActionVariable](ctx, actions_model.FindVariablesOpts{OwnerID: ownerID, RepoID: repoID})
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
	if l.Repo != nil {
		ctx.Data["OverridesRepo"] = overrides
	} else {
		ctx.Data["OverridesOrg"] = overrides
	}
}

// EnvironmentNew shows the form of a new environment.
func EnvironmentNew(ctx *context.Context) {
	prepareEnvironmentForm(ctx, nil, nil, &environmentFormView{})
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
	prepareEnvironmentForm(ctx, env, reviewers, &environmentFormView{
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
// reviewers. A wait timer or ref policy that is no number, or a reviewer list parseReviewers refuses, is the error of
// that rule.
func environmentFromForm(form *forms.EnvironmentForm, l environmentLevel) (env *actions_model.ActionEnvironment, view *environmentFormView, userIDs, teamIDs []int64, err error) {
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
		Name: form.Name, PreventSelfReview: form.PreventSelfReview, WaitTimerMinutes: view.WaitTimer,
		RefPolicy: view.RefPolicy, RunnerLabels: lines(form.RunnerLabels), AllowedWorkflows: lines(form.AllowedWorkflows),
	}
	env.OwnerID, env.RepoID = l.scope()
	if env.RefPolicy == actions_model.EnvironmentRefPatterns {
		env.RefPatterns = view.Patterns // the rows of another choice are left in the page, not saved
	}
	listed, parseErr := parseReviewers(form.Reviewers)
	if parseErr != nil {
		err = parseErr
	}
	for _, r := range listed {
		if r.TeamID > 0 {
			teamIDs = append(teamIDs, r.TeamID)
		} else {
			userIDs = append(userIDs, r.UserID)
		}
	}
	return env, view, userIDs, teamIDs, err
}

var errBadReviewer = util.NewInvalidArgumentErrorf("a reviewer is a user or a team")

// environmentError is the message of a refused save; the values the user typed go in as arguments, which Tr escapes.
func environmentError(ctx *context.Context, err error) template.HTML {
	var rule actions_model.ErrInvalidEnvironmentRule
	var usedBy actions_model.ErrEnvironmentUsedByRepos
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
	case errors.Is(err, actions_model.ErrEnvironmentTakenByOrg):
		return ctx.Tr("actions.environments.error.name_taken_by_org", ctx.Repo.Owner.Name)
	case errors.As(err, &usedBy):
		return ctx.TrN(usedBy.N, "actions.environments.error.name_used_1", "actions.environments.error.name_used_n", usedBy.N)
	case errors.Is(err, actions_model.ErrEnvironmentLimit):
		return ctx.Tr("actions.environments.error.limit", actions_model.MaxEnvironmentsPerRepo)
	case errors.Is(err, actions_service.ErrTooManyReviewers):
		return ctx.Tr("actions.environments.error.too_many_reviewers", actions_model.MaxEnvironmentReviewers)
	case errors.Is(err, actions_service.ErrReviewerNotMember):
		return ctx.Tr("actions.environments.error.reviewer_not_member")
	case errors.Is(err, actions_service.ErrReviewerTwice):
		return ctx.Tr("actions.environments.error.reviewer_twice")
	case errors.Is(err, actions_service.ErrUnknownReviewer), errors.Is(err, errBadReviewer):
		return ctx.Tr("actions.environments.error.reviewers", actions_model.MaxEnvironmentReviewers)
	}
	// a refusal without a message of its own (e.g. a reviewer deleted while saving): its text, escaped by Tr
	return ctx.Tr("actions.environments.error.other", err.Error())
}

// saveEnvironment saves the posted form: a new environment when env is nil, otherwise its rules.
func saveEnvironment(ctx *context.Context, env *actions_model.ActionEnvironment) {
	form := web.GetForm(ctx).(*forms.EnvironmentForm)
	l := levelOf(ctx)
	e, view, userIDs, teamIDs, err := environmentFromForm(form, l)
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
		ctx.Redirect(l.Link + "/" + strconv.FormatInt(e.ID, 10))
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
	var stored []*actions_model.ActionEnvironmentReviewer
	if env != nil {
		var loadErr error
		if stored, loadErr = actions_model.FindEnvironmentReviewers(ctx, env.ID); loadErr != nil {
			ctx.ServerError("FindEnvironmentReviewers", loadErr)
			return
		}
	}
	prepareEnvironmentForm(ctx, env, stored, view)
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
	if ctx.Req.FormValue("confirm_name") != env.Name { // the exact name, as the button's check
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
	ctx.Redirect(levelOf(ctx).Link)
}

// EnvironmentSecretCreate adds a secret to the environment.
func EnvironmentSecretCreate(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_secrets.CreateSecretPost(ctx, env.OwnerID, 0, env.RepoID, env.ID, link)
}

// EnvironmentSecretEdit changes a secret of the environment.
func EnvironmentSecretEdit(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_secrets.EditSecretPost(ctx, env.OwnerID, 0, env.RepoID, env.ID, ctx.ParamsInt64(":secret_id"), link)
}

// EnvironmentSecretDelete deletes a secret of the environment.
func EnvironmentSecretDelete(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	shared_secrets.DeleteSecretPost(ctx, env.OwnerID, 0, env.RepoID, env.ID, ctx.ParamsInt64(":secret_id"), link)
}

// EnvironmentVariableCreate adds a variable to the environment.
func EnvironmentVariableCreate(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_actions.CreateVariable(ctx, env.OwnerID, 0, env.RepoID, env.ID, link)
}

// EnvironmentVariableUpdate changes a variable of the environment.
func EnvironmentVariableUpdate(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	if ctx.HasError() {
		ctx.JSONError(ctx.GetErrMsg())
		return
	}
	shared_actions.UpdateVariable(ctx, env.OwnerID, 0, env.RepoID, env.ID, link)
}

// EnvironmentVariableDelete deletes a variable of the environment.
func EnvironmentVariableDelete(ctx *context.Context) {
	env, link := assignedEnvironment(ctx)
	shared_actions.DeleteVariable(ctx, env.OwnerID, 0, env.RepoID, env.ID, link)
}
