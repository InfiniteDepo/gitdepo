// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// orgRunsMaxValues caps the values of a repeatable filter.
const orgRunsMaxValues = 20

// OrgRunFilter is what the runs list of an organization can be narrowed by. The filters are ANDed.
type OrgRunFilter struct {
	Statuses []actions_model.Status
	Events   []string
	Repo     string // name of a repository of the organization
	Workflow string // file name of the workflow
	Branch   string
	Actor    string // user name of the person who triggered the run
	From, To timeutil.TimeStamp
}

// OrgRunsEnabled says whether Actions is on for the instance, which the org runs list needs as the repository pages do.
func OrgRunsEnabled() bool {
	return setting.Actions.Enabled && !unit.TypeActions.UnitGlobalDisabled()
}

// FormGetter is the part of the web and API contexts that reads query parameters.
type FormGetter interface {
	FormString(key string) string
	FormStrings(key string) []string
}

func dedupe(values []string) []string {
	out := make([]string, 0, min(len(values), orgRunsMaxValues))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) && len(out) < orgRunsMaxValues {
			out = append(out, v)
		}
	}
	return out
}

func parseOrgRunTime(value string, endOfDay bool) (timeutil.TimeStamp, error) {
	if value == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		if t, err = time.Parse(time.DateOnly, value); err != nil {
			return 0, fmt.Errorf("invalid time %q, want RFC 3339 or YYYY-MM-DD", value)
		}
		if endOfDay {
			t = t.AddDate(0, 0, 1).Add(-time.Second)
		}
	}
	return timeutil.TimeStamp(t.Unix()), nil
}

// ParseOrgRunFilter reads the filter from query parameters: the repeatable status and event, and repo, workflow_id,
// branch, actor, from and to (RFC 3339 or YYYY-MM-DD). An unknown status or a bad time is an error.
func ParseOrgRunFilter(form FormGetter) (f OrgRunFilter, err error) {
	for _, name := range dedupe(form.FormStrings("status")) {
		status, ok := actions_model.StatusFromString(name)
		if !ok {
			return f, fmt.Errorf("unknown status: %s", name)
		}
		f.Statuses = append(f.Statuses, status)
	}
	// ponytail: events are not checked against a list (there is none); an unknown one just matches no run
	f.Events = dedupe(form.FormStrings("event"))
	f.Repo = strings.TrimSpace(form.FormString("repo"))
	f.Workflow = strings.TrimSpace(form.FormString("workflow_id"))
	f.Branch = strings.TrimSpace(form.FormString("branch"))
	f.Actor = strings.TrimSpace(form.FormString("actor"))
	if f.From, err = parseOrgRunTime(form.FormString("from"), false); err != nil {
		return f, err
	}
	f.To, err = parseOrgRunTime(form.FormString("to"), true)
	return f, err
}

// orgRunRepoCond matches, in the repository table, the repositories of org whose Actions runs doer may see. It is
// the one visibility rule of the runs list, the overview and the instance pages. A nil org (site admins only) means
// every owner.
func orgRunRepoCond(ctx context.Context, org *organization.Organization, doer *user_model.User, admin bool, tokenRepos builder.Cond) builder.Cond {
	var ownerID int64
	if org != nil {
		ownerID = org.ID
	}
	cond := repo_model.OrgUnitRepoCond(ctx, ownerID, doer, admin, unit.TypeActions)
	if tokenRepos != nil {
		cond = cond.And(tokenRepos)
	}
	return cond
}

// IsActiveSiteAdmin says whether u may use the instance-wide Actions pages.
func IsActiveSiteAdmin(u *user_model.User) bool {
	return u != nil && u.IsAdmin && u.IsActive && !u.ProhibitLogin
}

// FindOrgRuns lists the runs of the repositories of org (all owners if nil, for site admins) that doer can read the Actions of, newest first, and how
// many there are. admin is whether doer acts as a site admin, who sees every repository that isn't trashed.
// tokenRepos, if not nil, further limits the repositories (what an access token may read, as
// Reducer().RepoReadAccessFilter()). Ownership comes from the repository: action_run.owner_id can be stale.
func FindOrgRuns(ctx context.Context, org *organization.Organization, doer *user_model.User, admin bool, tokenRepos builder.Cond, f OrgRunFilter, lo db.ListOptions) (actions_model.RunList, int64, error) {
	if org == nil && !admin {
		return nil, 0, errors.New("runs of all owners are for site admins only")
	}
	repoCond := orgRunRepoCond(ctx, org, doer, admin, tokenRepos)
	if owner, name, ok := strings.Cut(strings.ToLower(f.Repo), "/"); ok {
		repoCond = repoCond.And(builder.Eq{"`repository`.lower_name": name}, builder.Expr("LOWER(`repository`.owner_name) = ?", owner))
	} else if f.Repo != "" {
		repoCond = repoCond.And(builder.Eq{"`repository`.lower_name": owner})
	}

	lo.Page = max(lo.Page, 1) // FindAndCount doesn't paginate page 0
	opts := actions_model.FindRunOptions{
		ListOptions: lo, RepoCond: repoCond, Status: f.Statuses, Events: f.Events, WorkflowID: f.Workflow,
		CreatedFrom: f.From, CreatedTo: f.To, OmitEventPayload: true,
	}
	if f.Branch != "" {
		opts.Ref = git.BranchPrefix + f.Branch
	}
	if f.Actor != "" {
		actor, err := user_model.GetUserByName(ctx, f.Actor)
		if err != nil {
			if user_model.IsErrUserNotExist(err) {
				return nil, 0, nil
			}
			return nil, 0, err
		}
		opts.TriggerUserID = actor.ID
	}
	return db.FindAndCount[actions_model.ActionRun](ctx, opts)
}

// LoadOrgRunRepos loads the repositories of the runs and drops the runs whose repository went away since the query.
func LoadOrgRunRepos(ctx context.Context, runs actions_model.RunList) (actions_model.RunList, error) {
	if err := runs.LoadRepos(ctx); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(runs, func(run *actions_model.ActionRun) bool { return run.Repo == nil }), nil
}

// OrgRunPermissions returns the permission of doer in each repository of the loaded runs, with one lookup per
// distinct repository.
func OrgRunPermissions(ctx context.Context, runs actions_model.RunList, doer *user_model.User) (map[int64]*access_model.Permission, error) {
	perms := make(map[int64]*access_model.Permission)
	for _, run := range runs {
		if _, ok := perms[run.RepoID]; ok || run.Repo == nil {
			continue
		}
		perm, err := access_model.GetUserRepoPermission(ctx, run.Repo, doer)
		if err != nil {
			return nil, err
		}
		perms[run.RepoID] = &perm
	}
	return perms, nil
}
