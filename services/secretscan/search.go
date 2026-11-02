// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"errors"
	"slices"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/util"
	"forgejo.org/services/accessreport"
	dependency_service "forgejo.org/services/dependency"

	"xorm.io/builder"
)

// Scope says whose repositories a list of secret alerts covers and who asks. The organization and instance lists
// share it, as they share the one visibility rule in RepoCond.
type Scope struct {
	Org   *organization.Organization // nil: every owner (the instance list)
	Doer  *user_model.User
	Admin bool // the doer acts as a site admin or an auditor: every repository not hidden by a rule of the instance
	// Narrow limits an organization list to the repositories where the doer can write the code (a member who is no
	// owner, as for the alerts of one repository: CanSeeAlerts).
	Narrow bool
	// Writable is the repositories of a narrowed list (WritableRepoIDs); a narrowed list without any is empty.
	Writable []int64
	Project  string // org only: a project of the organization
	Owner    string // instance only: an owner name
	Query    string // a part of the repository's or its owner's name
}

// Filter narrows a list by the state of its alerts: State is "open", "closed" or "all", Reason one of ClosedStates,
// Type a rule ID.
type Filter struct {
	State, Reason, Type string
}

// ParseFilter reads the filter of a form. No state lists the open alerts, as the repository list does, or the closed
// ones when a reason is given. A value that is not one of the allowed ones is dropped and its field ("state",
// "reason", "type") reported, so a page can say that it did not filter by it.
func ParseFilter(state, reason, secretType string) (f Filter, ignored []string) {
	switch state {
	case secretscan_model.StateOpen, "closed", "all":
		f.State = state
	default:
		if state != "" {
			ignored = append(ignored, "state")
		}
		f.State = secretscan_model.StateOpen
		if slices.Contains(secretscan_model.ClosedStates, reason) {
			f.State = "closed"
		}
	}
	switch {
	case reason == "":
	case slices.Contains(secretscan_model.ClosedStates, reason) && f.State != secretscan_model.StateOpen:
		f.Reason = reason
	default:
		ignored = append(ignored, "reason")
	}
	_, custom := secretscan_model.ParseCustomRuleID(secretType)
	if _, ok := builtinRule(secretType); ok || custom || secretType == "" {
		f.Type = secretType
	} else {
		ignored = append(ignored, "type")
	}
	return f, ignored
}

// MaxNarrowRepos is the most repositories a narrowed list holds: their IDs are bound in the query, which a driver
// limits (about 32,000 on SQLite). A member who can write more is asked to get the list from an owner.
var MaxNarrowRepos = 10_000

// ErrTooManyRepos is a narrowed list of more than MaxNarrowRepos repositories.
var ErrTooManyRepos = util.NewInvalidArgumentErrorf("too many repositories")

// writeCandidateRepoIDs returns the repositories of the organization where a collaboration or a team could give the
// user write access to the code: a superset of where they can write, so a member who only reads loads nothing.
func writeCandidateRepoIDs(ctx context.Context, uid, orgID int64) ([]int64, error) {
	writeTeams := builder.Select("team.id").From("team").Where(builder.Eq{"team.org_id": orgID}.And(builder.Or(
		builder.Gte{"team.authorize": perm.AccessModeWrite},
		builder.In("team.id", builder.Select("team_id").From("team_unit").
			Where(builder.Eq{"type": unit.TypeCode}.And(builder.Gte{"access_mode": perm.AccessModeWrite}))),
	)))
	cond := builder.Eq{"owner_id": orgID}.And(builder.Or(
		builder.In("id", builder.Select("repo_id").From("collaboration").
			Where(builder.Eq{"user_id": uid}.And(builder.Gte{"mode": perm.AccessModeWrite}))),
		builder.In("id", builder.Select("team_repo.repo_id").From("team_repo").
			Join("INNER", "team_user", "team_user.team_id = team_repo.team_id").
			Where(builder.Eq{"team_user.uid": uid}.And(builder.In("team_repo.team_id", writeTeams)))),
	))
	ids := make([]int64, 0, 10)
	return ids, db.GetEngine(ctx).Table("repository").Where(cond).Cols("id").OrderBy("id").Find(&ids)
}

// WritableRepoIDs returns the repositories of the organization where the user can write the code, decided as
// GetUserRepoPermission does (accessreport) for the repositories a collaboration or team could give them write to,
// in chunks of at most MaxNarrowRepos bound IDs. Above MaxNarrowRepos writable repositories it returns
// ErrTooManyRepos.
func WritableRepoIDs(ctx context.Context, org *organization.Organization, doer *user_model.User) ([]int64, error) {
	ids, err := writeCandidateRepoIDs(ctx, doer.ID, org.ID)
	if err != nil {
		return nil, err
	}
	var out []int64
	for chunk := range slices.Chunk(ids, MaxNarrowRepos) {
		rows, err := accessreport.Compute(ctx, accessreport.Options{RepoIDs: chunk, User: doer, Plain: true})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.User != nil && r.User.ID == doer.ID && r.Perm.CanWrite(unit.TypeCode) {
				out = append(out, r.Repo.ID)
			}
		}
		if len(out) > MaxNarrowRepos {
			return nil, ErrTooManyRepos
		}
	}
	return out, nil
}

// RepoCond is the one visibility rule of the lists across repositories, on the repository table: not trashed, a Code
// unit the policy and the organization allow, readable by the doer (not hidden by a two-factor requirement), and
// secret scanning on for the repository (its alerts are hidden while it is off, as on the repository's own pages).
// A narrowed list holds only s.Writable, and an auditor loses every organization whose two-factor rule blocks them
// (as AuditorView on the repository's page), public repositories too. empty
// is true when a filter names nothing (cond is then not to be used). It reads dynamic settings: call it before
// building a session.
func (s Scope) RepoCond(ctx context.Context) (cond builder.Cond, empty bool, err error) {
	if s.Org == nil && !s.Admin {
		return nil, false, errors.New("a list of every owner is for site admins and auditors only")
	}
	if !SiteEnabled(ctx) {
		return builder.NewCond(), true, nil
	}
	var ownerID int64
	if s.Org != nil {
		ownerID = s.Org.ID
	}
	cond = repo_model.OrgUnitRepoCond(ctx, ownerID, s.Doer, s.Admin, unit.TypeCode).And(builder.Not{secretscan_model.OffCond()})
	if s.Admin && !s.Doer.IsAdmin {
		cond = cond.And(builder.NotIn("`repository`.owner_id", repo_model.TwoFactorBlockingOrgIDs(s.Doer.ID)))
	}
	if s.Narrow {
		if len(s.Writable) == 0 {
			return builder.NewCond(), true, nil
		}
		cond = cond.And(builder.In("`repository`.id", s.Writable))
	}
	if s.Project != "" && s.Org != nil {
		group, err := repo_model.GetRepoGroupByName(ctx, s.Org.ID, s.Project)
		if errors.Is(err, repo_model.ErrRepoGroupNotExist) {
			return builder.NewCond(), true, nil
		} else if err != nil {
			return nil, false, err
		}
		cond = cond.And(builder.Eq{"`repository`.group_id": group.ID})
	}
	if s.Owner != "" && s.Org == nil {
		owner, err := user_model.GetUserByName(ctx, s.Owner)
		if user_model.IsErrUserNotExist(err) {
			return builder.NewCond(), true, nil
		} else if err != nil {
			return nil, false, err
		}
		cond = cond.And(builder.Eq{"`repository`.owner_id": owner.ID})
	}
	if s.Query != "" {
		cond = cond.And(secretscan_model.RepoSearchCond(s.Query))
	}
	return cond, false, nil
}

// options builds the alert search of the scope and filter. Alerts only in the wiki are left out: the viewer's access
// to the wiki is not part of the scope, as the repository page decides it for one repository.
func (s Scope) options(ctx context.Context, f Filter) (opts *secretscan_model.AlertSearchOptions, empty bool, err error) {
	cond, empty, err := s.RepoCond(ctx)
	if err != nil || empty {
		return nil, empty, err
	}
	opts = &secretscan_model.AlertSearchOptions{RepoCond: cond, CodeOnly: true}
	switch f.State {
	case "all":
	case "closed":
		opts.State = "resolved"
	default:
		opts.State = secretscan_model.StateOpen
	}
	if f.Reason != "" {
		opts.Resolutions = []string{f.Reason}
	}
	if f.Type != "" {
		opts.SecretTypes = []string{f.Type}
	}
	return opts, false, nil
}

func builtinRule(ruleID string) (secretdetection.Rule, bool) {
	for _, r := range secretdetection.BuiltinRules() {
		if r.ID == ruleID {
			return r, true
		}
	}
	return secretdetection.Rule{}, false
}

// seeDeletedPattern says whether the viewer may read the name of a deleted pattern of the owner: the instance list
// (site admins and auditors) the site's, and an owner or auditor of the organization the organization's.
func (s Scope) seeDeletedPattern(ownerID int64) bool {
	if ownerID == 0 {
		return s.Org == nil
	}
	return s.Org != nil && s.Org.ID == ownerID && !s.Narrow
}

// Hit is an alert of a list with what the rows show.
type Hit struct {
	*secretscan_model.Alert
	secretscan_model.RuleLabel // what the rule is called, as the viewer may read it
	Repo                       *repo_model.Repository
	First                      *secretscan_model.Location
	More                       int // places beyond the first
	ClosedBy                   *user_model.User
}

// Result is a page of a list.
type Result struct {
	Hits         []*Hit
	Total, Repos int64 // alerts and repositories over all pages
}

// hits loads what the rows of the alerts show, in a fixed number of queries.
func (s Scope) hits(ctx context.Context, alerts []*secretscan_model.Alert) ([]*Hit, error) {
	if len(alerts) == 0 {
		return nil, nil
	}
	var alertIDs, repoIDs, userIDs []int64
	for _, a := range alerts {
		alertIDs = append(alertIDs, a.ID)
		repoIDs = append(repoIDs, a.RepoID)
		if a.ClosedByID != 0 {
			userIDs = append(userIDs, a.ClosedByID)
		}
	}
	repos, err := repo_model.GetRepositoriesMapByIDs(ctx, repoIDs)
	if err != nil {
		return nil, err
	}
	first, err := secretscan_model.FirstLocations(ctx, 0, alertIDs, true)
	if err != nil {
		return nil, err
	}
	counts, err := secretscan_model.CountLocations(ctx, 0, alertIDs, true)
	if err != nil {
		return nil, err
	}
	users, err := user_model.GetUsersByIDsWithBots(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	ruleIDs := make([]string, len(alerts))
	for i, a := range alerts {
		ruleIDs[i] = a.RuleID
	}
	labels, err := secretscan_model.LoadRuleLabels(ctx, ruleIDs)
	if err != nil {
		return nil, err
	}
	out := make([]*Hit, 0, len(alerts))
	for _, a := range alerts {
		repo := repos[a.RepoID]
		if repo == nil {
			continue // trashed since the search
		}
		h := &Hit{Alert: a, Repo: repo, First: first[a.ID], More: max(counts[a.ID]-1, 0)}
		h.RuleLabel = labels.Label(a.RuleID, repo.OwnerID, s.seeDeletedPattern)
		if a.ClosedByID != 0 {
			_, h.ClosedBy = user_model.GetUserFromMap(a.ClosedByID, users)
		}
		out = append(out, h)
	}
	return out, nil
}

// Search returns a page of the alerts the scope lists, newest first, with the totals of the whole list.
func Search(ctx context.Context, s Scope, f Filter, lo db.ListOptions) (*Result, error) {
	opts, empty, err := s.options(ctx, f)
	if err != nil || empty {
		return &Result{}, err
	}
	opts.ListOptions = lo
	alerts, total, err := db.FindAndCount[secretscan_model.Alert](ctx, opts)
	if err != nil || total == 0 {
		return &Result{}, err
	}
	var repos int64
	if _, err := db.GetEngine(ctx).Table("secret_scanning_alert").Where(opts.ToConds()).Select("COUNT(DISTINCT repo_id)").Get(&repos); err != nil {
		return nil, err
	}
	h, err := s.hits(ctx, alerts)
	return &Result{Hits: h, Total: total, Repos: repos}, err
}

// ErrExportTooMany is an export of more alerts than MaxExportRows; the caller says to narrow the list.
var ErrExportTooMany = util.NewInvalidArgumentErrorf("too many alerts")

// Export reads every alert of the list in batches: start gets the number of alerts once, before the first batch
// (it may refuse by returning an error), emit each batch. The alerts are those that were in the list when it
// started; a batch is read again with the visibility rule, so an alert that became hidden meanwhile is left out.
func Export(ctx context.Context, s Scope, f Filter, start func(total int64) error, emit func([]*Hit) error) error {
	opts, empty, err := s.options(ctx, f)
	if err != nil {
		return err
	}
	var ids []int64
	if !empty {
		if err := db.GetEngine(ctx).Table("secret_scanning_alert").Where(opts.ToConds()).OrderBy(opts.ToOrders()).
			Limit(dependency_service.MaxExportRows + 1).Cols("id").Find(&ids); err != nil {
			return err
		}
	}
	if len(ids) > dependency_service.MaxExportRows {
		return ErrExportTooMany
	}
	if err := start(int64(len(ids))); err != nil {
		return err
	}
	for batch := range slices.Chunk(ids, dependency_service.ExportBatch) {
		var alerts []*secretscan_model.Alert
		if err := db.GetEngine(ctx).Where(opts.ToConds().And(builder.In("id", batch))).OrderBy(opts.ToOrders()).Find(&alerts); err != nil {
			return err
		}
		h, err := s.hits(ctx, alerts)
		if err != nil {
			return err
		}
		if err := emit(h); err != nil {
			return err
		}
	}
	return nil
}
