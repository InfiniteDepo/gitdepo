// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package accessreport works out who can access which repository, and why.
package accessreport

import (
	"context"
	"maps"
	"math"
	"slices"
	"sort"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/container"
	"forgejo.org/modules/structs"

	"xorm.io/builder"
)

// Kind is the kind of source a path grants access through.
type Kind string

const (
	KindOwnerUser    Kind = "owner"
	KindSiteAdmin    Kind = "site_admin"
	KindAuditor      Kind = "auditor"
	KindOrgOwner     Kind = "org_owner"
	KindAdminTeam    Kind = "admin_team"
	KindTeam         Kind = "team"
	KindCollaborator Kind = "collaborator"
	KindPublic       Kind = "public"
	KindInternal     Kind = "internal"
	KindOrgMember    Kind = "org_member"
	KindDeployKey    Kind = "deploy_key"
	KindOrgDeployKey Kind = "org_deploy_key"
	// KindProjectDeployKey is an organization deploy key of the repository's project.
	KindProjectDeployKey Kind = "project_deploy_key"
	// KindRepoToken, KindProjectToken and KindOrgToken are access tokens of the repository, its project and its
	// organization.
	KindRepoToken    Kind = "repo_token"
	KindProjectToken Kind = "project_token"
	KindOrgToken     Kind = "org_token"
	// KindInstanceRoles stands for the site admins and auditors, whom only site admins see by name.
	KindInstanceRoles Kind = "instance_roles"
)

// Group is a user group that made the user a member of a team.
type Group struct {
	Group  *organization.UserGroup
	Source *auth_model.Source // the login source that synced the membership, nil if an admin added it
}

// Path is one source of access.
type Path struct {
	Kind    Kind
	Mode    perm_model.AccessMode
	Units   map[unit.Type]perm_model.AccessMode // nil: Mode on every unit
	Team    *organization.Team
	Groups  []*Group
	Applied bool // false when the permission code doesn't use this path for any unit
}

// Row is the access of one identity to one repository.
type Row struct {
	User         *user_model.User // nil for the pseudo-rows and deploy keys
	Anonymous    bool             // pseudo-row for anyone, signed in or not; otherwise a pseudo-row is for any signed-in user, or any member of the private owner org (KindOrgMember)
	DeployKey    *asymkey_model.DeployKey
	OrgDeployKey *asymkey_model.OrgDeployKey
	AccessToken  *auth_model.AccessToken // a token of the repository, its project or its organization
	Team         *organization.Team      // a team shown as one row, for viewers outside the org
	OrgMember    bool                    // the user is a member of the repository's owner org
	Repo         *repo_model.Repository
	Perm         access_model.Permission
	Paths        []*Path
}

// Options selects what Compute reports.
type Options struct {
	RepoIDs []int64
	// User, if set, limits the report to this user, and to the repositories where they have a path.
	User *user_model.User
	// Plain computes users as if they were neither site admins nor auditors, and leaves out site admins and auditors.
	Plain bool
	// Outsider computes for a viewer outside the owner org: users as if they were in no team and in no org, and
	// one row per team instead of its members.
	Outsider bool
}

type key struct{ a, b int64 }

// data holds everything GetUserRepoPermission reads, loaded for all the repositories at once.
type data struct {
	owners      map[int64]*user_model.User
	users       map[int64]*user_model.User
	collab      map[key]perm_model.AccessMode // (uid, repo)
	access      map[key]perm_model.AccessMode // (uid, repo)
	orgMember   map[key]bool                  // (org, uid)
	teams       map[int64]*organization.Team
	repoTeams   map[int64][]int64    // repo -> team IDs, ascending
	teamMembers map[int64][]int64    // team -> uids
	userTeams   map[key]bool         // (team, uid)
	groups      map[key][]*Group     // (team, uid)
	roleUsers   []int64              // site admins and auditors
	twoFactor   container.Set[int64] // users with 2FA, loaded only when an owner requires it
}

// Compute returns the access rows of the repositories: one per user who has a path to the repository, the
// pseudo-rows (any member of a private owner org, any signed-in user, anyone), and the deploy keys. A user without
// a row has the access of the pseudo-row that applies to them, or none if they are restricted or none applies.
//
// It loads with a fixed number of queries, then repeats the decision order of access_model.GetUserRepoPermission
// (and of GetUserRepoReadPermission for auditors). TestComputeMatchesGetUserRepoPermission keeps them in step.
func Compute(ctx context.Context, opts Options) ([]*Row, error) {
	repos := make(repo_model.RepositoryList, 0, len(opts.RepoIDs))
	if len(opts.RepoIDs) == 0 {
		return nil, nil
	}
	if err := db.GetEngine(ctx).In("id", opts.RepoIDs).OrderBy("id").Find(&repos); err != nil {
		return nil, err
	}
	if err := repos.LoadUnits(ctx); err != nil {
		return nil, err
	}
	d, err := load(ctx, repos, opts)
	if err != nil {
		return nil, err
	}

	var rows []*Row
	for _, repo := range repos {
		owner := d.owners[repo.OwnerID]
		if owner == nil || repo.IsTrashed() { // a trashed repository has no access, as in GetUserRepoPermission
			continue
		}
		repo.Owner = owner
		if opts.User == nil && !repo.IsPrivate {
			rows = append(rows, d.pseudoRows(repo, owner)...)
		}
		if opts.Outsider {
			for _, tid := range d.repoTeams[repo.ID] {
				if t := d.teams[tid]; t != nil && t.OrgID == repo.OwnerID {
					rows = append(rows, teamRow(repo, t))
				}
			}
		}
		for _, uid := range d.candidates(repo, opts) {
			u := d.users[uid]
			if u == nil {
				continue
			}
			row := &Row{User: u, Repo: repo, Perm: d.permission(repo, u), Paths: d.paths(repo, u), OrgMember: d.orgMember[key{repo.OwnerID, u.ID}]}
			if len(row.Paths) == 0 {
				continue
			}
			setApplied(row)
			rows = append(rows, row)
		}
	}
	if opts.User != nil {
		return rows, nil
	}

	keys := make([]*asymkey_model.DeployKey, 0, 10)
	if err := db.GetEngine(ctx).In("repo_id", opts.RepoIDs).OrderBy("name").Find(&keys); err != nil {
		return nil, err
	}
	byID := make(map[int64]*repo_model.Repository, len(repos))
	for _, r := range repos {
		byID[r.ID] = r
	}
	// a trashed repository has no access, as in GetUserRepoPermission
	for _, k := range keys {
		if repo := byID[k.RepoID]; repo != nil && !repo.IsTrashed() {
			rows = append(rows, deployKeyRow(&Row{DeployKey: k, Repo: repo}, KindDeployKey, k.Mode, k.IsExpired()))
		}
	}
	orgKeys, err := asymkey_model.FindOrgDeployKeysCoveringRepos(ctx, opts.RepoIDs)
	if err != nil {
		return nil, err
	}
	for _, k := range orgKeys {
		if repo := byID[k.RepoID]; repo != nil && !repo.IsTrashed() {
			kind := KindOrgDeployKey
			if k.GroupID != 0 {
				kind = KindProjectDeployKey
			}
			rows = append(rows, deployKeyRow(&Row{OrgDeployKey: &k.OrgDeployKey, Repo: repo}, kind, k.Mode, k.IsExpired()))
		}
	}
	covered := make([]auth_model.CoveredRepo, 0, len(repos))
	for _, r := range repos {
		if !r.IsTrashed() {
			covered = append(covered, auth_model.CoveredRepo{ID: r.ID, OwnerID: r.OwnerID, GroupID: r.GroupID})
		}
	}
	tokens, err := auth_model.FindOwnedAccessTokensCoveringRepos(ctx, covered)
	if err != nil {
		return nil, err
	}
	for _, r := range covered {
		for _, t := range tokens[r.ID] {
			rows = append(rows, tokenRow(byID[r.ID], t))
		}
	}
	return rows, nil
}

// tokenRow fills the access of an access token row as accessTokenBotPermission decides it: the token's permission on
// every unit, none once it has expired (the path stays, not applied).
func tokenRow(repo *repo_model.Repository, t *auth_model.AccessToken) *Row {
	kind := map[auth_model.AccessTokenOwnerType]Kind{
		auth_model.AccessTokenOwnerRepo: KindRepoToken, auth_model.AccessTokenOwnerProject: KindProjectToken, auth_model.AccessTokenOwnerOrg: KindOrgToken,
	}[t.OwnerType]
	mode := min(t.Mode, perm_model.AccessModeAdmin)
	r := &Row{AccessToken: t, Repo: repo, Paths: []*Path{{Kind: kind, Mode: mode, Applied: t.IsUsable()}}}
	if t.IsUsable() {
		r.Perm = access_model.Permission{AccessMode: mode, Units: repo.Units, UnitsMode: make(map[unit.Type]perm_model.AccessMode, len(repo.Units))}
		for _, u := range repo.Units {
			r.Perm.UnitsMode[u.Type] = mode
		}
	}
	return r
}

// deployKeyRow fills the access of a deploy key row: the code only, read at most on an archived repository, and none
// once the key has expired (the path stays, not applied).
func deployKeyRow(r *Row, kind Kind, mode perm_model.AccessMode, expired bool) *Row {
	if r.Repo.IsArchived {
		mode = min(mode, perm_model.AccessModeRead)
	}
	units := map[unit.Type]perm_model.AccessMode{unit.TypeCode: mode}
	r.Paths = []*Path{{Kind: kind, Mode: mode, Units: units, Applied: !expired}}
	if !expired {
		r.Perm = access_model.Permission{AccessMode: mode, UnitsMode: units}
	}
	return r
}

// memberID stands for any non-restricted member of a private org, in the replay.
const memberID = math.MinInt64

// pseudoRows returns the rows of the users who have no path to the public repository: any member of its private
// owner org (with 2FA if the org requires it), or any signed-in user, and anyone if the owner is public too.
func (d *data) pseudoRows(repo *repo_model.Repository, owner *user_model.User) []*Row {
	if owner.Visibility == structs.VisibleTypePrivate {
		if !owner.IsOrganization() {
			return nil
		}
		d.orgMember[key{owner.ID, memberID}] = true
		r := &Row{Repo: repo, Perm: d.permission(repo, &user_model.User{ID: memberID}), Paths: []*Path{d.visibilityPath(repo, owner)}}
		setApplied(r)
		return []*Row{r}
	}
	// a user ID of 0 has no collaboration, team or membership
	signedIn := &Row{Repo: repo, Perm: d.permission(repo, &user_model.User{}), Paths: []*Path{d.visibilityPath(repo, owner)}}
	setApplied(signedIn)
	if owner.Visibility != structs.VisibleTypePublic {
		return []*Row{signedIn}
	}
	anyone := &Row{Repo: repo, Anonymous: true, Perm: access_model.Permission{AccessMode: perm_model.AccessModeRead, Units: repo.Units}}
	anyone.Paths = []*Path{{Kind: KindPublic, Mode: perm_model.AccessModeRead}}
	setApplied(anyone)
	return []*Row{signedIn, anyone}
}

func load(ctx context.Context, repos repo_model.RepositoryList, opts Options) (*data, error) {
	e := db.GetEngine(ctx)
	d := &data{
		owners: map[int64]*user_model.User{}, users: map[int64]*user_model.User{},
		collab: map[key]perm_model.AccessMode{}, access: map[key]perm_model.AccessMode{}, orgMember: map[key]bool{},
		teams: map[int64]*organization.Team{}, repoTeams: map[int64][]int64{}, teamMembers: map[int64][]int64{},
		userTeams: map[key]bool{}, groups: map[key][]*Group{},
	}
	repoIDs := repos.IDs()
	ownerIDs := make([]int64, 0, len(repos))
	for _, r := range repos {
		ownerIDs = append(ownerIDs, r.OwnerID)
	}
	userCond := func(col string) builder.Cond {
		if opts.User == nil {
			return builder.Expr("1=1")
		}
		return builder.Eq{col: opts.User.ID}
	}

	owners := make([]*user_model.User, 0, len(ownerIDs))
	if err := e.In("id", ownerIDs).Find(&owners); err != nil {
		return nil, err
	}
	for _, o := range owners {
		d.owners[o.ID] = o
	}

	collabs := make([]*repo_model.Collaboration, 0, 10)
	if err := e.In("repo_id", repoIDs).And(userCond("user_id")).Find(&collabs); err != nil {
		return nil, err
	}
	for _, c := range collabs {
		d.collab[key{c.UserID, c.RepoID}] = c.Mode
	}
	// what the membership queries match: nobody for an outsider, who is shown no team or org membership
	memberCond := userCond
	if opts.Outsider {
		memberCond = func(string) builder.Cond { return builder.Expr("1=0") }
		// without teams, the access table would hold the collaboration
		maps.Copy(d.access, d.collab)
	}
	accesses := make([]*access_model.Access, 0, 10)
	if err := e.In("repo_id", repoIDs).And(memberCond("user_id")).Find(&accesses); err != nil {
		return nil, err
	}
	for _, a := range accesses {
		d.access[key{a.UserID, a.RepoID}] = a.Mode
	}
	orgUsers := make([]*organization.OrgUser, 0, 10)
	if err := e.In("org_id", ownerIDs).And(memberCond("uid")).Find(&orgUsers); err != nil {
		return nil, err
	}
	for _, ou := range orgUsers {
		d.orgMember[key{ou.OrgID, ou.UID}] = true
	}

	teamRepos := make([]*organization.TeamRepo, 0, 10)
	if err := e.In("repo_id", repoIDs).OrderBy("team_id").Find(&teamRepos); err != nil {
		return nil, err
	}
	teamIDs := make([]int64, 0, len(teamRepos))
	for _, tr := range teamRepos {
		d.repoTeams[tr.RepoID] = append(d.repoTeams[tr.RepoID], tr.TeamID)
		teamIDs = append(teamIDs, tr.TeamID)
	}
	teams := make([]*organization.Team, 0, len(teamIDs))
	if err := e.In("id", teamIDs).Find(&teams); err != nil {
		return nil, err
	}
	for _, t := range teams {
		t.Units = []*organization.TeamUnit{}
		d.teams[t.ID] = t
	}
	teamUnits := make([]*organization.TeamUnit, 0, len(teamIDs)*8)
	if err := e.In("team_id", teamIDs).Find(&teamUnits); err != nil {
		return nil, err
	}
	for _, tu := range teamUnits {
		if t := d.teams[tu.TeamID]; t != nil {
			t.Units = append(t.Units, tu)
		}
	}
	teamUsers := make([]*organization.TeamUser, 0, 10)
	if err := e.In("team_id", teamIDs).And(memberCond("uid")).Find(&teamUsers); err != nil {
		return nil, err
	}
	for _, tu := range teamUsers {
		d.teamMembers[tu.TeamID] = append(d.teamMembers[tu.TeamID], tu.UID)
		d.userTeams[key{tu.TeamID, tu.UID}] = true
	}

	links := make([]struct {
		UID           int64 `xorm:"uid"`
		TeamID        int64
		GroupID       int64
		LoginSourceID int64
	}, 0, 10)
	if err := e.Table("user_group_user").
		Join("INNER", "user_group_team", "user_group_team.group_id = user_group_user.group_id").
		In("user_group_team.team_id", teamIDs).And(memberCond("user_group_user.uid")).
		Select("user_group_user.uid, user_group_team.team_id, user_group_user.group_id, user_group_user.login_source_id").
		Find(&links); err != nil {
		return nil, err
	}
	groupIDs := make([]int64, 0, len(links))
	sourceIDs := make([]int64, 0, len(links))
	for _, l := range links {
		groupIDs = append(groupIDs, l.GroupID)
		sourceIDs = append(sourceIDs, l.LoginSourceID)
	}
	groups := map[int64]*organization.UserGroup{}
	if err := e.In("id", groupIDs).Find(&groups); err != nil {
		return nil, err
	}
	sources := map[int64]*auth_model.Source{}
	if err := e.In("id", sourceIDs).Find(&sources); err != nil {
		return nil, err
	}
	for _, l := range links {
		if g := groups[l.GroupID]; g != nil {
			k := key{l.TeamID, l.UID}
			d.groups[k] = append(d.groups[k], &Group{Group: g, Source: sources[l.LoginSourceID]})
		}
	}

	users := make([]*user_model.User, 0, 20)
	if opts.User != nil {
		users = append(users, opts.User)
	} else {
		uids := make([]int64, 0, len(collabs)+len(teamUsers))
		for _, c := range collabs {
			uids = append(uids, c.UserID)
		}
		for _, tu := range teamUsers {
			uids = append(uids, tu.UID)
		}
		roles := builder.NewCond()
		if !opts.Plain {
			roles = builder.Or(builder.Eq{"is_admin": true}, builder.Eq{"is_auditor": true})
		}
		if err := e.Where(builder.Or(builder.In("id", append(uids, ownerIDs...)), roles)).
			In("type", user_model.UserTypeIndividual, user_model.UserTypeBot).OrderBy("lower_name").Find(&users); err != nil {
			return nil, err
		}
	}
	for _, u := range users {
		if opts.Plain {
			plain := *u
			plain.IsAdmin, plain.IsAuditor = false, false
			u = &plain
		}
		d.users[u.ID] = u
		if u.IsAdmin || u.IsAuditor {
			d.roleUsers = append(d.roleUsers, u.ID)
		}
	}
	for _, o := range owners {
		if o.IsOrganization() && o.RequireTwoFactor {
			var err error
			if d.twoFactor, err = auth_model.UserIDsWithTwoFactor(ctx, slices.Collect(maps.Keys(d.users))); err != nil {
				return nil, err
			}
			break
		}
	}
	return d, nil
}

// twoFactorBlocked is user_model.User.TwoFactorBlocked.
func (d *data) twoFactorBlocked(owner, u *user_model.User) bool {
	return owner.IsOrganization() && owner.RequireTwoFactor && !u.IsAdmin && u.ID > 0 && !d.twoFactor.Contains(u.ID)
}

// candidates returns the users who may have a path to the repository, in name order.
func (d *data) candidates(repo *repo_model.Repository, opts Options) []int64 {
	if opts.User != nil {
		return []int64{opts.User.ID}
	}
	set := container.Set[int64]{}
	set.Add(repo.OwnerID)
	set.AddMultiple(d.roleUsers...)
	for k := range d.collab {
		if k.b == repo.ID {
			set.Add(k.a)
		}
	}
	for _, tid := range d.repoTeams[repo.ID] {
		set.AddMultiple(d.teamMembers[tid]...)
	}
	uids := set.Values()
	sort.Slice(uids, func(i, j int) bool {
		a, b := d.users[uids[i]], d.users[uids[j]]
		if a == nil || b == nil {
			return a != nil
		}
		return a.LowerName < b.LowerName
	})
	return uids
}

// ownerVisible is organization.HasOrgOrUserVisible.
func (d *data) ownerVisible(owner, u *user_model.User) bool {
	if u.IsAdmin || owner.ID == u.ID {
		return true
	}
	return !((owner.Visibility == structs.VisibleTypePrivate || u.IsRestricted) && !d.orgMember[key{owner.ID, u.ID}])
}

// userRepoTeams is organization.GetUserRepoTeams.
func (d *data) userRepoTeams(repo *repo_model.Repository, u *user_model.User) []*organization.Team {
	var teams []*organization.Team
	for _, tid := range d.repoTeams[repo.ID] {
		if t := d.teams[tid]; t != nil && t.OrgID == repo.OwnerID && d.userTeams[key{tid, u.ID}] {
			teams = append(teams, t)
		}
	}
	return teams
}

// accessLevel is access_model's accessLevel for a user who doesn't own the repository.
func (d *data) accessLevel(repo *repo_model.Repository, u *user_model.User) perm_model.AccessMode {
	if m, ok := d.access[key{u.ID, repo.ID}]; ok {
		return m
	}
	if !u.IsRestricted && !repo.IsPrivate {
		return perm_model.AccessModeRead
	}
	return perm_model.AccessModeNone
}

// permission repeats access_model.GetUserRepoPermission, raised like GetUserRepoReadPermission for auditors.
func (d *data) permission(repo *repo_model.Repository, u *user_model.User) access_model.Permission {
	p := d.userPermission(repo, u)
	if u.IsAuditor && !d.twoFactorBlocked(d.owners[repo.OwnerID], u) {
		if p.UnitsMode == nil {
			p.AccessMode = max(p.AccessMode, perm_model.AccessModeRead)
		} else {
			for _, ru := range repo.Units {
				p.UnitsMode[ru.Type] = max(p.UnitsMode[ru.Type], perm_model.AccessModeRead)
			}
		}
		p.Units = repo.Units
	}
	return p
}

func (d *data) userPermission(repo *repo_model.Repository, u *user_model.User) (p access_model.Permission) {
	k := key{u.ID, repo.ID}
	_, isCollaborator := d.collab[k]
	owner := d.owners[repo.OwnerID]
	if d.twoFactorBlocked(owner, u) {
		// a stranger, as in GetUserRepoPermission
		if !repo.IsPrivate && !u.IsRestricted && owner.Visibility != structs.VisibleTypePrivate {
			p.AccessMode = perm_model.AccessModeRead
			p.Units = repo.Units
			p.UnitsMode = make(map[unit.Type]perm_model.AccessMode, len(repo.Units))
			for _, ru := range repo.Units {
				p.UnitsMode[ru.Type] = ru.DefaultPermissions.ToAccessMode(perm_model.AccessModeRead)
			}
		}
		return p
	}
	if !d.ownerVisible(owner, u) && !isCollaborator {
		return p
	}
	p.Units = repo.Units
	if u.IsAdmin || u.ID == repo.OwnerID {
		p.AccessMode = perm_model.AccessModeOwner
		return p
	}

	p.AccessMode = d.accessLevel(repo, u)

	if !owner.IsOrganization() {
		if !repo.IsPrivate && !u.IsRestricted && len(repo.Units) > 0 {
			p.UnitsMode = make(map[unit.Type]perm_model.AccessMode)
			for _, ru := range repo.Units {
				if _, ok := p.UnitsMode[ru.Type]; !ok {
					p.UnitsMode[ru.Type] = ru.DefaultPermissions.ToAccessMode(p.AccessMode)
				}
			}
		}
		return p
	}

	p.UnitsMode = make(map[unit.Type]perm_model.AccessMode)
	if isCollaborator {
		for _, ru := range repo.Units {
			p.UnitsMode[ru.Type] = p.AccessMode
		}
	}
	teams := d.userRepoTeams(repo, u)
	for _, t := range teams {
		if t.AccessMode >= perm_model.AccessModeAdmin {
			p.AccessMode = t.AccessMode
			p.UnitsMode = nil
			return p
		}
	}
	for _, ru := range repo.Units {
		var found bool
		for _, t := range teams {
			if m := teamUnitMode(t, ru.Type); m > perm_model.AccessModeNone {
				p.UnitsMode[ru.Type] = max(p.UnitsMode[ru.Type], m)
				found = true
			}
		}
		if !found && !repo.IsPrivate && !u.IsRestricted {
			if _, ok := p.UnitsMode[ru.Type]; !ok {
				p.UnitsMode[ru.Type] = ru.DefaultPermissions.ToAccessMode(perm_model.AccessModeRead)
			}
		}
	}
	p.Units = make([]*repo_model.RepoUnit, 0, len(repo.Units))
	for _, ru := range repo.Units {
		if _, ok := p.UnitsMode[ru.Type]; ok {
			p.Units = append(p.Units, ru)
		}
	}
	return p
}

// teamUnitMode is Team.UnitAccessMode on the preloaded units.
func teamUnitMode(t *organization.Team, tp unit.Type) perm_model.AccessMode {
	for _, tu := range t.Units {
		if tu.Type == tp {
			return tu.AccessMode
		}
	}
	return perm_model.AccessModeNone
}

// visibilityPath is the access a repository gives through its visibility, before teams and collaborations.
func (d *data) visibilityPath(repo *repo_model.Repository, owner *user_model.User) *Path {
	p := &Path{Kind: KindPublic, Mode: perm_model.AccessModeRead, Units: map[unit.Type]perm_model.AccessMode{}}
	switch owner.Visibility {
	case structs.VisibleTypeLimited:
		p.Kind = KindInternal
	case structs.VisibleTypePrivate:
		p.Kind = KindOrgMember
	}
	for _, ru := range repo.Units {
		p.Units[ru.Type] = ru.DefaultPermissions.ToAccessMode(perm_model.AccessModeRead)
	}
	return p
}

// paths lists every source that gives the user access to the repository.
func (d *data) paths(repo *repo_model.Repository, u *user_model.User) []*Path {
	var paths []*Path
	owner := d.owners[repo.OwnerID]
	if u.IsAdmin {
		paths = append(paths, &Path{Kind: KindSiteAdmin, Mode: perm_model.AccessModeOwner})
	}
	if u.ID == repo.OwnerID {
		paths = append(paths, &Path{Kind: KindOwnerUser, Mode: perm_model.AccessModeOwner})
	}
	for _, t := range d.userRepoTeams(repo, u) {
		p := teamPath(t)
		p.Groups = d.groups[key{t.ID, u.ID}]
		paths = append(paths, p)
	}
	if _, ok := d.collab[key{u.ID, repo.ID}]; ok {
		// GetUserRepoPermission gives a collaborator the access level of the access table, on every unit
		paths = append(paths, &Path{Kind: KindCollaborator, Mode: d.accessLevel(repo, u)})
	}
	if u.IsAuditor {
		paths = append(paths, &Path{Kind: KindAuditor, Mode: perm_model.AccessModeRead})
	}
	if len(paths) == 0 {
		// nothing beyond the pseudo-rows
		return nil
	}
	if !repo.IsPrivate && !u.IsRestricted && d.ownerVisible(owner, u) {
		paths = append(paths, d.visibilityPath(repo, owner))
	}
	return paths
}

func teamPath(t *organization.Team) *Path {
	p := &Path{Kind: KindTeam, Mode: t.AccessMode, Team: t}
	switch {
	case t.IsOwnerTeam():
		p.Kind = KindOrgOwner
	case t.AccessMode >= perm_model.AccessModeAdmin:
		p.Kind = KindAdminTeam
	default:
		p.Units = map[unit.Type]perm_model.AccessMode{}
		for _, tu := range t.Units {
			p.Units[tu.Type] = tu.AccessMode
		}
	}
	return p
}

// teamRow is the access a team gives to its members, as one row.
func teamRow(repo *repo_model.Repository, t *organization.Team) *Row {
	p := teamPath(t)
	p.Applied = true
	r := &Row{Team: t, Repo: repo, Perm: access_model.Permission{AccessMode: t.AccessMode, Units: repo.Units}, Paths: []*Path{p}}
	if p.Units != nil {
		r.Perm.UnitsMode = map[unit.Type]perm_model.AccessMode{}
		for _, ru := range repo.Units {
			if m := p.Units[ru.Type]; m > perm_model.AccessModeNone {
				r.Perm.UnitsMode[ru.Type] = m
			}
		}
	}
	return r
}

// setApplied marks the paths that explain the effective access of at least one unit.
func setApplied(r *Row) {
	for _, p := range r.Paths {
		for _, ru := range r.Repo.Units {
			eff := r.Perm.UnitAccessMode(ru.Type)
			grant := p.Mode
			if p.Units != nil {
				grant = p.Units[ru.Type]
			}
			if eff > perm_model.AccessModeNone && grant == eff {
				p.Applied = true
				break
			}
		}
	}
}
