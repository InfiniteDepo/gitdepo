// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package accessreport

import (
	"cmp"
	"context"
	"slices"
	"strconv"

	asymkey_model "forgejo.org/models/asymkey"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	perm_model "forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// Highest is the highest access the permission gives on any unit.
func Highest(p access_model.Permission) perm_model.AccessMode {
	if p.UnitsMode == nil {
		return p.AccessMode
	}
	m := perm_model.AccessModeNone
	for _, um := range p.UnitsMode {
		m = max(m, um)
	}
	return m
}

// ForRepo returns the rows of the repository access overview, as the doer may see them, filtered: site admins and
// auditors are named to site admins only, user groups to site admins and org owners, login sources to site admins
// only; a viewer outside the owner org sees each team as one row and no team or org membership. The inactive-days
// filter, which tells last sign-ins apart, applies only for site admins: anyone can create an org and add any user
// to it. activity says whether it did. admin says whether the doer acts as a site admin, which a restricted token
// doesn't.
func ForRepo(ctx context.Context, repo *repo_model.Repository, admin bool, doer *user_model.User, f Filter) (rows []*Row, activity bool, err error) {
	return ForRepos(ctx, []int64{repo.ID}, admin, doer, f)
}

// ForRepos is ForRepo for repositories of one owner, in ID order; for a site admin, of any owners.
func ForRepos(ctx context.Context, repoIDs []int64, admin bool, doer *user_model.User, f Filter) (rows []*Row, activity bool, err error) {
	repos := make(repo_model.RepositoryList, 0, len(repoIDs))
	if err := db.GetEngine(ctx).In("id", repoIDs).OrderBy("id").Find(&repos); err != nil || len(repos) == 0 {
		return nil, admin, err
	}
	opts := Options{RepoIDs: repoIDs, Plain: !admin}
	isOwner := false
	if !admin {
		if err := repos[0].LoadOwner(ctx); err != nil {
			return nil, false, err
		}
		if owner := repos[0].Owner; owner.IsOrganization() {
			if isOwner, err = organization.OrgFromUser(owner).IsActingOwner(ctx, doer); err != nil {
				return nil, false, err
			}
			isMember, err := organization.IsOrganizationMember(ctx, owner.ID, doer.ID)
			if err != nil {
				return nil, false, err
			}
			opts.Outsider = !isMember
		}
	}
	if rows, err = Compute(ctx, opts); err != nil {
		return nil, false, err
	}
	if !admin {
		for _, repo := range repos {
			rows = append(rows, &Row{Repo: repo, Paths: []*Path{{Kind: KindInstanceRoles, Applied: true}}})
		}
		for _, r := range rows {
			hideGroups(r, !isOwner)
		}
	}
	// Compute lists the deploy keys and tokens after all the repositories
	slices.SortStableFunc(rows, func(a, b *Row) int { return cmp.Compare(a.Repo.ID, b.Repo.ID) })
	if !admin {
		f.InactiveDays = 0
	}
	return f.Apply(rows), admin, nil
}

// AsAdmin returns the doer, as a site admin only if admin is set, for the conversions that read IsAdmin.
func AsAdmin(doer *user_model.User, admin bool) *user_model.User {
	if doer.IsAdmin == admin {
		return doer
	}
	u := *doer
	u.IsAdmin = admin
	return &u
}

// hideGroups removes the login sources from the paths of the row, and the groups too if all is set.
func hideGroups(r *Row, all bool) {
	for i, p := range r.Paths {
		if len(p.Groups) == 0 {
			continue
		}
		cp := *p
		cp.Groups = nil
		if !all {
			for _, g := range p.Groups {
				cp.Groups = append(cp.Groups, &Group{Group: g.Group})
			}
		}
		r.Paths[i] = &cp
	}
}

// Type is the type of identity of the row: person, bot, key or token, or "" for the other rows.
func (r *Row) Type() string {
	switch {
	case r.DeployKey != nil, r.OrgDeployKey != nil:
		return "key"
	case r.AccessToken != nil:
		return "token"
	case r.User == nil:
		return ""
	case r.User.Type == user_model.UserTypeBot:
		return "bot"
	default:
		return "person"
	}
}

// Filter selects rows of a report.
type Filter struct {
	Mode         perm_model.AccessMode // at least this access, on Unit if set
	Unit         unit.Type
	Type         string // person, bot, key or token
	ExternalOnly bool   // collaborators who aren't members of the owner org
	InactiveDays int    // users who haven't signed in for that many days
}

// Apply returns the rows that pass the filter.
func (f Filter) Apply(rows []*Row) []*Row {
	out := make([]*Row, 0, len(rows))
	inactiveBefore := timeutil.TimeStampNow().Add(-int64(f.InactiveDays) * 86400)
	for _, r := range rows {
		mode := Highest(r.Perm)
		if f.Unit != unit.TypeInvalid {
			mode = r.Perm.UnitAccessMode(f.Unit)
		}
		switch {
		case (f.Mode > perm_model.AccessModeNone || f.Unit != unit.TypeInvalid) && mode < max(f.Mode, perm_model.AccessModeRead):
		case f.Type != "" && r.Type() != f.Type:
		case f.ExternalOnly && (r.User == nil || r.OrgMember || !slices.ContainsFunc(r.Paths, func(p *Path) bool { return p.Kind == KindCollaborator })):
		case f.InactiveDays > 0 && (r.User == nil || r.User.LastLoginUnix >= inactiveBefore):
		default:
			out = append(out, r)
		}
	}
	return out
}

// UserRepoIDs returns the repositories where the user has a path other than visibility or an instance role:
// the repositories they own, collaborate on or have through a team. If orgID is set, only those of that org.
func UserRepoIDs(ctx context.Context, uid, orgID int64) ([]int64, error) {
	cond := builder.Or(
		builder.Eq{"owner_id": uid},
		builder.In("id", builder.Select("repo_id").From("collaboration").Where(builder.Eq{"user_id": uid})),
		builder.In("id", builder.Select("team_repo.repo_id").From("team_repo").
			Join("INNER", "team_user", "team_user.team_id = team_repo.team_id").Where(builder.Eq{"team_user.uid": uid})),
	)
	if orgID > 0 {
		cond = builder.And(cond, builder.Eq{"owner_id": orgID})
	}
	ids := make([]int64, 0, 10)
	return ids, db.GetEngine(ctx).Table("repository").Where(cond).Cols("id").Find(&ids)
}

// UserAccess is everything that gives a user access.
type UserAccess struct {
	User         *user_model.User
	SiteAdminVia string // the user groups that made the user a site admin, "" if it was set directly
	AuditorVia   string
	Orgs         []*organization.Organization
	PrivateOrgs  []*organization.Organization // whose public repositories the user reads as a member
	Teams        []*organization.Team
	Groups       []*Group
	Rows         []*Row
	PublicKeys   []*asymkey_model.PublicKey
	AccessTokens []*auth_model.AccessToken
	OAuth2Grants []*auth_model.OAuth2Grant
}

// ForUser returns what gives the user access. With an org, it is limited to that org and leaves out everything
// about the user's instance roles and credentials: the user is computed as if they were neither site admin nor
// auditor.
func ForUser(ctx context.Context, u *user_model.User, org *organization.Organization) (*UserAccess, error) {
	var orgID int64
	if org != nil {
		orgID = org.ID
		plain := *u
		plain.IsAdmin, plain.IsAuditor = false, false
		u = &plain
	}
	ua := &UserAccess{User: u}
	repoIDs, err := UserRepoIDs(ctx, u.ID, orgID)
	if err != nil {
		return nil, err
	}
	if ua.Rows, err = Compute(ctx, Options{RepoIDs: repoIDs, User: u}); err != nil {
		return nil, err
	}
	if org != nil {
		for _, r := range ua.Rows {
			hideGroups(r, false)
		}
		if org.Visibility == structs.VisibleTypePrivate && !u.IsRestricted {
			isMember, err := organization.IsOrganizationMember(ctx, org.ID, u.ID)
			if err != nil {
				return nil, err
			}
			if isMember {
				ua.PrivateOrgs = []*organization.Organization{org}
			}
		}
		ua.Teams, err = organization.GetUserOrgTeams(ctx, org.ID, u.ID)
		return ua, err
	}

	if u.IsAdmin || u.IsAuditor {
		grants, err := organization.GetUsersGrantedRoleGroups(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		ua.SiteAdminVia = grants[u.ID][string(organization.UserGroupRoleSiteAdmin)]
		ua.AuditorVia = grants[u.ID][string(organization.UserGroupRoleAuditor)]
	}
	if ua.Orgs, err = db.Find[organization.Organization](ctx, organization.FindOrgOptions{UserID: u.ID, IncludePrivate: true}); err != nil {
		return nil, err
	}
	for _, o := range ua.Orgs {
		if o.Visibility == structs.VisibleTypePrivate && !u.IsRestricted {
			ua.PrivateOrgs = append(ua.PrivateOrgs, o)
		}
	}
	if ua.Teams, err = organization.GetUserTeams(ctx, u.ID); err != nil {
		return nil, err
	}
	memberships := make([]*organization.UserGroupUser, 0, 4)
	if err := db.GetEngine(ctx).Where("uid = ?", u.ID).Find(&memberships); err != nil {
		return nil, err
	}
	groupIDs := make([]int64, 0, len(memberships))
	sourceIDs := make([]int64, 0, len(memberships))
	for _, m := range memberships {
		groupIDs = append(groupIDs, m.GroupID)
		sourceIDs = append(sourceIDs, m.LoginSourceID)
	}
	groups := map[int64]*organization.UserGroup{}
	if err := db.GetEngine(ctx).In("id", groupIDs).Find(&groups); err != nil {
		return nil, err
	}
	sources := map[int64]*auth_model.Source{}
	if err := db.GetEngine(ctx).In("id", sourceIDs).Find(&sources); err != nil {
		return nil, err
	}
	for _, m := range memberships {
		if g := groups[m.GroupID]; g != nil {
			ua.Groups = append(ua.Groups, &Group{Group: g, Source: sources[m.LoginSourceID]})
		}
	}
	if ua.PublicKeys, err = db.Find[asymkey_model.PublicKey](ctx, asymkey_model.FindPublicKeyOptions{OwnerID: u.ID}); err != nil {
		return nil, err
	}
	if ua.AccessTokens, err = db.Find[auth_model.AccessToken](ctx, auth_model.ListAccessTokensOptions{UserID: u.ID}); err != nil {
		return nil, err
	}
	ua.OAuth2Grants, err = auth_model.GetOAuth2GrantsByUserID(ctx, u.ID)
	return ua, err
}

// ParseFilter reads a filter from the query parameters mode, unit, type, external and inactive_days.
func ParseFilter(get func(string) string) Filter {
	days, _ := strconv.Atoi(get("inactive_days"))
	f := Filter{Mode: perm_model.ParseAccessMode(get("mode")), Type: get("type"), ExternalOnly: get("external") == "true", InactiveDays: days}
	if u := get("unit"); u != "" {
		f.Unit = unit.TypeFromKey(u)
	}
	return f
}
