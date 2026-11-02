// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package convert

import (
	"cmp"
	"context"
	"maps"
	"slices"

	perm_model "forgejo.org/models/perm"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	api "forgejo.org/modules/structs"
	"forgejo.org/services/accessreport"
)

func toAccessUnits(units map[unit.Type]perm_model.AccessMode) map[string]string {
	if units == nil {
		return nil
	}
	m := make(map[string]string, len(units))
	for tp, mode := range units {
		if u, ok := unit.Units[tp]; ok {
			m[u.NameKey] = mode.String()
		}
	}
	return m
}

// ToAccessRows converts access report rows
func ToAccessRows(ctx context.Context, rows []*accessreport.Row, doer *user_model.User) []*api.AccessRow {
	out := make([]*api.AccessRow, 0, len(rows))
	for _, r := range rows {
		ar := &api.AccessRow{Type: r.Type(), Repository: r.Repo.FullName(), Access: accessreport.Highest(r.Perm).String(), Units: map[string]string{}}
		for _, ru := range r.Repo.Units {
			if m := r.Perm.UnitAccessMode(ru.Type); m > perm_model.AccessModeNone {
				ar.Units[ru.Unit().NameKey] = m.String()
			}
		}
		switch {
		case r.User != nil:
			ar.User = ToUser(ctx, r.User, doer)
		case r.DeployKey != nil:
			ar.DeployKey = &api.AccessDeployKey{ID: r.DeployKey.ID, Name: r.DeployKey.Name, Fingerprint: r.DeployKey.Fingerprint, Expires: OptionalTime(r.DeployKey.ExpiresUnix)}
		case r.OrgDeployKey != nil:
			ar.DeployKey = &api.AccessDeployKey{ID: r.OrgDeployKey.ID, Name: r.OrgDeployKey.Name, Fingerprint: r.OrgDeployKey.Fingerprint, Expires: OptionalTime(r.OrgDeployKey.ExpiresUnix)}
		case r.AccessToken != nil:
			ar.AccessToken = &api.AccessAccessToken{ID: r.AccessToken.ID, Name: r.AccessToken.Name, Scopes: r.AccessToken.Scope.OrderedScopes(), Expires: OptionalTime(r.AccessToken.ExpiresUnix)}
		case r.Team != nil:
			ar.Type = "team"
			ar.Team = &api.AccessTeam{ID: r.Team.ID, Name: r.Team.Name, NumMembers: r.Team.NumMembers}
		case r.Anonymous:
			ar.Type = "anyone"
		case r.Paths[0].Kind == accessreport.KindOrgMember:
			ar.Type = "org_members"
		case r.Paths[0].Kind == accessreport.KindInstanceRoles:
			ar.Type = "instance_roles"
			ar.Access, ar.Units = "", nil
		default:
			ar.Type = "signed_in"
		}
		for _, p := range r.Paths {
			ap := &api.AccessPath{Kind: string(p.Kind), Access: p.Mode.String(), Units: toAccessUnits(p.Units), Applied: p.Applied}
			if p.Team != nil {
				ap.Team = p.Team.Name
			}
			for _, g := range p.Groups {
				ag := &api.AccessUserGroup{Name: g.Group.Name}
				if g.Source != nil {
					ag.LoginSource = g.Source.Name
				}
				ap.UserGroups = append(ap.UserGroups, ag)
			}
			ar.Paths = append(ar.Paths, ap)
		}
		out = append(out, ar)
	}
	return out
}

// ToAccessReportLines converts access report rows to one line per path to each unit with access, or to all the
// repository if none; people, if set, fills the person columns of the users.
func ToAccessReportLines(ctx context.Context, rows []*accessreport.Row, doer *user_model.User, people map[int64]*accessreport.Person) []*api.AccessReportLine {
	var out []*api.AccessReportLine
	for i, ar := range ToAccessRows(ctx, rows, doer) {
		base := api.AccessReportLine{Type: ar.Type, Repository: ar.Repository}
		switch {
		case ar.User != nil:
			base.Name, base.FullName = ar.User.UserName, ar.User.FullName
			if u, p := rows[i].User, people[rows[i].User.ID]; p != nil {
				suspended := u.ProhibitLogin || !u.IsActive
				base.LastLogin, base.LastPush, base.TwoFactor, base.AccountSource, base.Suspended = OptionalTime(u.LastLoginUnix), OptionalTime(p.LastPush), &p.TwoFactor, p.AccountSource, &suspended
			}
		case ar.DeployKey != nil:
			base.Name = ar.DeployKey.Name
		case ar.AccessToken != nil:
			base.Name, base.Scopes = ar.AccessToken.Name, ar.AccessToken.Scopes
		case ar.Team != nil:
			base.Name = ar.Team.Name
		}
		units := slices.Sorted(maps.Keys(ar.Units))
		if len(units) == 0 {
			ar.Units = map[string]string{"*": ar.Access}
			units = []string{"*"}
		}
		for _, u := range units {
			for _, p := range ar.Paths {
				l := base
				l.Unit, l.Access, l.Path, l.Team, l.UserGroups, l.Applied = u, ar.Units[u], p.Kind, p.Team, p.UserGroups, p.Applied
				l.Grant = p.Access
				if p.Units != nil {
					l.Grant = cmp.Or(p.Units[u], perm_model.AccessModeNone.String())
				}
				out = append(out, &l)
			}
		}
	}
	return out
}

// ToUserAccess converts what gives a user access
func ToUserAccess(ctx context.Context, ua *accessreport.UserAccess, doer *user_model.User) *api.UserAccess {
	out := &api.UserAccess{
		SiteAdmin: ua.User.IsAdmin, SiteAdminVia: ua.SiteAdminVia,
		Auditor: ua.User.IsAuditor, AuditorVia: ua.AuditorVia,
		Orgs: []string{}, PrivateOrgs: []string{}, Teams: []string{}, UserGroups: []*api.AccessUserGroup{},
		Rows:        ToAccessRows(ctx, ua.Rows, doer),
		Credentials: []*api.AccessCredential{},
	}
	for _, o := range ua.Orgs {
		out.Orgs = append(out.Orgs, o.Name)
	}
	for _, o := range ua.PrivateOrgs {
		out.PrivateOrgs = append(out.PrivateOrgs, o.Name)
	}
	for _, t := range ua.Teams {
		out.Teams = append(out.Teams, t.Name)
	}
	for _, g := range ua.Groups {
		ag := &api.AccessUserGroup{Name: g.Group.Name}
		if g.Source != nil {
			ag.LoginSource = g.Source.Name
		}
		out.UserGroups = append(out.UserGroups, ag)
	}
	for _, k := range ua.PublicKeys {
		out.Credentials = append(out.Credentials, &api.AccessCredential{Kind: "ssh_key", Name: k.Name, Fingerprint: k.Fingerprint, Created: k.CreatedUnix.AsTime(), LastUsed: k.UpdatedUnix.AsTime(), Expires: OptionalTime(k.ExpiresUnix)})
	}
	for _, t := range ua.AccessTokens {
		out.Credentials = append(out.Credentials, &api.AccessCredential{Kind: "access_token", Name: t.Name, LastEight: t.TokenLastEight, Scopes: t.Scope.StringSlice(), Created: t.CreatedUnix.AsTime(), LastUsed: t.UpdatedUnix.AsTime(), Expires: OptionalTime(t.ExpiresUnix)})
	}
	for _, g := range ua.OAuth2Grants {
		out.Credentials = append(out.Credentials, &api.AccessCredential{Kind: "oauth2_grant", Name: g.Application.Name, Scopes: []string{g.Scope}, Created: g.CreatedUnix.AsTime(), LastUsed: g.UpdatedUnix.AsTime()})
	}
	return out
}
