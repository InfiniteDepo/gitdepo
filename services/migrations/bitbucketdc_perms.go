// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package migrations

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"forgejo.org/models"
	asymkey_model "forgejo.org/models/asymkey"
	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/authz"
	"forgejo.org/services/branchworkflow"
	repo_service "forgejo.org/services/repository"
	"forgejo.org/services/usergroup"
)

// bitbucketPermission is what an item of kind team, member, group, collaborator or key needs to be applied.
type bitbucketPermission struct {
	perms     []*BitbucketImportItem // of a project: everything to apply after its repositories, in order
	parent    *BitbucketImportItem   // the project or repository of a team, collaborator or key; the team of a member or group
	mode      perm.AccessMode
	user      *user_model.User
	userGroup *organization.UserGroup
	team      *organization.Team
	content   string // the public key
	expires   timeutil.TimeStamp
	keyID     int64 // the public key ID of a repository key once it exists

	rule                                *git_model.ProtectedBranch
	ruleOpts                            git_model.WhitelistOptions
	pushKeys, deleteKeys, forcePushKeys []*BitbucketImportItem
	hook                                *webhook_model.Webhook
	branchingModel                      *repo_model.BranchingModel
}

type bitbucketAccount struct {
	Name         string `json:"name"`
	EmailAddress string `json:"emailAddress"`
	Active       bool   `json:"active"`
}

type bitbucketUserGrant struct {
	User       bitbucketAccount `json:"user"`
	Permission string           `json:"permission"`
}

type bitbucketGroupGrant struct {
	Group struct {
		Name string `json:"name"`
	} `json:"group"`
	Permission string `json:"permission"`
}

type bitbucketAccessKey struct {
	Key struct {
		ID          int64  `json:"id"`
		Text        string `json:"text"`
		Label       string `json:"label"`
		CreatedDate int64  `json:"createdDate"` // milliseconds
		ExpiryDays  int64  `json:"expiryDays"`
	} `json:"key"`
	Permission string `json:"permission"`
}

// bitbucketAccess maps a Bitbucket permission to the access it gets: read stays read, and admin becomes write because
// imported teams carry Code and pull requests only. Anything else gets nothing.
func bitbucketAccess(permission string) (perm.AccessMode, string) {
	switch permission {
	case "PROJECT_READ", "REPO_READ":
		return perm.AccessModeRead, ""
	case "PROJECT_WRITE", "REPO_WRITE":
		return perm.AccessModeWrite, ""
	case "PROJECT_ADMIN", "REPO_ADMIN":
		return perm.AccessModeWrite, "admin mapped to write"
	}
	return perm.AccessModeNone, ""
}

// bitbucketKeyExpiry is the earliest of the expiries that are set (not 0), or 0 if none is.
func bitbucketKeyExpiry(expiries ...timeutil.TimeStamp) timeutil.TimeStamp {
	var earliest timeutil.TimeStamp
	for _, e := range expiries {
		if e != 0 && (earliest == 0 || e < earliest) {
			earliest = e
		}
	}
	return earliest
}

// bitbucketUnmatched is the reason code of a Bitbucket user without a gitdepo user.
type bitbucketUnmatched string

func (e bitbucketUnmatched) Error() string { return string(e) }

// matchBitbucketUser finds the gitdepo user of a Bitbucket user: the login is the Bitbucket name, and the Bitbucket
// email is an activated email of that same user, who is an active individual allowed to sign in. Otherwise it returns
// a bitbucketUnmatched reason code; the email is never reported.
func matchBitbucketUser(ctx context.Context, bu bitbucketAccount) (*user_model.User, error) {
	if !bu.Active {
		return nil, bitbucketUnmatched("bb_inactive")
	}
	u, err := user_model.GetUserByName(ctx, bu.Name)
	if user_model.IsErrUserNotExist(err) || (err == nil && !u.IsIndividual()) {
		return nil, bitbucketUnmatched("no_user")
	} else if err != nil {
		return nil, err
	}
	if !u.IsActive || u.ProhibitLogin {
		return nil, bitbucketUnmatched("inactive")
	}
	if bu.EmailAddress == "" {
		return nil, bitbucketUnmatched("email_mismatch")
	}
	email, err := user_model.GetEmailAddressByEmail(ctx, bu.EmailAddress)
	if user_model.IsErrEmailAddressNotExist(err) || (err == nil && email.UID != u.ID) {
		return nil, bitbucketUnmatched("email_mismatch")
	} else if err != nil {
		return nil, err
	}
	if !email.IsActivated {
		return nil, bitbucketUnmatched("email_not_activated")
	}
	return u, nil
}

// bitbucketTeamShape reports whether an existing team has exactly the shape the importer gives a team: not the owner
// team, the mode, exactly two units (Code and pull requests at that mode), and either linked to the project (groupID)
// alone with only that project's repositories, or holding only the repository (repoID) with no link.
func bitbucketTeamShape(ctx context.Context, team *organization.Team, mode perm.AccessMode, groupID, repoID int64) (bool, error) {
	if team.IsOwnerTeam() || team.AccessMode != mode || team.IncludesAllRepositories || team.CanCreateOrgRepo {
		return false, nil
	}
	if err := team.LoadUnits(ctx); err != nil {
		return false, err
	}
	if len(team.Units) != 2 {
		return false, nil
	}
	for _, u := range team.Units {
		if (u.Type != unit.TypeCode && u.Type != unit.TypePullRequests) || u.AccessMode != mode {
			return false, nil
		}
	}
	var groupIDs []int64
	if err := db.GetEngine(ctx).Table("team_group").Where("team_id = ?", team.ID).Cols("group_id").Find(&groupIDs); err != nil {
		return false, err
	}
	if groupID != 0 {
		// every repository row comes from the link: none direct, none outside the project
		outside, err := db.GetEngine(ctx).Table("team_repo").Join("INNER", "repository", "repository.id = team_repo.repo_id").
			Where("team_repo.team_id = ? AND (team_repo.via_group = ? OR repository.group_id <> ?)", team.ID, false, groupID).Count()
		return err == nil && outside == 0 && slices.Equal(groupIDs, []int64{groupID}), err
	}
	var rows []*organization.TeamRepo
	if err := db.GetEngine(ctx).Where("team_id = ?", team.ID).Find(&rows); err != nil {
		return false, err
	}
	return len(groupIDs) == 0 && len(rows) == 1 && rows[0].RepoID == repoID && !rows[0].ViaGroup, nil
}

// bitbucketPlanner plans the permissions and keys of one project.
type bitbucketPlanner struct {
	ctx       context.Context
	d         *BitbucketDataCenterDownloader
	org       *organization.Organization
	report    *BitbucketImportReport
	project   *BitbucketImportItem
	keyExpiry timeutil.TimeStamp
	teams     map[string]*BitbucketImportItem // the teams of the whole run, by lower-case name

	skipUnmapped bool
	keys         map[*BitbucketImportItem]map[int64]*BitbucketImportItem // the keys of a project or repository by Bitbucket key ID
	members      map[int64]bool                                          // users the plan makes org members
	writers      map[*BitbucketImportItem]map[int64]bool                 // users the plan lets write a project's or repository's code
}

func (p *bitbucketPlanner) add(item *BitbucketImportItem, status, reason string) {
	item.set(status, reason)
	if status == BitbucketConflict {
		p.report.Blocked = true
	}
	p.project.perms = append(p.project.perms, item)
	p.report.Items = append(p.report.Items, item)
}

func (p *bitbucketPlanner) unmapped(owner *BitbucketImportItem, what string) {
	p.add(&BitbucketImportItem{Kind: "permission", Bitbucket: util.StripControl(what), Target: owner.Name}, BitbucketSkipped, "unmapped")
}

// planBitbucketPermissions plans, without writing, the teams, members, user group links, collaborators and deploy
// keys of a project and its repositories.
func planBitbucketPermissions(ctx context.Context, d *BitbucketDataCenterDownloader, org *organization.Organization, report *BitbucketImportReport, project *BitbucketImportItem, keyExpiry timeutil.TimeStamp, teams map[string]*BitbucketImportItem, skipUnmapped bool) error {
	p := &bitbucketPlanner{
		ctx: ctx, d: d, org: org, report: report, project: project, keyExpiry: keyExpiry, teams: teams, skipUnmapped: skipUnmapped, keys: map[*BitbucketImportItem]map[int64]*BitbucketImportItem{},
		members: map[int64]bool{}, writers: map[*BitbucketImportItem]map[int64]bool{},
	}
	if err := p.plan(project, "api/1.0/projects/"+project.key); err != nil {
		return err
	}
	for _, mode := range []string{"PROJECT_READ", "PROJECT_WRITE"} {
		var all struct {
			Permitted bool `json:"permitted"`
		}
		if err := d.callAPI("api/1.0/projects/"+project.key+"/permissions/"+mode+"/all", nil, &all); err != nil {
			return err
		}
		if all.Permitted {
			p.unmapped(project, project.key+" default "+mode)
		}
	}
	for _, repo := range project.repos {
		if repo.Status == BitbucketConflict {
			continue
		}
		if err := p.plan(repo, "api/1.0/projects/"+project.key+"/repos/"+repo.slug); err != nil {
			return err
		}
	}
	if err := p.planKeys(project, "keys/1.0/projects/"+project.key+"/ssh"); err != nil {
		return err
	}
	return p.planRulesAndHooks(project, "projects/"+project.key)
}

// planRulesAndHooks plans the branch rules and the webhooks of a project or repository, after its keys.
func (p *bitbucketPlanner) planRulesAndHooks(owner *BitbucketImportItem, path string) error {
	if err := p.planRules(owner, "branch-permissions/2.0/"+path+"/restrictions"); err != nil {
		return err
	}
	return p.planHooks(owner, "api/1.0/"+path+"/webhooks")
}

// plan plans the user and group grants of a project or repository, and its repository keys.
func (p *bitbucketPlanner) plan(owner *BitbucketImportItem, endpoint string) error {
	if owner.public {
		p.unmapped(owner, owner.Bitbucket+" public")
	}
	users, err := callAPIPaged[bitbucketUserGrant](p.d, endpoint+"/permissions/users")
	if err != nil {
		return err
	}
	groups, err := callAPIPaged[bitbucketGroupGrant](p.d, endpoint+"/permissions/groups")
	if err != nil {
		return err
	}
	for _, g := range users {
		mode, note := bitbucketAccess(g.Permission)
		if mode == perm.AccessModeNone {
			p.unmapped(owner, g.User.Name+" "+g.Permission)
			continue
		}
		if err := p.planUser(owner, g, mode, note); err != nil {
			return err
		}
	}
	for _, g := range groups {
		mode, note := bitbucketAccess(g.Permission)
		if mode == perm.AccessModeNone {
			p.unmapped(owner, g.Group.Name+" "+g.Permission)
			continue
		}
		item := &BitbucketImportItem{Kind: "group", Bitbucket: util.StripControl(g.Group.Name), Target: p.teamName(owner, mode), Access: mode.String()}
		group, err := organization.GetUserGroupByName(p.ctx, g.Group.Name)
		if organization.IsErrUserGroupNotExist(err) || (err == nil && group.Name != g.Group.Name) {
			p.add(item, BitbucketSkipped, "no user group") // and no team for it
			continue
		} else if err != nil {
			return err
		}
		team, err := p.planTeam(owner, mode)
		if err != nil {
			return err
		}
		item.Name, item.userGroup, item.parent = group.Name, group, team
		status := BitbucketPlanned
		if team.team != nil {
			if linked, err := organization.IsUserGroupLinkedToTeam(p.ctx, group.ID, team.team.ID); err != nil {
				return err
			} else if linked {
				status = BitbucketReused
			}
		}
		p.add(item, status, note)
	}
	if owner.Kind == "repository" {
		if err := p.planKeys(owner, "keys/1.0/projects/"+p.project.key+"/repos/"+owner.slug+"/ssh"); err != nil {
			return err
		}
		if err := p.planBranchingModel(owner); err != nil {
			return err
		}
		return p.planRulesAndHooks(owner, "projects/"+p.project.key+"/repos/"+owner.slug)
	}
	return nil
}

// teamName is the name of the team of a project or repository at a mode: <project>[-<repo>]-<mode>.
func (p *bitbucketPlanner) teamName(owner *BitbucketImportItem, mode perm.AccessMode) string {
	name := p.project.groupName
	if owner != p.project {
		name += "-" + owner.slug
	}
	return name + "-" + mode.String()
}

// planTeam plans the team of a project (linked to it) or of a repository (holding only it) at a mode, once. Two
// different teams of the run with one name are a conflict.
func (p *bitbucketPlanner) planTeam(owner *BitbucketImportItem, mode perm.AccessMode) (*BitbucketImportItem, error) {
	name := p.teamName(owner, mode)
	item := &BitbucketImportItem{Kind: "team", Name: name, Target: owner.Name, Access: mode.String(), bitbucketPermission: bitbucketPermission{parent: owner, mode: mode}}
	if team, ok := p.teams[strings.ToLower(name)]; ok {
		if team.parent == owner && team.mode == mode {
			return team, nil
		}
		p.add(item, BitbucketConflict, "another team of this import has this name")
		return item, nil
	}
	p.teams[strings.ToLower(name)] = item
	team, err := organization.GetTeam(p.ctx, p.org.ID, name)
	if organization.IsErrTeamNotExist(err) {
		if len(name) > 255 {
			p.add(item, BitbucketConflict, "the team name is too long")
		} else {
			p.add(item, BitbucketPlanned, "")
		}
		return item, nil
	} else if err != nil {
		return nil, err
	}
	// reuse only a team of exactly the importer's shape, so that adding members never widens its access
	same := false
	if owner.group != nil {
		same, err = bitbucketTeamShape(p.ctx, team, mode, owner.group.ID, 0)
	} else if owner.repo != nil {
		same, err = bitbucketTeamShape(p.ctx, team, mode, 0, owner.repo.ID)
	}
	if err != nil {
		return nil, err
	}
	if !same {
		p.add(item, BitbucketConflict, "a team of this name exists and isn't one this import created")
		return item, nil
	}
	item.team = team
	p.add(item, BitbucketReused, "")
	return item, nil
}

// planUser plans a member of a project team, or a collaborator of a repository.
func (p *bitbucketPlanner) planUser(owner *BitbucketImportItem, g bitbucketUserGrant, mode perm.AccessMode, note string) error {
	item := &BitbucketImportItem{Kind: "collaborator", Bitbucket: util.StripControl(g.User.Name), Target: owner.Name, Access: mode.String(), bitbucketPermission: bitbucketPermission{parent: owner, mode: mode}}
	var team *BitbucketImportItem
	if owner == p.project {
		var err error
		if team, err = p.planTeam(owner, mode); err != nil {
			return err
		}
		item.Kind, item.Target, item.parent = "member", team.Name, team
	}
	u, err := matchBitbucketUser(p.ctx, g.User)
	if unmatched, ok := errors.AsType[bitbucketUnmatched](err); ok {
		p.add(item, BitbucketSkipped, string(unmatched))
		return nil
	} else if err != nil {
		return err
	}
	item.Name, item.user = u.Name, u
	if blocked, err := u.TwoFactorBlocked(p.ctx, p.org.AsUser()); err != nil {
		return err
	} else if blocked {
		note = strings.TrimPrefix(note+"; blocked until two-factor is enabled", "; ")
	}

	if team != nil {
		if member, err := organization.IsOrganizationMember(p.ctx, p.org.ID, u.ID); err != nil {
			return err
		} else if !member {
			if err := organization.CheckVerifiedDomainGate(p.ctx, p.org.ID, u.ID); organization.IsErrUserNoVerifiedDomainEmail(err) {
				p.add(item, BitbucketSkipped, "no verified-domain email")
				return nil
			} else if err != nil {
				return err
			}
		}
		status := BitbucketPlanned
		if team.team != nil {
			if member, err := organization.IsTeamMember(p.ctx, p.org.ID, team.team.ID, u.ID); err != nil {
				return err
			} else if member {
				status = BitbucketReused
			}
		}
		p.add(item, status, note)
		p.grant(p.project, u.ID, mode)
		return nil
	}

	if owner, err := organization.IsOrganizationOwner(p.ctx, p.org.ID, u.ID); err != nil {
		return err
	} else if owner {
		p.add(item, BitbucketSkipped, "an owner of the organization")
		return nil
	}
	if user_model.IsBlocked(p.ctx, p.org.ID, u.ID) || user_model.IsBlocked(p.ctx, u.ID, p.org.ID) {
		p.add(item, BitbucketSkipped, "blocked")
		return nil
	}
	// a collaborator isn't an organization member, so the verified-domain gate doesn't apply (as on the web and API)
	note = strings.TrimSuffix("added as a collaborator, not a member; "+note, "; ")
	status := BitbucketPlanned
	if owner.repo != nil {
		c := &repo_model.Collaboration{RepoID: owner.repo.ID, UserID: u.ID}
		if has, err := db.GetEngine(p.ctx).Get(c); err != nil {
			return err
		} else if has && c.Mode == mode {
			status = BitbucketReused
		} else if has {
			p.add(item, BitbucketSkipped, "an existing collaborator, kept as is")
			return nil
		}
	}
	p.add(item, status, note)
	p.grant(owner, u.ID, mode)
	return nil
}

// grant records what the plan gives a user, so that a rule planned in the same run can tell who will be an org member
// (a project team) and who will write a repository (a write team of its project, or a write collaboration).
func (p *bitbucketPlanner) grant(owner *BitbucketImportItem, uid int64, mode perm.AccessMode) {
	if owner == p.project {
		p.members[uid] = true
	}
	if mode >= perm.AccessModeWrite {
		if p.writers[owner] == nil {
			p.writers[owner] = map[int64]bool{}
		}
		p.writers[owner][uid] = true
	}
}

// planKeys plans the access keys of a project or repository as deploy keys, each with an expiry.
func (p *bitbucketPlanner) planKeys(owner *BitbucketImportItem, endpoint string) error {
	keys, err := callAPIPaged[bitbucketAccessKey](p.d, endpoint)
	if err != nil {
		return err
	}
	for _, k := range keys {
		item := &BitbucketImportItem{Kind: "key", Bitbucket: util.StripControl(fmt.Sprintf("%s key %d", owner.Bitbucket, k.Key.ID)), Target: owner.Name, bitbucketPermission: bitbucketPermission{parent: owner}}
		item.Name = strings.TrimSpace(util.StripControl(k.Key.Label))
		if item.Name == "" {
			item.Name = fmt.Sprintf("bitbucket-%d", k.Key.ID)
		}
		switch k.Permission {
		case "PROJECT_READ", "REPO_READ":
			item.mode = perm.AccessModeRead
		case "PROJECT_WRITE", "REPO_WRITE":
			item.mode = perm.AccessModeWrite
		default:
			p.add(item, BitbucketSkipped, "unmapped")
			continue
		}
		item.Access = item.mode.String()
		if setting.SSH.Disabled {
			p.add(item, BitbucketSkipped, "SSH is disabled")
			continue
		}
		if item.content, err = asymkey_model.CheckPublicKeyString(k.Key.Text); err != nil {
			p.add(item, BitbucketSkipped, "not a valid public key")
			continue
		}
		var bitbucket timeutil.TimeStamp
		if k.Key.CreatedDate > 0 && k.Key.ExpiryDays > 0 {
			bitbucket = timeutil.TimeStamp(k.Key.CreatedDate/1000 + k.Key.ExpiryDays*86400)
			if bitbucket <= timeutil.TimeStampNow() {
				p.add(item, BitbucketSkipped, "expired in Bitbucket")
				continue
			}
		}
		item.expires = bitbucketKeyExpiry(bitbucket, authz.MaxExpiry(setting.DeployKeyExpiry), p.keyExpiry)
		if item.expires == 0 {
			p.add(item, BitbucketConflict, "no expiry: pass --key-expiry")
			continue
		}
		if err := authz.ValidateExpiry(setting.DeployKeyExpiry, item.expires); err != nil {
			p.add(item, BitbucketConflict, err.Error())
			continue
		}
		item.Expires = item.expires.FormatDate()

		fingerprint, err := asymkey_model.CalcFingerprint(item.content)
		if err != nil {
			p.add(item, BitbucketSkipped, "not a valid public key")
			continue
		}
		if pkey, err := asymkey_model.SearchPublicKeyByContentExact(p.ctx, item.content); err == nil && pkey.Type != asymkey_model.KeyTypeDeploy {
			p.add(item, BitbucketSkipped, "used as a user key")
			continue
		} else if err != nil && !asymkey_model.IsErrKeyNotExist(err) {
			return err
		}
		var exists bool
		if owner.group != nil && owner == p.project {
			exists, err = db.GetEngine(p.ctx).Exist(&asymkey_model.OrgDeployKey{OrgID: p.org.ID, GroupID: owner.group.ID, Fingerprint: fingerprint})
		} else if owner.repo != nil {
			key := &asymkey_model.DeployKey{RepoID: owner.repo.ID, Fingerprint: fingerprint}
			exists, err = db.GetEngine(p.ctx).Get(key)
			item.keyID = key.KeyID
		}
		if err != nil {
			return err
		}
		if p.keys[owner] == nil {
			p.keys[owner] = map[int64]*BitbucketImportItem{}
		}
		p.keys[owner][k.Key.ID] = item
		note := ""
		if owner == p.project {
			note = "covers every repository of the project, also ones moved in later"
		}
		if exists {
			p.add(item, BitbucketReused, note)
		} else {
			p.add(item, BitbucketPlanned, note)
		}
	}
	return nil
}

// addBitbucketCollaborator adds the user as a collaborator at the mode, unless they already are one.
func addBitbucketCollaborator(ctx context.Context, repo *repo_model.Repository, u *user_model.User, mode perm.AccessMode) (existed bool, err error) {
	err = db.WithTx(ctx, func(ctx context.Context) error {
		if existed, err = repo_model.IsCollaborator(ctx, repo.ID, u.ID); err != nil || existed {
			return err
		}
		return repo_module.AddCollaborator(ctx, repo, u, mode)
	})
	return existed, err
}

// repoDeployKeyID returns the public key ID of the repository's deploy key with that content.
func repoDeployKeyID(ctx context.Context, repoID int64, content string) (int64, error) {
	fingerprint, err := asymkey_model.CalcFingerprint(content)
	if err != nil {
		return 0, err
	}
	key := &asymkey_model.DeployKey{RepoID: repoID, Fingerprint: fingerprint}
	_, err = db.GetEngine(ctx).Get(key)
	return key.KeyID, err
}

// applyBitbucketPermissions applies the planned permissions and keys of a project once its repositories were
// imported. Each item is applied on its own: one that fails is reported and the others go on.
func applyBitbucketPermissions(ctx context.Context, doer *user_model.User, org *organization.Organization, project *BitbucketImportItem, failure func(*BitbucketImportItem, error)) {
	for _, item := range project.perms {
		if item.Status != BitbucketPlanned {
			continue
		}
		if ctx.Err() != nil {
			item.set(BitbucketFailed, "the import was cancelled")
			continue
		}
		parent := item.parent
		var owner *BitbucketImportItem // the project or repository the grant needs
		switch item.Kind {
		case "team", "collaborator", "key", "rule", "hook", "branching_model":
			owner = parent
		}
		if owner != nil && owner.group == nil && owner.repo == nil {
			item.set(BitbucketSkipped, "its "+owner.Kind+" was not imported")
			continue
		}
		if (item.Kind == "member" || item.Kind == "group") && parent.team == nil {
			item.set(BitbucketSkipped, "its team was not created")
			continue
		}

		var err error
		status := BitbucketCreated
		switch item.Kind {
		case "team":
			team := &organization.Team{OrgID: org.ID, Name: item.Name, AccessMode: item.mode, Units: []*organization.TeamUnit{
				{OrgID: org.ID, Type: unit.TypeCode, AccessMode: item.mode},
				{OrgID: org.ID, Type: unit.TypePullRequests, AccessMode: item.mode},
			}}
			err = db.WithTx(ctx, func(ctx context.Context) error {
				if err := models.NewTeam(ctx, team); err != nil {
					return err
				}
				if owner.Kind == "project" {
					return repo_service.LinkTeamToRepoGroup(ctx, doer, org, team.ID, owner.group.ID)
				}
				if err := models.AddRepository(ctx, team, owner.repo); err != nil {
					return err
				}
				return organization.RecordTeamRepo(ctx, "org.team.repo_added", team, owner.repo)
			})
			if err == nil {
				item.team = team
			}
		case "member":
			err = models.AddTeamMemberByCooptation(ctx, parent.team, item.user.ID, doer.ID)
			if organization.IsErrUserNoVerifiedDomainEmail(err) {
				status, err = BitbucketSkipped, nil
				item.Reason = "no verified-domain email"
			}
		case "group":
			err = usergroup.LinkTeam(ctx, item.userGroup, parent.team)
			if errors.Is(err, usergroup.ErrAlreadyLinked) {
				status, err = BitbucketReused, nil
			}
		case "collaborator":
			var existed bool
			if existed, err = addBitbucketCollaborator(ctx, owner.repo, item.user, item.mode); existed {
				status, item.Reason = BitbucketSkipped, "an existing collaborator, kept as is"
			} else if errors.Is(err, user_model.ErrBlockedByUser) {
				status, err = BitbucketSkipped, nil
			}
		case "key":
			readOnly := item.mode == perm.AccessModeRead
			if owner.Kind == "project" {
				_, err = asymkey_model.AddOrgDeployKey(asymkey_model.WithKeyCreator(ctx, doer.ID), org.ID, owner.group.ID, item.Name, item.content, readOnly, false, nil, item.expires)
			} else {
				var key *asymkey_model.DeployKey
				if key, err = asymkey_model.AddDeployKey(asymkey_model.WithKeyCreator(ctx, doer.ID), owner.repo.ID, item.Name, item.content, readOnly, item.expires); err == nil {
					item.keyID = key.KeyID
				}
			}
			switch {
			case asymkey_model.IsErrDeployKeyAlreadyExist(err):
				status, err = BitbucketReused, nil
				if owner.Kind == "repository" {
					item.keyID, err = repoDeployKeyID(ctx, owner.repo.ID, item.content)
				}
			case asymkey_model.IsErrKeyAlreadyExist(err):
				status, err = BitbucketSkipped, nil
				item.Reason = "used as a user key"
			case asymkey_model.IsErrDeployKeyNameAlreadyUsed(err), asymkey_model.IsErrKeyNameAlreadyUsed(err):
				status, err = BitbucketSkipped, nil
				item.Reason = "the name is used"
			}
		case "rule":
			err = applyBitbucketRule(ctx, org, owner, item)
		case "hook":
			err = applyBitbucketHook(ctx, org, owner, item)
		case "branching_model":
			err = branchworkflow.SetRepoModel(ctx, owner.repo, item.branchingModel)
			switch {
			case errors.Is(err, branchworkflow.ErrLocked):
				status, err, item.Reason = BitbucketSkipped, nil, "the organization enforces a branching model"
			case errors.Is(err, branchworkflow.ErrNoPullRequests):
				status, err, item.Reason = BitbucketSkipped, nil, "pull requests are off in the repository"
			}
		}
		if err != nil {
			failure(item, err)
			continue
		}
		item.Status = status
	}
}
