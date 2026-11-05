// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// AccessTokenOwnerType is what an access token belongs to: a user (personal access token), or an organization, a
// project or a repository (a token that acts as itself, not as a person).
type AccessTokenOwnerType int

const (
	AccessTokenOwnerUser    AccessTokenOwnerType = iota // UID is the user
	AccessTokenOwnerOrg                                 // OwnerID is the organization
	AccessTokenOwnerProject                             // OwnerID is the organization, GroupID the project
	AccessTokenOwnerRepo                                // OwnerID is the repository
)

// IsOwnedByUser reports whether the token is a personal access token; any other token has no user (UID is 0).
func (t *AccessToken) IsOwnedByUser() bool {
	return t.OwnerType == AccessTokenOwnerUser
}

// IsRevoked reports whether the token was revoked; its row is kept without a secret so its name stays in history.
func (t *AccessToken) IsRevoked() bool {
	return t.RevokedUnix != 0
}

// IsUsable reports whether the token still grants anything: neither expired nor revoked.
func (t *AccessToken) IsUsable() bool {
	return !t.IsExpired() && !t.IsRevoked()
}

// ReachesAllRepos reports whether the token reaches every repository its owner can: a personal or organization token
// not limited to selected repositories. A project or repository token is limited by its owner, which is what the
// scope policy's ACCESS_TOKEN_SCOPES_REQUIRING_REPO_RESTRICTION asks for.
func (t *AccessToken) ReachesAllRepos() bool {
	return t.ResourceAllRepos && (t.OwnerType == AccessTokenOwnerUser || t.OwnerType == AccessTokenOwnerOrg)
}

// PackageAccessMode is the token's access to the packages of the owner with the ID: its permission for an
// organization token covering every repository of that organization, none otherwise. Packages belong to the
// organization, not to a repository, so a narrower token never reaches them.
func (t *AccessToken) PackageAccessMode(ownerID int64) perm.AccessMode {
	if t.OwnerType != AccessTokenOwnerOrg || !t.ResourceAllRepos || t.OwnerID != ownerID || !t.IsUsable() {
		return perm.AccessModeNone
	}
	return t.Mode
}

// ErrOwnedTokenPackageScope refuses a package scope on a token that can't reach packages (see PackageAccessMode).
var ErrOwnedTokenPackageScope = fmt.Errorf("%w: package scopes need an organization token covering every repository", ErrOwnedTokenScope)

// ErrOwnedTokenScope is the refusal of a scope that a token of an organization, a project or a repository can't have.
var ErrOwnedTokenScope = errors.New("scope not allowed for an organization, project or repository token")

// ownedTokenScopeBits are the scopes a token that isn't a person's may hold; anything about a user, the instance or
// writing an organization is refused when it is created and when it is used.
const ownedTokenScopeBits = accessTokenScopeWriteRepositoryBits | accessTokenScopeWriteIssueBits |
	accessTokenScopeWritePackageBits | accessTokenScopeReadOrganizationBits

// OwnedTokenScopeCategories are the scope categories a token of an organization, a project or a repository may hold,
// in the order the create form offers them; organization offers read only.
var OwnedTokenScopeCategories = []string{"repository", "issue", "package", "organization"}

// OrderedScopes is StringSlice in the order of OwnedTokenScopeCategories, the order of the create form.
func (s AccessTokenScope) OrderedScopes() []string {
	scopes := s.StringSlice()
	position := func(scope string) int {
		_, category, _ := strings.Cut(scope, ":")
		if i := slices.Index(OwnedTokenScopeCategories, category); i >= 0 {
			return i
		}
		return len(OwnedTokenScopeCategories)
	}
	slices.SortStableFunc(scopes, func(a, b string) int { return position(a) - position(b) })
	return scopes
}

// ValidateOwnedTokenScope returns ErrOwnedTokenScope unless every scope is allowed for an organization, project or
// repository token. An empty scope grants no API access and is allowed.
func ValidateOwnedTokenScope(scope AccessTokenScope) error {
	bitmap, err := scope.parse()
	if err != nil {
		return err
	}
	if bitmap&^ownedTokenScopeBits != 0 {
		return ErrOwnedTokenScope
	}
	return nil
}

// ErrOwnedTokenMode is the refusal of a permission other than read, write or admin.
var ErrOwnedTokenMode = errors.New("invalid access token permission")

// ValidateOwnedTokenMode returns ErrOwnedTokenMode unless mode is read, write or admin.
func ValidateOwnedTokenMode(mode perm.AccessMode) error {
	if mode < perm.AccessModeRead || mode > perm.AccessModeAdmin {
		return fmt.Errorf("%w: %v", ErrOwnedTokenMode, mode)
	}
	return nil
}

// CoversRepo reports whether a token of an organization, a project or a repository applies to the repository with
// the given ID, owner and project (0 = at the owner's root), as they are now: a repository token to its repository
// only, a project token to every repository in the project, an organization token to every repository of the
// organization or only to its selected ones. A personal access token covers nothing here.
func (t *AccessToken) CoversRepo(ctx context.Context, repoID, ownerID, groupID int64) (bool, error) {
	switch t.OwnerType {
	case AccessTokenOwnerRepo:
		return t.OwnerID == repoID, nil
	case AccessTokenOwnerProject:
		return t.OwnerID == ownerID && t.GroupID != 0 && t.GroupID == groupID, nil
	case AccessTokenOwnerOrg:
		if t.OwnerID != ownerID {
			return false, nil
		}
		if t.ResourceAllRepos {
			return true, nil
		}
		return db.GetEngine(ctx).Table("access_token_resource_repo").Where("token_id = ? AND repo_id = ?", t.ID, repoID).Exist()
	default:
		return false, nil
	}
}

// FindOwnedAccessTokensOptions lists the tokens of one owner: an organization's own (GroupID 0), one project's or one
// repository's. Without an owner it matches nothing.
type FindOwnedAccessTokensOptions struct {
	db.ListOptions
	OwnerType AccessTokenOwnerType
	OwnerID   int64
	GroupID   int64
	Name      string
	Keyword   string // part of the name, any case
}

func (opts FindOwnedAccessTokensOptions) ToConds() builder.Cond {
	if opts.OwnerType == AccessTokenOwnerUser || opts.OwnerID == 0 {
		return builder.Expr("1 = 0")
	}
	cond := builder.Eq{"owner_type": opts.OwnerType, "owner_id": opts.OwnerID, "group_id": opts.GroupID, "revoked_unix": 0}
	if opts.Name != "" {
		cond["name"] = opts.Name
	}
	if opts.Keyword != "" {
		return cond.And(builder.Like{"LOWER(name)", strings.ToLower(opts.Keyword)})
	}
	return cond
}

// FindOwnedAccessTokensCoveringRepo returns the organization and project tokens that cover the repository with the
// given ID, owner and project (0 = at the owner's root), newest first; the SQL form of CoversRepo for those levels.
func FindOwnedAccessTokensCoveringRepo(ctx context.Context, repoID, ownerID, groupID int64) ([]*AccessToken, error) {
	orgCond := builder.Eq{"owner_type": AccessTokenOwnerOrg, "owner_id": ownerID, "group_id": 0, "revoked_unix": 0}.And(builder.Or(
		builder.Eq{"resource_all_repos": true},
		builder.In("id", builder.Select("token_id").From("access_token_resource_repo").Where(builder.Eq{"repo_id": repoID})),
	))
	cond := builder.Or(orgCond)
	if groupID != 0 {
		cond = cond.Or(builder.Eq{"owner_type": AccessTokenOwnerProject, "owner_id": ownerID, "group_id": groupID, "revoked_unix": 0})
	}
	tokens := make([]*AccessToken, 0, 4)
	return tokens, db.GetEngine(ctx).Where(cond).OrderBy("created_unix DESC, id DESC").Find(&tokens)
}

// CoveredRepo names a repository for FindOwnedAccessTokensCoveringRepos: its ID, owner and project (0 = at the owner's
// root).
type CoveredRepo struct{ ID, OwnerID, GroupID int64 }

// FindOwnedAccessTokensCoveringRepos returns, by repository ID, the tokens of the repository, its organization and its
// project that cover it, expired ones too but never revoked ones, ordered by name; the bulk form of CoversRepo, in two
// queries.
func FindOwnedAccessTokensCoveringRepos(ctx context.Context, repos []CoveredRepo) (map[int64][]*AccessToken, error) {
	out := make(map[int64][]*AccessToken, len(repos))
	if len(repos) == 0 {
		return out, nil
	}
	repoIDs := make([]int64, 0, len(repos))
	ownerIDs := make([]int64, 0, len(repos))
	for _, r := range repos {
		repoIDs = append(repoIDs, r.ID)
		ownerIDs = append(ownerIDs, r.OwnerID)
	}
	tokens := make([]*AccessToken, 0, 10)
	if err := db.GetEngine(ctx).Where(builder.Eq{"revoked_unix": 0}.And(builder.Or(
		builder.Eq{"owner_type": AccessTokenOwnerRepo}.And(builder.In("owner_id", repoIDs)),
		builder.In("owner_type", AccessTokenOwnerOrg, AccessTokenOwnerProject).And(builder.In("owner_id", ownerIDs)),
	))).OrderBy("name, id").Find(&tokens); err != nil {
		return nil, err
	}
	var selectedIDs []int64
	for _, t := range tokens {
		if t.OwnerType == AccessTokenOwnerOrg && !t.ResourceAllRepos {
			selectedIDs = append(selectedIDs, t.ID)
		}
	}
	selected := make(map[[2]int64]bool)
	if len(selectedIDs) > 0 {
		var rows []*AccessTokenResourceRepo
		if err := db.GetEngine(ctx).In("token_id", selectedIDs).In("repo_id", repoIDs).Find(&rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			selected[[2]int64{r.TokenID, r.RepoID}] = true
		}
	}
	for _, r := range repos {
		for _, t := range tokens {
			var covers bool
			switch t.OwnerType {
			case AccessTokenOwnerRepo:
				covers = t.OwnerID == r.ID
			case AccessTokenOwnerProject:
				covers = t.OwnerID == r.OwnerID && t.GroupID != 0 && t.GroupID == r.GroupID
			case AccessTokenOwnerOrg:
				covers = t.OwnerID == r.OwnerID && t.GroupID == 0 && (t.ResourceAllRepos || selected[[2]int64{t.ID, r.ID}])
			}
			if covers {
				out[r.ID] = append(out[r.ID], t)
			}
		}
	}
	return out, nil
}

func (opts FindOwnedAccessTokensOptions) ToOrders() string {
	return "created_unix DESC, id DESC"
}

// DeleteOwnedAccessToken revokes the token with the ID of the owner opts names. The row stays as a tombstone without
// a secret, coverage or anything a lookup finds, so the token's identity keeps its name in history.
func DeleteOwnedAccessToken(ctx context.Context, opts FindOwnedAccessTokensOptions, id, doerID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		t := &AccessToken{}
		if has, err := db.GetEngine(ctx).Where(opts.ToConds()).And("id = ?", id).Get(t); err != nil {
			return err
		} else if !has {
			return ErrAccessTokenNotExist{}
		}
		var repoIDs []int64
		if err := db.GetEngine(ctx).Table("access_token_resource_repo").Where("token_id = ?", id).Cols("repo_id").Find(&repoIDs); err != nil {
			return err
		}
		if _, err := db.GetEngine(ctx).Where("token_id = ?", id).Delete(&AccessTokenResourceRepo{}); err != nil {
			return err
		}
		tomb := &AccessToken{
			RevokedUnix: timeutil.TimeStampNow(),
			RevokedByID: doerID,
			// unique like any hash, and never the hex output of HashToken, so nothing can match it
			TokenHash: fmt.Sprintf("revoked:%d", id),
		}
		if cnt, err := db.GetEngine(ctx).Where(opts.ToConds()).And("id = ? AND token_hash = ?", id, t.TokenHash).
			Cols("revoked_unix", "revoked_by_id", "token_hash", "token_salt", "token_last_eight", "self_rotate").NoAutoTime().Update(tomb); err != nil {
			return err
		} else if cnt != 1 {
			return ErrAccessTokenNotExist{}
		}
		return recordAccessToken(ctx, "deleted", t, map[string]any{"before": accessTokenFields(t, repoIDs)})
	})
}

// RotateOwnedAccessToken gives the token with the ID of the owner opts names a new secret (in Token) and the expiry,
// keeping everything else; an expired token may be rotated. oldHash, when set, must still be the token's hash (a
// token rotating itself). rotatedByID is the user who rotated it, or the token's own identity.
func RotateOwnedAccessToken(ctx context.Context, opts FindOwnedAccessTokensOptions, id int64, oldHash string, expires timeutil.TimeStamp, rotatedByID int64) (*AccessToken, error) {
	// a new secret, as in NewAccessToken; a token rotating itself acts with its own credential
	if err := audit_model.CheckOwnAct(ctx); err != nil {
		return nil, err
	}
	t := &AccessToken{}
	return t, db.WithTx(ctx, func(ctx context.Context) error {
		if has, err := db.GetEngine(ctx).Where(opts.ToConds()).And("id = ?", id).Get(t); err != nil {
			return err
		} else if !has || oldHash != "" && t.TokenHash != oldHash {
			return ErrAccessTokenNotExist{}
		}
		before := t.TokenHash
		expiresBefore := t.ExpiresUnix
		generateAccessToken(t)
		t.ExpiresUnix = expires
		t.RotatedUnix = timeutil.TimeStampNow()
		t.RotatedByID = rotatedByID
		if cnt, err := db.GetEngine(ctx).Where(opts.ToConds()).And("id = ? AND token_hash = ?", id, before).
			Cols("token_salt", "token_hash", "token_last_eight", "expires_unix", "rotated_unix", "rotated_by_id").NoAutoTime().Update(t); err != nil {
			return err
		} else if cnt != 1 {
			return ErrAccessTokenNotExist{} // rotated or revoked meanwhile
		}
		return recordAccessToken(ctx, "rotated", t, map[string]any{
			"name": t.Name, "self": rotatedByID < 0,
			"before": map[string]any{"expires": int64(expiresBefore)}, "after": map[string]any{"expires": int64(t.ExpiresUnix)},
		})
	})
}

// GetOwnedAccessTokenByID returns the token of an organization, a project or a repository with the ID.
func GetOwnedAccessTokenByID(ctx context.Context, id int64) (*AccessToken, error) {
	t := &AccessToken{}
	has, err := db.GetEngine(ctx).Where("id = ? AND owner_type <> ?", id, AccessTokenOwnerUser).Get(t)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrAccessTokenNotExist{}
	}
	return t, nil
}

// DeleteOwnedAccessTokens deletes the tokens of the owner: with AccessTokenOwnerOrg the organization's and its
// projects', with AccessTokenOwnerProject one project's (groupID), with AccessTokenOwnerRepo one repository's.
func DeleteOwnedAccessTokens(ctx context.Context, ownerType AccessTokenOwnerType, ownerID, groupID int64) error {
	var cond builder.Cond
	switch ownerType {
	case AccessTokenOwnerOrg:
		cond = builder.In("owner_type", AccessTokenOwnerOrg, AccessTokenOwnerProject).And(builder.Eq{"owner_id": ownerID})
	case AccessTokenOwnerProject:
		cond = builder.Eq{"owner_type": AccessTokenOwnerProject, "owner_id": ownerID, "group_id": groupID}
	case AccessTokenOwnerRepo:
		cond = builder.Eq{"owner_type": AccessTokenOwnerRepo, "owner_id": ownerID}
	default:
		return fmt.Errorf("DeleteOwnedAccessTokens: invalid owner type %d", ownerType)
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.GetEngine(ctx).Where(builder.In("token_id", builder.Select("id").From("access_token").Where(cond))).Delete(&AccessTokenResourceRepo{}); err != nil {
			return err
		}
		_, err := db.GetEngine(ctx).Where(cond).Delete(&AccessToken{})
		return err
	})
}

// DropOwnedAccessTokensOfTransferredRepo deletes the repository's own tokens and the repository from the selections of
// organization tokens, for a repository leaving its owner: moving it back must not restore them.
func DropOwnedAccessTokensOfTransferredRepo(ctx context.Context, repoID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		ownedTokens := builder.Select("id").From("access_token").Where(builder.Neq{"owner_type": AccessTokenOwnerUser})
		if _, err := db.GetEngine(ctx).Where(builder.Eq{"repo_id": repoID}.And(builder.In("token_id", ownedTokens))).Delete(&AccessTokenResourceRepo{}); err != nil {
			return err
		}
		return DeleteOwnedAccessTokens(ctx, AccessTokenOwnerRepo, repoID, 0)
	})
}
