// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package git

import (
	"context"
	"regexp"
	"slices"
	"strings"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	linearglob "forgejo.org/modules/glob"
	"forgejo.org/modules/timeutil"
)

// ProtectedTag struct
type ProtectedTag struct {
	ID               int64 `xorm:"pk autoincr"`
	RepoID           int64
	NamePattern      string
	RegexPattern     *regexp.Regexp `xorm:"-"`
	GlobPattern      *regexp.Regexp `xorm:"-"`
	AllowlistUserIDs []int64        `xorm:"JSON TEXT"`
	AllowlistTeamIDs []int64        `xorm:"JSON TEXT"`
	// public key IDs of the deploy keys allowed to control the tags
	AllowlistDeployKeyIDs []int64 `xorm:"JSON TEXT"`

	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func init() {
	db.RegisterModel(new(ProtectedTag))
}

// EnsureCompiledPattern ensures the glob pattern is compiled
func (pt *ProtectedTag) EnsureCompiledPattern() error {
	if pt.RegexPattern != nil || pt.GlobPattern != nil {
		return nil
	}

	var err error
	if len(pt.NamePattern) >= 2 && strings.HasPrefix(pt.NamePattern, "/") && strings.HasSuffix(pt.NamePattern, "/") {
		pt.RegexPattern, err = regexp.Compile(pt.NamePattern[1 : len(pt.NamePattern)-1])
	} else {
		pt.GlobPattern, err = linearglob.CompileExact(pt.NamePattern)
	}
	return err
}

func (pt *ProtectedTag) matchString(name string) bool {
	if pt.RegexPattern != nil {
		return pt.RegexPattern.MatchString(name)
	}
	return pt.GlobPattern.MatchString(name)
}

// InsertProtectedTag inserts a protected tag to database
func InsertProtectedTag(ctx context.Context, pt *ProtectedTag) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.GetEngine(ctx).Insert(pt); err != nil {
			return err
		}
		return recordProtectedTag(ctx, "repo.tag_protection.created", pt, pt.AuditFields())
	})
}

// UpdateProtectedTag updates the protected tag
func UpdateProtectedTag(ctx context.Context, pt *ProtectedTag) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		stored, err := GetProtectedTagByID(ctx, pt.ID)
		if err != nil {
			return err
		}
		if stored != nil {
			if changes := audit_model.Changes(stored.AuditFields(), pt.AuditFields()); changes != nil {
				if err := recordProtectedTag(ctx, "repo.tag_protection.updated", pt, changes); err != nil {
					return err
				}
			}
		}
		_, err = db.GetEngine(ctx).ID(pt.ID).AllCols().Update(pt)
		return err
	})
}

// DeleteProtectedTag deletes a protected tag by ID
func DeleteProtectedTag(ctx context.Context, pt *ProtectedTag) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := recordProtectedTag(ctx, "repo.tag_protection.deleted", pt, map[string]any{"name_pattern": pt.NamePattern}); err != nil {
			return err
		}
		_, err := db.GetEngine(ctx).ID(pt.ID).Delete(&ProtectedTag{})
		return err
	})
}

// IsUserAllowedModifyTag returns true if the user is allowed to modify the tag
func IsUserAllowedModifyTag(ctx context.Context, pt *ProtectedTag, userID int64) (bool, error) {
	if slices.Contains(pt.AllowlistUserIDs, userID) {
		return true, nil
	}

	if len(pt.AllowlistTeamIDs) == 0 {
		return false, nil
	}

	in, err := organization.IsUserInTeams(ctx, userID, pt.AllowlistTeamIDs)
	if err != nil {
		return false, err
	}
	return in, nil
}

// GetProtectedTags gets all protected tags of the repository
func GetProtectedTags(ctx context.Context, repoID int64) ([]*ProtectedTag, error) {
	tags := make([]*ProtectedTag, 0)
	return tags, db.GetEngine(ctx).Find(&tags, &ProtectedTag{RepoID: repoID})
}

// GetProtectedTagByID gets the protected tag with the specific id
func GetProtectedTagByID(ctx context.Context, id int64) (*ProtectedTag, error) {
	tag := new(ProtectedTag)
	has, err := db.GetEngine(ctx).ID(id).Get(tag)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return tag, nil
}

// GetProtectedTagByNamePattern gets protected tag by name_pattern
func GetProtectedTagByNamePattern(ctx context.Context, repoID int64, pattern string) (*ProtectedTag, error) {
	tag := &ProtectedTag{NamePattern: pattern, RepoID: repoID}
	has, err := db.GetEngine(ctx).Get(tag)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return tag, nil
}

// IsUserAllowedToControlTag checks if a user can control the specific tag.
// It returns true if the tag name is not protected or the user is allowed to control it.
func IsUserAllowedToControlTag(ctx context.Context, tags []*ProtectedTag, tagName string, userID int64) (bool, error) {
	isAllowed := true
	for _, tag := range tags {
		err := tag.EnsureCompiledPattern()
		if err != nil {
			return false, err
		}

		if !tag.matchString(tagName) {
			continue
		}

		isAllowed, err = IsUserAllowedModifyTag(ctx, tag, userID)
		if err != nil {
			return false, err
		}
		if isAllowed {
			break
		}
	}

	return isAllowed, nil
}

// IsDeployKeyAllowedToControlTag checks if the deploy key with the given public key ID can control the specific tag.
// It returns true if the tag name is not protected or the deploy key is allowed to control it.
// The caller must check that the deploy key has write access to the repository.
func IsDeployKeyAllowedToControlTag(tags []*ProtectedTag, tagName string, keyID int64) (bool, error) {
	isAllowed := true
	for _, tag := range tags {
		if err := tag.EnsureCompiledPattern(); err != nil {
			return false, err
		}

		if !tag.matchString(tagName) {
			continue
		}

		isAllowed = slices.Contains(tag.AllowlistDeployKeyIDs, keyID)
		if isAllowed {
			break
		}
	}

	return isAllowed, nil
}
