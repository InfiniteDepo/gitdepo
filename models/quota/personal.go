// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package quota

import (
	"context"
	"fmt"
	"strings"

	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"

	"github.com/dustin/go-humanize"
	"xorm.io/builder"
)

// PersonalRepoLimit is the size limit of a user's personal repositories.
type PersonalRepoLimit struct {
	Used, Limit int64 // bytes; Limit 0 means no limit applies
}

// Reached reports whether the user's personal repositories are locked for writes: usage at or over the limit.
func (l PersonalRepoLimit) Reached() bool {
	return l.Limit > 0 && l.Used >= l.Limit
}

// MessageFor is Message for the owner, and without the owner's numbers for anyone else.
func (l PersonalRepoLimit) MessageFor(doerID, ownerID int64) string {
	if doerID == ownerID {
		return l.Message()
	}
	return "The owner's personal repositories reached their size limit. The owner can delete content in the web UI to allow writes again."
}

// Message is the refusal shown when the limit is reached.
func (l PersonalRepoLimit) Message() string {
	return fmt.Sprintf("Personal repository size limit reached (%s of %s used). Delete content in the web UI to write again.",
		FormatSize(l.Used), FormatSize(l.Limit))
}

// FormatSize formats a size like the web UI does (Locale.TrSize in English): "1 MiB", "1.5 MiB", "512 B".
func FormatSize(n int64) string {
	number, unit, _ := strings.Cut(humanize.IBytes(uint64(max(n, 0))), " ")
	return strings.TrimSuffix(number, ".0") + " " + unit
}

// ErrPersonalRepoLimit refuses a new repository in a namespace whose size limit is reached.
type ErrPersonalRepoLimit struct {
	PersonalRepoLimit
	OwnerID int64 // whose repositories are locked; only they see the numbers (MessageFor)
}

func (e ErrPersonalRepoLimit) Error() string {
	return e.Message()
}

func (ErrPersonalRepoLimit) Unwrap() error {
	return util.ErrPermissionDenied
}

// EffectivePersonalRepoSizeLimit is the limit in bytes for u's personal repositories, 0 if none applies: never for
// organizations and usable site admins, else the user's override (-1 unlimited, >0 bytes) or the site limit.
// siteLimit is setting.PersonalReposState.EffectiveSizeLimit(); without it no limit applies to anyone.
func EffectivePersonalRepoSizeLimit(u *user_model.User, siteLimit int64) int64 {
	if siteLimit <= 0 || u.IsOrganization() || u.IsAdmin && u.IsActive && !u.ProhibitLogin && u.Type == user_model.UserTypeIndividual {
		return 0
	}
	switch {
	case u.PersonalRepoSizeLimit < 0:
		return 0
	case u.PersonalRepoSizeLimit > 0:
		return u.PersonalRepoSizeLimit
	}
	return siteLimit
}

// personalRepoUsageSQL is, per owner, the space all of its repositories use, those in the trash included: git
// data and wiki as last measured, and LFS objects as stored now (an LFS upload doesn't refresh the repository
// size). cond restricts the owners; it is the same for both parts, so its arguments are given twice.
func personalRepoUsageSQL(cond string) string {
	return "SELECT owner_id, SUM(used) AS used FROM (" +
		"SELECT owner_id, size - lfs_size + wiki_size AS used FROM repository WHERE " + cond +
		" UNION ALL SELECT repository.owner_id, lfs_meta_object.size FROM lfs_meta_object INNER JOIN repository ON repository.id = lfs_meta_object.repository_id WHERE " + cond +
		") personal_usage GROUP BY owner_id"
}

// GetPersonalRepoUsages returns, for the given owners, the space in bytes all of their repositories use, those in
// the trash included, in one query.
func GetPersonalRepoUsages(ctx context.Context, ownerIDs []int64) (map[int64]int64, error) {
	usages := make(map[int64]int64, len(ownerIDs))
	if len(ownerIDs) == 0 {
		return usages, nil
	}
	in, args := builder.In("owner_id", ownerIDs), []any{}
	cond, condArgs, err := builder.ToSQL(in)
	if err != nil {
		return nil, err
	}
	args = append(append(args, condArgs...), condArgs...)
	rows := make([]struct {
		OwnerID int64 `xorm:"owner_id"`
		Used    int64 `xorm:"used"`
	}, 0, len(ownerIDs))
	sql := personalRepoUsageSQL(cond)
	if err := db.GetEngine(ctx).SQL(sql, args...).Find(&rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		usages[r.OwnerID] = r.Used
	}
	return usages, nil
}

// GetPersonalRepoUsage returns the space in bytes all repositories of ownerID use, those in the trash included.
func GetPersonalRepoUsage(ctx context.Context, ownerID int64) (int64, error) {
	usages, err := GetPersonalRepoUsages(ctx, []int64{ownerID})
	return usages[ownerID], err
}

// GetPersonalRepoLimits returns the usage and limit of the personal repositories of each of users (a zero limit
// for organizations, admins and unlimited users), for lists.
func GetPersonalRepoLimits(ctx context.Context, users []*user_model.User) (map[int64]PersonalRepoLimit, error) {
	ids := make([]int64, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	usages, err := GetPersonalRepoUsages(ctx, ids)
	if err != nil {
		return nil, err
	}
	siteLimit := setting.Config().PersonalRepos.Value(ctx).EffectiveSizeLimit()
	limits := make(map[int64]PersonalRepoLimit, len(users))
	for _, u := range users {
		limits[u.ID] = PersonalRepoLimit{Used: usages[u.ID], Limit: EffectivePersonalRepoSizeLimit(u, siteLimit)}
	}
	return limits, nil
}

// PersonalRepoOverLimit is a user whose personal repositories are at or over their size limit.
type PersonalRepoOverLimit struct {
	ID    int64  `xorm:"id"`
	Name  string `xorm:"name"`
	Used  int64  `xorm:"used"`
	Limit int64  `xorm:"lim"`
}

// FindPersonalRepoOverLimit returns up to limit users, by name, whose personal repositories are locked by the size
// limit (usage at or over it), and how many there are. Organizations, usable admins and unlimited users are never
// listed; without a site limit nobody is.
func FindPersonalRepoOverLimit(ctx context.Context, limit int) ([]*PersonalRepoOverLimit, int64, error) {
	siteLimit := setting.Config().PersonalRepos.Value(ctx).EffectiveSizeLimit()
	if siteLimit <= 0 {
		return nil, 0, nil
	}
	from := " FROM `user` INNER JOIN (" + personalRepoUsageSQL("1=1") + ") u ON u.owner_id = `user`.id" +
		" WHERE `user`.type = ? AND `user`.personal_repo_size_limit >= 0 AND NOT (`user`.is_admin = ? AND `user`.is_active = ? AND `user`.prohibit_login = ?)" +
		" AND u.used >= CASE WHEN `user`.personal_repo_size_limit > 0 THEN `user`.personal_repo_size_limit ELSE ? END"
	args := []any{user_model.UserTypeIndividual, true, true, false, siteLimit}
	var total int64
	if _, err := db.GetEngine(ctx).SQL("SELECT COUNT(*)"+from, args...).Get(&total); err != nil || total == 0 {
		return nil, total, err
	}
	rows := make([]*PersonalRepoOverLimit, 0, min(int(total), limit))
	err := db.GetEngine(ctx).SQL("SELECT `user`.id, `user`.name, u.used, CASE WHEN `user`.personal_repo_size_limit > 0 THEN `user`.personal_repo_size_limit ELSE ? END AS lim"+
		from+" ORDER BY `user`.name LIMIT ?", append(append([]any{siteLimit}, args...), limit)...).Find(&rows)
	return rows, total, err
}

// GetPersonalRepoLimit returns the usage and limit of userID's personal repositories. With the site limit off it
// reads nothing but the cached setting.
func GetPersonalRepoLimit(ctx context.Context, userID int64) (PersonalRepoLimit, error) {
	siteLimit := setting.Config().PersonalRepos.Value(ctx).EffectiveSizeLimit()
	if siteLimit <= 0 {
		return PersonalRepoLimit{}, nil
	}
	// an owner in the trash still owns its repositories; no user row (pseudo users) means no personal namespace
	u, err := user_model.GetUserByIDIncludingTrashed(ctx, userID)
	if user_model.IsErrUserNotExist(err) {
		return PersonalRepoLimit{}, nil
	} else if err != nil {
		return PersonalRepoLimit{}, err
	}
	return personalRepoLimitOf(ctx, u, siteLimit)
}

// GetPersonalRepoLimitOf is GetPersonalRepoLimit for an owner that is already loaded.
func GetPersonalRepoLimitOf(ctx context.Context, u *user_model.User) (PersonalRepoLimit, error) {
	siteLimit := setting.Config().PersonalRepos.Value(ctx).EffectiveSizeLimit()
	if siteLimit <= 0 {
		return PersonalRepoLimit{}, nil
	}
	return personalRepoLimitOf(ctx, u, siteLimit)
}

func personalRepoLimitOf(ctx context.Context, u *user_model.User, siteLimit int64) (PersonalRepoLimit, error) {
	limit := PersonalRepoLimit{Limit: EffectivePersonalRepoSizeLimit(u, siteLimit)}
	if limit.Limit == 0 {
		return limit, nil
	}
	var err error
	limit.Used, err = GetPersonalRepoUsage(ctx, u.ID)
	return limit, err
}

// personalRepoLimitReached logs and reports a reached limit, for the refusals of EvaluateForUser.
func personalRepoLimitReached(ctx context.Context, userID int64) (bool, error) {
	l, err := GetPersonalRepoLimit(ctx, userID)
	if err != nil || !l.Reached() {
		return false, err
	}
	log.Warn("Personal repository size limit reached for user %d (%d of %d bytes): write refused", userID, l.Used, l.Limit)
	return true, nil
}
