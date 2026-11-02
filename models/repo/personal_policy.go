// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"

	"forgejo.org/models/db"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/setting"

	"xorm.io/builder"
)

// PersonalRepoViolator is an individual user whose repositories break the personal repository policy.
type PersonalRepoViolator struct {
	OwnerID   int64  `xorm:"owner_id"`
	OwnerName string `xorm:"owner_name"`
	NumRepos  int64  `xorm:"num_repos"`
}

// FindPersonalRepoViolators returns up to limit users, by name, whose repositories outside the trash break the
// policy mode (public ones for private_only, any for disabled), and how many such users there are. Usable site
// admins are exempt from the policy and never listed.
func FindPersonalRepoViolators(ctx context.Context, mode string, limit int) ([]*PersonalRepoViolator, int64, error) {
	if mode != setting.PersonalReposPrivateOnly && mode != setting.PersonalReposDisabled {
		return nil, 0, nil
	}
	cond := builder.NewCond().And(
		builder.Eq{"trashed_unix": 0},
		builder.In("owner_id", builder.Select("id").From("`user`").Where(builder.Eq{"type": user_model.UserTypeIndividual})),
		builder.NotIn("owner_id", builder.Select("id").From("`user`").Where(user_model.UsableAdminCond())),
	)
	if mode == setting.PersonalReposPrivateOnly {
		cond = cond.And(builder.Eq{"is_private": false})
	}
	var total int64
	if _, err := db.GetEngine(ctx).Table("repository").Where(cond).Select("COUNT(DISTINCT owner_id)").Get(&total); err != nil || total == 0 {
		return nil, total, err
	}
	rows := make([]*PersonalRepoViolator, 0, min(int(total), limit))
	err := db.GetEngine(ctx).Table("repository").Where(cond).Select("owner_id, owner_name, COUNT(*) AS num_repos").
		GroupBy("owner_id, owner_name").OrderBy("owner_name").Limit(limit).Find(&rows)
	return rows, total, err
}
