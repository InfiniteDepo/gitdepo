// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import "code.forgejo.org/xorm/xorm"

func init() {
	registerMigration(&Migration{
		Description: "add the merge base a review was made against",
		Upgrade:     addReviewMergeBase,
	})
}

type v18zzgReview struct {
	ID        int64  `xorm:"pk autoincr"`
	MergeBase string `xorm:"VARCHAR(64)"`
}

func (v18zzgReview) TableName() string {
	return "review"
}

func addReviewMergeBase(x *xorm.Engine) error {
	return x.Sync(new(v18zzgReview))
}
