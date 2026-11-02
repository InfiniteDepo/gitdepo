// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

// AnnouncementType is the severity of an announcement, which decides its colour and order
type AnnouncementType string

const (
	AnnouncementInfo     AnnouncementType = "info"
	AnnouncementWarning  AnnouncementType = "warning"
	AnnouncementCritical AnnouncementType = "critical"
)

// AnnouncementTypes lists the valid announcement types, most severe first
var AnnouncementTypes = []AnnouncementType{AnnouncementCritical, AnnouncementWarning, AnnouncementInfo}

// AnnouncementAudience decides who sees an announcement
type AnnouncementAudience string

const (
	AnnouncementAudienceEveryone AnnouncementAudience = "everyone"
	AnnouncementAudienceSignedIn AnnouncementAudience = "signed_in"
	AnnouncementAudienceAdmins   AnnouncementAudience = "admins"
)

// AnnouncementAudiences lists the valid audiences
var AnnouncementAudiences = []AnnouncementAudience{AnnouncementAudienceEveryone, AnnouncementAudienceSignedIn, AnnouncementAudienceAdmins}

// Announcement is a message site administrators show as a banner on every page
type Announcement struct {
	ID          int64                `xorm:"pk autoincr"`
	Message     string               `xorm:"TEXT NOT NULL"`
	Type        AnnouncementType     `xorm:"VARCHAR(16) NOT NULL"`
	Audience    AnnouncementAudience `xorm:"VARCHAR(16) NOT NULL"`
	Dismissible bool                 `xorm:"NOT NULL DEFAULT false"`
	// StartUnix and EndUnix bound the time the announcement is shown in; 0 means unbounded
	StartUnix   timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	EndUnix     timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	CreatedByID int64              `xorm:"NOT NULL DEFAULT 0"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

// AnnouncementDismissal records that a user closed an announcement. It only
// applies while the announcement's message still has the same ContentHash.
type AnnouncementDismissal struct {
	ID             int64  `xorm:"pk autoincr"`
	AnnouncementID int64  `xorm:"UNIQUE(s) INDEX NOT NULL"`
	UserID         int64  `xorm:"UNIQUE(s) INDEX NOT NULL"`
	ContentHash    string `xorm:"VARCHAR(64) NOT NULL"`
}

func init() {
	db.RegisterModel(new(Announcement))
	db.RegisterModel(new(AnnouncementDismissal))
}

// ErrAnnouncementNotExist represents an error for an announcement that does not exist
type ErrAnnouncementNotExist struct {
	ID int64
}

// IsErrAnnouncementNotExist checks if an error is a ErrAnnouncementNotExist
func IsErrAnnouncementNotExist(err error) bool {
	_, ok := err.(ErrAnnouncementNotExist)
	return ok
}

func (err ErrAnnouncementNotExist) Error() string {
	return fmt.Sprintf("announcement does not exist [id: %d]", err.ID)
}

func (err ErrAnnouncementNotExist) Unwrap() error {
	return util.ErrNotExist
}

// IsValid reports whether the type is a known announcement type
func (t AnnouncementType) IsValid() bool {
	return slices.Contains(AnnouncementTypes, t)
}

// IsValid reports whether the audience is a known audience
func (a AnnouncementAudience) IsValid() bool {
	return slices.Contains(AnnouncementAudiences, a)
}

// ContentHash identifies the message, so that a dismissal no longer applies once the message changes
func (a *Announcement) ContentHash() string {
	sum := sha256.Sum256([]byte(a.Message))
	return hex.EncodeToString(sum[:])
}

// IsActiveAt reports whether the announcement should be shown at the given time
func (a *Announcement) IsActiveAt(now timeutil.TimeStamp) bool {
	return (a.StartUnix == 0 || now >= a.StartUnix) && (a.EndUnix == 0 || now < a.EndUnix)
}

// IsVisibleTo reports whether a visitor with the given sign-in state and admin status is in the audience
func (a *Announcement) IsVisibleTo(isSigned, isAdmin bool) bool {
	switch a.Audience {
	case AnnouncementAudienceEveryone:
		return true
	case AnnouncementAudienceSignedIn:
		return isSigned
	case AnnouncementAudienceAdmins:
		return isSigned && isAdmin
	}
	return false
}

// CanBeDismissed reports whether users may close the announcement. Critical ones are never dismissible.
func (a *Announcement) CanBeDismissed() bool {
	return a.Dismissible && a.Type != AnnouncementCritical
}

// SortAnnouncements orders announcements by severity, most severe first, then newest first
func SortAnnouncements(list []*Announcement) {
	slices.SortStableFunc(list, func(a, b *Announcement) int {
		if c := slices.Index(AnnouncementTypes, a.Type) - slices.Index(AnnouncementTypes, b.Type); c != 0 {
			return c
		}
		return int(b.ID - a.ID)
	})
}

// GetAnnouncementByID returns the announcement with the given ID
func GetAnnouncementByID(ctx context.Context, id int64) (*Announcement, error) {
	a := new(Announcement)
	has, err := db.GetEngine(ctx).ID(id).Get(a)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrAnnouncementNotExist{ID: id}
	}
	return a, nil
}

// FindAnnouncements returns a page of announcements, newest first, and the total count.
// An empty ListOptions returns all of them.
func FindAnnouncements(ctx context.Context, opts db.ListOptions) ([]*Announcement, int64, error) {
	sess := db.GetEngine(ctx).OrderBy("id DESC")
	if opts.PageSize > 0 {
		sess = db.SetSessionPagination(sess, &opts)
	}
	list := make([]*Announcement, 0, opts.PageSize)
	count, err := sess.FindAndCount(&list)
	return list, count, err
}

// InsertAnnouncement creates an announcement
func InsertAnnouncement(ctx context.Context, a *Announcement) error {
	return db.Insert(ctx, a)
}

// UpdateAnnouncement saves all the fields of an announcement
func UpdateAnnouncement(ctx context.Context, a *Announcement) error {
	_, err := db.GetEngine(ctx).ID(a.ID).AllCols().Omit("created_unix", "created_by_id").Update(a)
	return err
}

// DeleteAnnouncement deletes an announcement and its dismissals
func DeleteAnnouncement(ctx context.Context, id int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.GetEngine(ctx).Where("announcement_id = ?", id).Delete(new(AnnouncementDismissal)); err != nil {
			return err
		}
		_, err := db.GetEngine(ctx).ID(id).Delete(new(Announcement))
		return err
	})
}

// DismissAnnouncement records that the user closed the announcement in its current version
func DismissAnnouncement(ctx context.Context, a *Announcement, userID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		d := &AnnouncementDismissal{AnnouncementID: a.ID, UserID: userID, ContentHash: a.ContentHash()}
		has, err := db.GetEngine(ctx).Where("announcement_id = ? AND user_id = ?", a.ID, userID).Exist(new(AnnouncementDismissal))
		if err != nil {
			return err
		}
		if has {
			_, err = db.GetEngine(ctx).Where("announcement_id = ? AND user_id = ?", a.ID, userID).Cols("content_hash").Update(d)
			return err
		}
		return db.Insert(ctx, d)
	})
}

// FilterDismissedAnnouncements removes the announcements the user dismissed in their current version
func FilterDismissedAnnouncements(ctx context.Context, list []*Announcement, userID int64) ([]*Announcement, error) {
	ids := make([]int64, 0, len(list))
	for _, a := range list {
		if a.CanBeDismissed() {
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		return list, nil
	}

	dismissals := make([]*AnnouncementDismissal, 0, len(ids))
	if err := db.GetEngine(ctx).Where(builder.Eq{"user_id": userID}.And(builder.In("announcement_id", ids))).Find(&dismissals); err != nil {
		return nil, err
	}
	dismissed := make(map[int64]string, len(dismissals))
	for _, d := range dismissals {
		dismissed[d.AnnouncementID] = d.ContentHash
	}

	return slices.DeleteFunc(slices.Clone(list), func(a *Announcement) bool {
		hash, ok := dismissed[a.ID]
		return ok && a.CanBeDismissed() && hash == a.ContentHash()
	}), nil
}
