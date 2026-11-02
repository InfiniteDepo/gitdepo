// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package ipallowlist

import (
	"context"
	"errors"
	"slices"
	"time"
	"unicode/utf8"

	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/setting/config"
	"forgejo.org/modules/util"
)

// MaxItems is the most entries, exempt users and exempt tokens the list holds, each.
const MaxItems = 500

// ErrSetByConfig is returned when [ip_allowlist] ENABLED = false in app.ini turns the list off.
var ErrSetByConfig = errors.New("the IP allowlist is turned off in the configuration file")

// Set validates and stores the IP allowlist. A nil doer means the command line. Entries keep who added them and when,
// and the owners of exempt tokens are looked up.
func Set(ctx context.Context, doer *user_model.User, s setting.IPAllowlistState) error {
	old := setting.GetIPAllowlist(ctx)
	if old.FromConfig {
		return ErrSetByConfig
	}
	if len(s.Entries) > MaxItems || len(s.ExemptUserIDs) > MaxItems || len(s.ExemptTokens) > MaxItems {
		return util.NewInvalidArgumentErrorf("the IP allowlist can hold at most %d entries, users and tokens each", MaxItems)
	}
	// the slices may share the cached state's arrays
	s.Entries, s.ExemptTokens = slices.Clone(s.Entries), slices.Clone(s.ExemptTokens)
	var doerID int64
	if doer != nil {
		doerID = doer.ID
	}
	for i := range s.Entries {
		e := &s.Entries[i]
		if !e.CIDR.IsValid() {
			return util.NewInvalidArgumentErrorf("invalid CIDR")
		}
		if utf8.RuneCountInString(e.Description) > 255 {
			return util.NewInvalidArgumentErrorf("the description of %s must be at most 255 characters", e.CIDR)
		}
		e.CIDR = setting.NormalizeIPPrefix(e.CIDR)
		e.CreatedByID, e.CreatedUnix = doerID, time.Now().Unix()
		if j := slices.IndexFunc(old.Entries, func(o setting.IPAllowlistEntry) bool { return o.CIDR == e.CIDR }); j >= 0 {
			e.CreatedByID, e.CreatedUnix = old.Entries[j].CreatedByID, old.Entries[j].CreatedUnix
		}
	}
	s.ExemptUserIDs = slices.Compact(slices.Sorted(slices.Values(s.ExemptUserIDs)))
	users, err := user_model.GetUsersByIDs(ctx, s.ExemptUserIDs)
	if err != nil {
		return err
	}
	if len(users) != len(s.ExemptUserIDs) {
		return util.NewInvalidArgumentErrorf("an exempt user does not exist")
	}
	tokenIDs := make([]int64, 0, len(s.ExemptTokens))
	for _, t := range s.ExemptTokens {
		tokenIDs = append(tokenIDs, t.ID)
	}
	tokens, err := db.GetByIDs(ctx, "id", tokenIDs, &auth_model.AccessToken{})
	if err != nil {
		return err
	}
	for i := range s.ExemptTokens {
		t, ok := tokens[s.ExemptTokens[i].ID]
		if !ok {
			return util.NewInvalidArgumentErrorf("exempt token %d does not exist", s.ExemptTokens[i].ID)
		}
		// a token keeps the owner it was exempted for; only tokens new to the list take it from the database
		if j := slices.IndexFunc(old.ExemptTokens, func(o setting.IPAllowlistToken) bool { return o.ID == t.ID }); j >= 0 && old.ExemptTokens[j].UID != t.UID {
			return util.NewInvalidArgumentErrorf("token %d now belongs to another user; remove it from the exemptions", t.ID)
		}
		s.ExemptTokens[i].UID = t.UID
	}

	v, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := system_model.SetSettings(ctx, map[string]string{setting.Config().IPAllowlist.DynKey(): string(v)}); err != nil {
		return err
	}
	if g := config.GetDynGetter(); g != nil {
		g.InvalidateCache()
	}
	return nil
}
