// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/modules/json"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// CustomRulePrefix starts the rule ID of a custom pattern: "custom-<id>", stored in Alert.RuleID like a built-in ID.
const CustomRulePrefix = "custom-"

// CustomPattern is a rule an organization (OwnerID is its ID) or the site (OwnerID 0) wrote. Rows are never removed:
// a delete sets DeletedUnix, so an alert of the rule keeps a label. The name is unique among an owner's live rows
// (a tombstone has its own time). The pattern is a rule, not a secret.
type CustomPattern struct {
	ID          int64              `xorm:"pk autoincr"`
	OwnerID     int64              `xorm:"UNIQUE(owner_name_deleted) NOT NULL DEFAULT 0"`
	Name        string             `xorm:"VARCHAR(64) UNIQUE(owner_name_deleted) NOT NULL"`
	Pattern     string             `xorm:"TEXT NOT NULL"`
	Keywords    string             `xorm:"TEXT NOT NULL"` // a JSON list
	Enabled     bool               `xorm:"NOT NULL DEFAULT true"`
	DeletedUnix timeutil.TimeStamp `xorm:"UNIQUE(owner_name_deleted) NOT NULL DEFAULT 0"`
	CreatedByID int64              `xorm:"NOT NULL DEFAULT 0"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*CustomPattern) TableName() string { return "secret_custom_pattern" }

func init() {
	db.RegisterModel(new(CustomPattern))
}

// RuleID is the rule ID of the pattern's alerts.
func (p *CustomPattern) RuleID() string { return CustomRuleID(p.ID) }

// CustomRuleID is the rule ID of the custom pattern with this ID.
func CustomRuleID(id int64) string { return CustomRulePrefix + strconv.FormatInt(id, 10) }

// ParseCustomRuleID returns the pattern ID of a custom rule ID.
func ParseCustomRuleID(ruleID string) (int64, bool) {
	rest, ok := strings.CutPrefix(ruleID, CustomRulePrefix)
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(rest, 10, 64)
	return id, err == nil && id > 0
}

// KeywordList is the keywords of the pattern; a stored value that can't be read gives none (the rule is then refused).
func (p *CustomPattern) KeywordList() []string {
	var k []string
	_ = json.Unmarshal([]byte(p.Keywords), &k)
	return k
}

// EncodeKeywords is the stored form of a keyword list.
func EncodeKeywords(keywords []string) string {
	b, _ := json.Marshal(keywords)
	return string(b)
}

// GetCustomPattern returns a pattern of the owner, deleted or not (not found: nil).
func GetCustomPattern(ctx context.Context, ownerID, id int64) (*CustomPattern, error) {
	p := &CustomPattern{}
	has, err := db.GetEngine(ctx).Where("owner_id = ? AND id = ?", ownerID, id).Get(p)
	if err != nil || !has {
		return nil, err
	}
	return p, nil
}

// FindCustomPatterns lists the live patterns of the owner, oldest first.
func FindCustomPatterns(ctx context.Context, ownerID int64) ([]*CustomPattern, error) {
	var out []*CustomPattern
	return out, db.GetEngine(ctx).Where("owner_id = ? AND deleted_unix = 0", ownerID).OrderBy("id").Find(&out)
}

// FindActiveCustomPatterns lists the enabled live patterns of the owners, the site's (owner 0) first, then by ID:
// the order in which the cap keeps them. It reads at most twice the cap, so rows the engine refuses can be skipped
// without loading every row a race of saves left.
func FindActiveCustomPatterns(ctx context.Context, ownerIDs ...int64) ([]*CustomPattern, error) {
	var out []*CustomPattern
	return out, db.GetEngine(ctx).Where(builder.In("owner_id", ownerIDs).And(builder.Eq{"enabled": true, "deleted_unix": 0})).
		OrderBy("owner_id, id").Limit(2 * secretdetection.MaxCustomRules).Find(&out)
}

// CountActiveCustomPatterns counts the enabled live patterns of the owners.
func CountActiveCustomPatterns(ctx context.Context, ownerIDs ...int64) (int64, error) {
	return db.GetEngine(ctx).Where(builder.In("owner_id", ownerIDs).And(builder.Eq{"enabled": true, "deleted_unix": 0})).Count(new(CustomPattern))
}

// GetCustomPatternsByIDs returns the patterns with these IDs, tombstones too, in one query.
func GetCustomPatternsByIDs(ctx context.Context, ids []int64) (map[int64]*CustomPattern, error) {
	out := map[int64]*CustomPattern{}
	if len(ids) == 0 {
		return out, nil
	}
	var list []*CustomPattern
	if err := db.GetEngine(ctx).In("id", ids).Find(&list); err != nil {
		return nil, err
	}
	for _, p := range list {
		out[p.ID] = p
	}
	return out, nil
}

// FindLiveCustomPatterns lists at most limit patterns of the owners that match ownerCond (on owner_id) and are not
// deleted, on or off, the site's (owner 0) first.
func FindLiveCustomPatterns(ctx context.Context, ownerCond builder.Cond, limit int) ([]*CustomPattern, error) {
	var out []*CustomPattern
	return out, db.GetEngine(ctx).Where(ownerCond.And(builder.Eq{"deleted_unix": 0})).OrderBy("owner_id, id").Limit(limit).Find(&out)
}

// FreeTombstoneTime is the deleted_unix a pattern of the owner and name gets when it is deleted: now, or the next
// second no tombstone of that name has (the unique key has one per second).
func FreeTombstoneTime(ctx context.Context, ownerID int64, name string) (timeutil.TimeStamp, error) {
	at := timeutil.TimeStampNow()
	for {
		taken, err := db.GetEngine(ctx).Where("owner_id = ? AND name = ? AND deleted_unix = ?", ownerID, name, at).Exist(new(CustomPattern))
		if err != nil || !taken {
			return at, err
		}
		at++
	}
}

// TombstoneOwnerPatterns deletes the patterns of an organization that is purged, as tombstones (off, the pattern
// text cleared): an alert in a repository that moved out of the organization earlier keeps its "previous owner"
// label, which needs the row.
func TombstoneOwnerPatterns(ctx context.Context, ownerID int64) error {
	var live []*CustomPattern
	if err := db.GetEngine(ctx).Where("owner_id = ? AND deleted_unix = 0", ownerID).Find(&live); err != nil {
		return err
	}
	for _, p := range live {
		at, err := FreeTombstoneTime(ctx, ownerID, p.Name)
		if err != nil {
			return err
		}
		if _, err := db.GetEngine(ctx).ID(p.ID).Cols("enabled", "deleted_unix").Update(&CustomPattern{DeletedUnix: at}); err != nil {
			return err
		}
	}
	_, err := db.GetEngine(ctx).Where("owner_id = ?", ownerID).Cols("pattern").Update(&CustomPattern{})
	return err
}

// CountLiveCustomPatterns counts the patterns of the owner that are not deleted, on or off.
func CountLiveCustomPatterns(ctx context.Context, ownerID int64) (int64, error) {
	return db.GetEngine(ctx).Where(builder.Eq{"owner_id": ownerID, "deleted_unix": 0}).Count(new(CustomPattern))
}

// CountOpenAlertsByRule counts the open alerts of the rules in the repositories that match repoCond, in one query.
func CountOpenAlertsByRule(ctx context.Context, repoCond builder.Cond, ruleIDs []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(ruleIDs) == 0 {
		return out, nil
	}
	opts := &AlertSearchOptions{RepoCond: repoCond, State: StateOpen, SecretTypes: ruleIDs}
	var rows []struct {
		RuleID string
		N      int64
	}
	if err := db.GetEngine(ctx).Table("secret_scanning_alert").Select("rule_id, COUNT(*) AS n").Where(opts.ToConds()).GroupBy("rule_id").Find(&rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.RuleID] = r.N
	}
	return out, nil
}
