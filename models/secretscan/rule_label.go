// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"sync"

	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/translation"
)

// RuleLabel is how an alert's rule is shown.
type RuleLabel struct {
	Name     string // the built-in rule's name, or the pattern's; empty for a deleted pattern the viewer may not name
	Generic  bool   // one of the generic built-in rules
	Deleted  bool   // a custom pattern that is deleted, or has no row
	Disabled bool   // a custom pattern that is turned off
	Foreign  bool   // a pattern of an organization that doesn't own the alert's repository (any more)
}

// Text is the label as every page, mail and download shows it.
func (l RuleLabel) Text(locale translation.Locale) string {
	switch {
	case l.Foreign:
		return locale.TrString("secret_search.foreign_pattern")
	case l.Deleted && l.Name != "":
		return locale.TrString("secret_search.deleted_pattern") + " (" + l.Name + ")"
	case l.Deleted:
		return locale.TrString("secret_search.deleted_pattern")
	case l.Disabled:
		return l.Name + " (" + locale.TrString("secret_search.pattern_disabled") + ")"
	}
	return l.Name
}

var builtinRules = sync.OnceValue(func() map[string]secretdetection.Rule {
	rules := map[string]secretdetection.Rule{}
	for _, r := range secretdetection.BuiltinRules() {
		rules[r.ID] = r
	}
	return rules
})

// RuleLabels are the custom patterns of a set of rule IDs, read in one query; Label names a rule from them. It is the
// one place that decides what an alert's rule is called.
type RuleLabels struct {
	patterns map[int64]*CustomPattern
}

// LoadRuleLabels reads the custom patterns among ruleIDs (tombstones too) in one query.
func LoadRuleLabels(ctx context.Context, ruleIDs []string) (*RuleLabels, error) {
	var ids []int64
	for _, ruleID := range ruleIDs {
		if id, ok := ParseCustomRuleID(ruleID); ok {
			ids = append(ids, id)
		}
	}
	patterns, err := GetCustomPatternsByIDs(ctx, ids)
	return &RuleLabels{patterns}, err
}

// Label names ruleID on an alert of a repository of repoOwnerID. A built-in rule has its engine name (an unknown ID is
// shown as it is). A pattern of the site or of that owner has its name, also when it is turned off; one of another
// owner (the repository was transferred) is Foreign, without a name. A deleted pattern (or one without a row) has its
// name only where seeDeleted (nil: never) says the viewer may read the deleted names of the pattern's owner.
func (rl *RuleLabels) Label(ruleID string, repoOwnerID int64, seeDeleted func(ownerID int64) bool) RuleLabel {
	id, ok := ParseCustomRuleID(ruleID)
	if !ok {
		if r, ok := builtinRules()[ruleID]; ok {
			return RuleLabel{Name: r.Name, Generic: r.Type == "generic"}
		}
		return RuleLabel{Name: ruleID}
	}
	p := rl.patterns[id]
	switch {
	case p == nil:
		return RuleLabel{Deleted: true}
	case p.OwnerID != 0 && p.OwnerID != repoOwnerID:
		return RuleLabel{Foreign: true}
	case p.DeletedUnix != 0:
		l := RuleLabel{Deleted: true}
		if seeDeleted != nil && seeDeleted(p.OwnerID) {
			l.Name = p.Name
		}
		return l
	}
	return RuleLabel{Name: p.Name, Disabled: !p.Enabled}
}
