// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unittest"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	"forgejo.org/modules/translation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acme is a secret of the test rule, built from parts so that no source line holds one.
func acme(seed string) string { return "acme-" + "key-" + token(seed)[4:24] }

func acmeInput(name string) PatternInput {
	return PatternInput{Name: name, Pattern: `acme-key-[a-z0-9]{20}`, Keywords: []string{"acme-key"}, Sample: "K=" + acme("sample")}
}

func patternCtx(t *testing.T) (context.Context, *user_model.User) {
	t.Helper()
	unittest.PrepareTestEnv(t)
	return audit_model.WithSystem(t.Context(), "test"), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
}

func org3(t *testing.T) *user_model.User {
	t.Helper()
	return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
}

func auditCount(t *testing.T, action string) int64 {
	t.Helper()
	n, err := db.GetEngine(t.Context()).Table("audit_event").Where("action = ?", action).Count()
	require.NoError(t, err)
	return n
}

func TestValidatePattern(t *testing.T) {
	require.NoError(t, ValidatePattern(acmeInput("ok")))

	in := acmeInput("ok")
	in.Name = "  padded  "
	require.NoError(t, ValidatePattern(in), "the name is stripped")

	for name, mod := range map[string]func(*PatternInput){
		"empty name":        func(in *PatternInput) { in.Name = "  " },
		"long name":         func(in *PatternInput) { in.Name = strings.Repeat("n", MaxPatternNameLen+1) },
		"control in name":   func(in *PatternInput) { in.Name = "a\x1b[31mb" },
		"no keyword":        func(in *PatternInput) { in.Keywords = nil },
		"short keyword":     func(in *PatternInput) { in.Keywords = []string{"ac"} },
		"keyword not found": func(in *PatternInput) { in.Keywords = []string{"zzz-key"} },
		"six keywords":      func(in *PatternInput) { in.Keywords = []string{"acme-key", "acme", "cme-", "me-k", "e-ke", "-key"} },
		"nothing found":     func(in *PatternInput) { in.Sample = "nothing here" },
		"nested repeat":     func(in *PatternInput) { in.Pattern = `(acme-key-[a-z0-9]+)+` },
		"unbounded repeat":  func(in *PatternInput) { in.Pattern = `acme-key-[a-z0-9]+` },
		"matches ordinary": func(in *PatternInput) {
			in.Pattern = `[a-z]{8,12}`
			in.Keywords = []string{"acme-key"}
			in.Sample = "acme-keyxx"
		},
		"bad syntax":           func(in *PatternInput) { in.Pattern = `acme-key-(` },
		"NUL in name":          func(in *PatternInput) { in.Name = "a\x00b" },
		"bidi in name":         func(in *PatternInput) { in.Name = "a\u202eb" },
		"zero-width in name":   func(in *PatternInput) { in.Name = "a\u200bb" },
		"isolate in name":      func(in *PatternInput) { in.Name = "a\u2066b" },
		"BOM in name":          func(in *PatternInput) { in.Name = "a\ufeffb" },
		"not UTF-8 in name":    func(in *PatternInput) { in.Name = "a\xffb" },
		"NUL in pattern":       func(in *PatternInput) { in.Pattern = "acme-key-[a-z0-9]{20}\x00?" },
		"not UTF-8 in pattern": func(in *PatternInput) { in.Pattern = "acme-key-[a-z0-9]{20}(?:\xff)?" },
		"NUL in keyword":       func(in *PatternInput) { in.Keywords = []string{"acme-key", "acm\x00"} },
		"not UTF-8 in keyword": func(in *PatternInput) { in.Keywords = []string{"acme-key", "acm\xff"} },
		"common keyword":       func(in *PatternInput) { in.Keywords = []string{"acme-key", "the"} },
		"literal secret":       func(in *PatternInput) { in.Pattern = `acme-key-[a-z0-9]{20}|` + token("leak") },
	} {
		t.Run(name, func(t *testing.T) {
			in := acmeInput("x")
			mod(&in)
			require.Error(t, ValidatePattern(in))
		})
	}
	// a keyword given twice (other case) is one
	in = acmeInput("dup")
	in.Keywords = []string{"acme-key", "ACME-KEY"}
	require.NoError(t, ValidatePattern(in))
}

func TestPatternLifecycleAndAudit(t *testing.T) {
	ctx, admin := patternCtx(t)
	org := org3(t)

	site, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("site rule"))
	require.NoError(t, err)
	assert.Zero(t, site.OwnerID)
	assert.True(t, site.Enabled)
	assert.Equal(t, fmt.Sprintf("custom-%d", site.ID), site.RuleID())
	assert.Equal(t, []string{"acme-key"}, site.KeywordList())
	assert.EqualValues(t, 1, auditCount(t, "admin.secret_pattern.created"))

	mine, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("site rule"))
	require.NoError(t, err, "the same name of another owner")
	assert.Equal(t, org.ID, mine.OwnerID)
	assert.EqualValues(t, 1, auditCount(t, "org.secret_pattern.created"))

	_, err = CreatePattern(ctx, admin, SitePatterns, acmeInput("site rule"))
	require.ErrorIs(t, err, ErrPatternNameTaken)
	noKeyword := acmeInput("bad")
	noKeyword.Keywords = nil
	_, err = CreatePattern(ctx, admin, SitePatterns, noKeyword)
	require.ErrorIs(t, err, secretdetection.ErrKeywordMissing)
	n, err := db.GetEngine(ctx).Count(new(secretscan_model.CustomPattern))
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "a refused save stores nothing")

	// the audit entry has a hash of the rule (the log can be shipped elsewhere), never its text or the sample
	var e audit_model.Entry
	has, err := db.GetEngine(ctx).Where("action = ?", "admin.secret_pattern.created").Get(&e)
	require.NoError(t, err)
	require.True(t, has)
	assert.Contains(t, e.Data, `"pattern_sha256":"`+base.EncodeSha256(site.Pattern)+`"`)
	assert.NotContains(t, e.Data, "acme-key-[a-z0-9]")
	assert.NotContains(t, e.Data, acme("sample"))
	assert.Equal(t, "secret_pattern", e.TargetType)
	assert.Equal(t, site.ID, e.TargetID)
	assert.Zero(t, e.OwnerID)

	// update: another owner's pattern is not found, an unchanged save records nothing
	_, err = UpdatePattern(ctx, OrgPatterns(org), site.ID, acmeInput("x"))
	require.ErrorIs(t, err, ErrPatternNotFound)
	_, err = UpdatePattern(ctx, SitePatterns, site.ID, acmeInput("site rule"))
	require.NoError(t, err)
	assert.EqualValues(t, 0, auditCount(t, "admin.secret_pattern.updated"))
	_, err = CreatePattern(ctx, admin, SitePatterns, acmeInput("other"))
	require.NoError(t, err)
	_, err = UpdatePattern(ctx, SitePatterns, site.ID, acmeInput("other"))
	require.ErrorIs(t, err, ErrPatternNameTaken)
	renamed := acmeInput("renamed")
	renamed.Pattern = `acme-key-[a-z0-9]{20}|acme-key-[A-Z0-9]{20}`
	updated, err := UpdatePattern(ctx, SitePatterns, site.ID, renamed)
	require.NoError(t, err)
	assert.Equal(t, "renamed", updated.Name)
	assert.EqualValues(t, 1, auditCount(t, "admin.secret_pattern.updated"))
	var upd audit_model.Entry
	has, err = db.GetEngine(ctx).Where("action = ?", "admin.secret_pattern.updated").Get(&upd)
	require.NoError(t, err)
	require.True(t, has)
	assert.Contains(t, upd.Data, `"previous_name":"site rule"`, "a rename records the name it replaces")
	assert.Contains(t, upd.Data, `"previous_pattern_sha256":"`+base.EncodeSha256(site.Pattern)+`"`)
	assert.NotContains(t, upd.Data, "acme-key-[")
	got, err := secretscan_model.GetCustomPattern(ctx, 0, site.ID)
	require.NoError(t, err)
	assert.Equal(t, renamed.Pattern, got.Pattern)

	// disable and enable record once each; repeating them does nothing
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, site.ID, false))
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, site.ID, false))
	assert.EqualValues(t, 1, auditCount(t, "admin.secret_pattern.disabled"))
	require.ErrorIs(t, SetPatternEnabled(ctx, OrgPatterns(org), site.ID, true), ErrPatternNotFound)
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, site.ID, true))
	assert.EqualValues(t, 1, auditCount(t, "admin.secret_pattern.enabled"))

	// delete keeps the row as a tombstone and frees the name, also twice within a second
	for range 2 {
		p, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("again"))
		require.NoError(t, err)
		require.NoError(t, DeletePattern(ctx, OrgPatterns(org), p.ID))
		require.ErrorIs(t, DeletePattern(ctx, OrgPatterns(org), p.ID), ErrPatternNotFound)
		_, err = UpdatePattern(ctx, OrgPatterns(org), p.ID, acmeInput("again"))
		require.ErrorIs(t, err, ErrPatternNotFound)
		require.ErrorIs(t, SetPatternEnabled(ctx, OrgPatterns(org), p.ID, true), ErrPatternNotFound)
		tomb, err := secretscan_model.GetCustomPattern(ctx, org.ID, p.ID)
		require.NoError(t, err)
		require.NotNil(t, tomb)
		assert.NotZero(t, tomb.DeletedUnix)
		assert.Equal(t, "again", tomb.Name)
	}
	assert.EqualValues(t, 2, auditCount(t, "org.secret_pattern.deleted"))
	live, err := secretscan_model.FindCustomPatterns(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, live, 1)
	assert.Equal(t, mine.ID, live[0].ID)
}

func TestPatternCap(t *testing.T) {
	ctx, admin := patternCtx(t)
	org := org3(t)
	var ids []int64
	for i := range secretdetection.MaxCustomRules {
		p, err := CreatePattern(ctx, admin, SitePatterns, acmeInput(fmt.Sprintf("site %d", i)))
		require.NoError(t, err)
		ids = append(ids, p.ID)
	}
	_, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("one more"))
	require.ErrorIs(t, err, ErrPatternLimit)
	_, err = CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("org rule"))
	require.ErrorIs(t, err, ErrPatternLimit, "the site's patterns use the organization's room")

	// a disabled or deleted pattern gives its room back
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, ids[0], false))
	require.NoError(t, DeletePattern(ctx, SitePatterns, ids[1]))
	mine, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("org rule"))
	require.NoError(t, err)
	_, err = CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("org rule 2"))
	require.NoError(t, err)
	_, err = CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("org rule 3"))
	require.ErrorIs(t, err, ErrPatternLimit)
	require.NoError(t, SetPatternEnabled(ctx, OrgPatterns(org), mine.ID, false))
	_, err = CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("org rule 3"))
	require.NoError(t, err)
	require.ErrorIs(t, SetPatternEnabled(ctx, OrgPatterns(org), mine.ID, true), ErrPatternLimit, "turning one on counts again")
	// a site pattern is limited by the site's own count: the organization's last patterns give way at load
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, ids[0], true))

	// rows over the cap (a race of two saves) don't break a scan: the site's come first
	for i := range 5 {
		_, err := db.GetEngine(ctx).Insert(&secretscan_model.CustomPattern{
			OwnerID: org.ID, Name: fmt.Sprintf("raced %d", i), Pattern: `acme-key-[a-z0-9]{20}`,
			Keywords: secretscan_model.EncodeKeywords([]string{"acme-key"}), Enabled: true,
		})
		require.NoError(t, err)
	}
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	rules, err := customRules(ctx, repo)
	require.NoError(t, err)
	assert.Len(t, rules, secretdetection.MaxCustomRules)
	site, err := secretscan_model.FindActiveCustomPatterns(ctx, 0)
	require.NoError(t, err)
	for i, p := range site {
		assert.Equal(t, p.RuleID(), rules[i].ID, "the site's patterns come first")
	}
}

func TestCustomRulesLoading(t *testing.T) {
	ctx, admin := patternCtx(t)
	org := org3(t)
	site, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("site"))
	require.NoError(t, err)
	mine, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("mine"))
	require.NoError(t, err)
	off, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("off"))
	require.NoError(t, err)
	require.NoError(t, SetPatternEnabled(ctx, OrgPatterns(org), off.ID, false))
	gone, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("gone"))
	require.NoError(t, err)
	require.NoError(t, DeletePattern(ctx, OrgPatterns(org), gone.ID))
	// another organization's pattern, and a stored rule the engine refuses
	_, err = CreatePattern(ctx, admin, OrgPatterns(unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 6})), acmeInput("other org"))
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Insert(&secretscan_model.CustomPattern{
		OwnerID: org.ID, Name: "refused", Pattern: `(a+)+acme-key-[a-z0-9]{20}`, Keywords: secretscan_model.EncodeKeywords([]string{"acme-key"}), Enabled: true,
	})
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Insert(&secretscan_model.CustomPattern{
		OwnerID: org.ID, Name: "unreadable", Pattern: `acme-key-[a-z0-9]{20}`, Keywords: "not json", Enabled: true,
	})
	require.NoError(t, err)

	ids := func(repoID int64) []string {
		rules, err := customRules(ctx, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID}))
		require.NoError(t, err)
		var out []string
		for _, r := range rules {
			out = append(out, r.ID)
		}
		return out
	}
	assert.Equal(t, []string{site.RuleID(), mine.RuleID()}, ids(3), "the site's and the organization's enabled ones, nothing refused")
	assert.Equal(t, []string{site.RuleID()}, ids(1), "a repository of a user gets the site's only")
}

func TestScanWithCustomPattern(t *testing.T) {
	repo := enable(t) // user2/repo1
	ctx := audit_model.WithSystem(t.Context(), "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	w := newWork(t, repo)
	secret := acme("scan")

	require.NoError(t, Scan(t.Context(), repo.ID))
	p, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("acme key"))
	require.NoError(t, err)

	// a pattern added later applies to what is pushed from then on, not to the history
	w.commit(map[string]string{"old.env": "K=" + secret + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	require.Len(t, alertsOf(t, repo.ID), 1)
	a := alertsOf(t, repo.ID)[0]
	assert.Equal(t, p.RuleID(), a.RuleID)
	assert.Equal(t, "custom", a.SecretType)
	assert.Equal(t, secretdetection.Fingerprint([]byte(secret)), a.Fingerprint)
	assert.Equal(t, 1, a.LocationCount)

	// the value is stored nowhere
	for _, tbl := range []string{"secret_scanning_alert", "secret_scanning_location", "secret_custom_pattern", "audit_event"} {
		rows, err := db.GetEngine(ctx).SQL("SELECT * FROM " + tbl).QueryString()
		require.NoError(t, err)
		for _, row := range rows {
			for _, v := range row {
				assert.NotContains(t, v, secret, tbl)
			}
		}
	}

	// disabled: a new secret is not found, the alert stays open
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, p.ID, false))
	w.commit(map[string]string{"new.env": "K=" + acme("disabled") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Len(t, alertsOf(t, repo.ID), 1)
	assert.Equal(t, secretscan_model.StateOpen, alertsOf(t, repo.ID)[0].State)

	// on again, then deleted: nothing more is found, the alert stays with its label
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, p.ID, true))
	w.commit(map[string]string{"again.env": "K=" + acme("on again") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Len(t, alertsOf(t, repo.ID), 2)
	require.NoError(t, DeletePattern(ctx, SitePatterns, p.ID))
	w.commit(map[string]string{"deleted.env": "K=" + acme("deleted") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.Len(t, alertsOf(t, repo.ID), 2)
}

func TestScanOrgPatternOnlyInItsOrg(t *testing.T) {
	enable(t)
	ctx := audit_model.WithSystem(t.Context(), "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := org3(t)
	p, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("org only"))
	require.NoError(t, err)

	_, err = db.Exec(ctx, "UPDATE repository SET status = ? WHERE id = 3", repo_model.RepositoryReady) // a fixture migration
	require.NoError(t, err)
	orgRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	userRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	for _, repo := range []*repo_model.Repository{orgRepo, userRepo} {
		w := newWork(t, repo)
		require.NoError(t, Scan(t.Context(), repo.ID))
		w.commit(map[string]string{"k.env": "K=" + acme("org") + "\n"})
		w.pushDefault()
		require.NoError(t, Scan(t.Context(), repo.ID))
	}
	require.Len(t, alertsOf(t, orgRepo.ID), 1)
	assert.Equal(t, p.RuleID(), alertsOf(t, orgRepo.ID)[0].RuleID)
	assert.Empty(t, alertsOf(t, userRepo.ID), "an organization's pattern is not applied to other owners' repositories")

	// the site's pattern runs in the organization's repositories, and the organization can't turn it off
	_, err = CreatePattern(ctx, admin, SitePatterns, PatternInput{Name: "site acme", Pattern: `site-key-[a-z0-9]{20}`, Keywords: []string{"site-key"}, Sample: "K=site-key-" + token("s")[4:24]})
	require.NoError(t, err)
	w := newWork(t, orgRepo)
	w.commit(map[string]string{"s.env": "K=site-key-" + token("site found")[4:24] + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), orgRepo.ID))
	assert.Len(t, alertsOf(t, orgRepo.ID), 2)
}

func TestRuleLabels(t *testing.T) {
	ctx, admin := patternCtx(t)
	org := org3(t)
	live, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("live"))
	require.NoError(t, err)
	off, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("off"))
	require.NoError(t, err)
	require.NoError(t, SetPatternEnabled(ctx, SitePatterns, off.ID, false))
	orgGone, err := CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("org gone"))
	require.NoError(t, err)
	require.NoError(t, DeletePattern(ctx, OrgPatterns(org), orgGone.ID))
	siteGone, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("site gone"))
	require.NoError(t, err)
	require.NoError(t, DeletePattern(ctx, SitePatterns, siteGone.ID))

	ruleIDs := []string{"github-token", live.RuleID(), off.RuleID(), orgGone.RuleID(), siteGone.RuleID(), "custom-99999", "custom-x", "removed-builtin"}
	labels, err := secretscan_model.LoadRuleLabels(ctx, ruleIDs)
	require.NoError(t, err)
	label := func(ruleID string) secretscan_model.RuleLabel { return labels.Label(ruleID, org.ID, nil) }
	assert.False(t, label("github-token").Deleted)
	assert.NotEmpty(t, label("github-token").Name)
	assert.Equal(t, secretscan_model.RuleLabel{Name: "live"}, label(live.RuleID()))
	assert.Equal(t, secretscan_model.RuleLabel{Name: "off", Disabled: true}, label(off.RuleID()))
	assert.Equal(t, secretscan_model.RuleLabel{Deleted: true}, label(orgGone.RuleID()), "a deleted pattern's name is for its owners")
	assert.Equal(t, secretscan_model.RuleLabel{Deleted: true}, label(siteGone.RuleID()))
	assert.Equal(t, secretscan_model.RuleLabel{Deleted: true}, label("custom-99999"), "a row that is gone is a deleted pattern")
	assert.Equal(t, "custom-x", label("custom-x").Name, "not a custom ID: shown as it is")
	assert.Equal(t, "removed-builtin", label("removed-builtin").Name)

	ownOrg := func(owner int64) bool { return owner == org.ID }
	assert.Equal(t, secretscan_model.RuleLabel{Name: "org gone", Deleted: true}, labels.Label(orgGone.RuleID(), org.ID, ownOrg))
	assert.Equal(t, secretscan_model.RuleLabel{Deleted: true}, labels.Label(siteGone.RuleID(), org.ID, ownOrg))

	// in a repository of another owner (transferred away) the organization's patterns have no name, the site's keep it
	for _, l := range []secretscan_model.RuleLabel{labels.Label(live.RuleID(), 2, nil), labels.Label(orgGone.RuleID(), 2, ownOrg)} {
		assert.Equal(t, secretscan_model.RuleLabel{Foreign: true}, l)
	}
	assert.Equal(t, secretscan_model.RuleLabel{Name: "off", Disabled: true}, labels.Label(off.RuleID(), 2, nil))

	// one text for every place
	translation.InitLocales(t.Context())
	locale := translation.NewLocale("en-US")
	for want, l := range map[string]secretscan_model.RuleLabel{
		"live": label(live.RuleID()), "off (disabled)": label(off.RuleID()), "Deleted pattern": label(orgGone.RuleID()),
		"Deleted pattern (org gone)": labels.Label(orgGone.RuleID(), org.ID, ownOrg), "Pattern of a previous owner": labels.Label(live.RuleID(), 2, nil),
	} {
		assert.Equal(t, want, l.Text(locale))
	}

	// which scope may read which tombstone
	assert.True(t, Scope{}.seeDeletedPattern(0), "the instance list: the site's")
	assert.False(t, Scope{}.seeDeletedPattern(org.ID))
	orgScope := Scope{Org: organizationOf(t, org.ID)}
	assert.True(t, orgScope.seeDeletedPattern(org.ID))
	assert.False(t, orgScope.seeDeletedPattern(0), "an organization's list never names a site pattern")
	assert.False(t, orgScope.seeDeletedPattern(6))
	orgScope.Narrow = true
	assert.False(t, orgScope.seeDeletedPattern(org.ID), "a member narrowed to their repositories")
}

func organizationOf(t *testing.T, id int64) *organization.Organization {
	t.Helper()
	org, err := organization.GetOrgByID(t.Context(), id)
	require.NoError(t, err)
	return org
}

// Each change records its entry at the level of the owner: every key is a literal here (TestActionCatalog).
func TestPatternAuditActions(t *testing.T) {
	ctx, admin := patternCtx(t)
	for owner, keys := range map[PatternOwner][]string{
		SitePatterns: {
			"admin.secret_pattern.created", "admin.secret_pattern.updated", "admin.secret_pattern.disabled",
			"admin.secret_pattern.enabled", "admin.secret_pattern.deleted",
		},
		OrgPatterns(org3(t)): {
			"org.secret_pattern.created", "org.secret_pattern.updated", "org.secret_pattern.disabled",
			"org.secret_pattern.enabled", "org.secret_pattern.deleted",
		},
	} {
		p, err := CreatePattern(ctx, admin, owner, acmeInput("audited"))
		require.NoError(t, err)
		renamed := acmeInput("audited too")
		_, err = UpdatePattern(ctx, owner, p.ID, renamed)
		require.NoError(t, err)
		require.NoError(t, SetPatternEnabled(ctx, owner, p.ID, false))
		require.NoError(t, SetPatternEnabled(ctx, owner, p.ID, true))
		require.NoError(t, DeletePattern(ctx, owner, p.ID))
		for _, key := range keys {
			assert.EqualValues(t, 1, auditCount(t, key), key)
		}
	}
}

// Custom patterns have their own share of the alert cap: however many secrets they find, a built-in rule's still get
// alerts.
func TestScanCustomPatternsHaveTheirOwnShare(t *testing.T) {
	repo := enable(t) // user2/repo1
	ctx := audit_model.WithSystem(t.Context(), "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	open, _ := openAlerts(t, repo.ID)
	limit := 2*open + 8
	defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, limit)()
	_, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("acme"))
	require.NoError(t, err)

	files := map[string]string{"z.txt": token("real-key") + "\n"} // read after the custom ones
	for i := range limit + 3 {
		files[fmt.Sprintf("a%d.env", i)] = "K=" + acme(fmt.Sprintf("noise-%d", i)) + "\n"
	}
	w.commit(files)
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	assert.NotNil(t, alertFor(t, repo.ID, token("real-key")), "the built-in rule's secret has room")
	_, _, custom, err := secretscan_model.CountOpenAlerts(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.Equal(t, limit/2, custom, "half of the cap at most")
	assert.Equal(t, stopAlerts, scanOf(t, repo.ID, secretscan_model.KindRepo).Error, "the rest is a hole")
}

func TestPatternOwnerMustBeSiteOrOrganization(t *testing.T) {
	ctx, admin := patternCtx(t)
	for name, o := range map[string]PatternOwner{
		"zero value": {}, "nil organization": OrgPatterns(nil),
		"a user": OrgPatterns(unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})),
	} {
		_, err := CreatePattern(ctx, admin, o, acmeInput("x"))
		require.ErrorIs(t, err, ErrPatternOwnerInvalid, name)
		_, err = UpdatePattern(ctx, o, 1, acmeInput("x"))
		require.ErrorIs(t, err, ErrPatternOwnerInvalid, name)
		require.ErrorIs(t, SetPatternEnabled(ctx, o, 1, false), ErrPatternOwnerInvalid, name)
		require.ErrorIs(t, DeletePattern(ctx, o, 1), ErrPatternOwnerInvalid, name)
	}
}

// A rename that loses the unique key to a concurrent save is ErrPatternNameTaken, as a create is.
func TestPatternNameRace(t *testing.T) {
	ctx, admin := patternCtx(t)
	p, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("taken"))
	require.NoError(t, err)
	dbErr := errors.New("UNIQUE constraint failed")
	require.ErrorIs(t, nameRace(ctx, dbErr, 0, "taken", p.ID+1), ErrPatternNameTaken)
	require.ErrorIs(t, nameRace(ctx, dbErr, 0, "taken", p.ID), dbErr, "its own name")
	require.ErrorIs(t, nameRace(ctx, dbErr, 0, "free", 0), dbErr)
	require.ErrorIs(t, nameRace(ctx, ErrPatternNotFound, 0, "taken", 0), ErrPatternNotFound)
}

// Parallel saves can't pass the cap: each save locks the site's row before it counts (SQLite serializes the
// transactions anyway; the lock is what holds on PostgreSQL and MySQL).
func TestPatternCapUnderParallelSaves(t *testing.T) {
	ctx, admin := patternCtx(t)
	for i := range secretdetection.MaxCustomRules - 3 {
		_, err := CreatePattern(ctx, admin, SitePatterns, acmeInput(fmt.Sprintf("site %d", i)))
		require.NoError(t, err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 10)
	org := org3(t)
	for i := range errs {
		wg.Go(func() {
			_, errs[i] = CreatePattern(ctx, admin, OrgPatterns(org), acmeInput(fmt.Sprintf("org %d", i)))
		})
	}
	wg.Wait()
	created := 0
	for _, err := range errs {
		if err == nil {
			created++
			continue
		}
		require.ErrorIs(t, err, ErrPatternLimit)
	}
	assert.Equal(t, 3, created)
	n, err := secretscan_model.CountActiveCustomPatterns(ctx, 0, 3)
	require.NoError(t, err)
	assert.EqualValues(t, secretdetection.MaxCustomRules, n)
}

// A stored rule is checked once per process; a refused one is skipped every time.
func TestStoredRuleCheckIsCached(t *testing.T) {
	ctx, _ := patternCtx(t)
	org := org3(t)
	refused := &secretscan_model.CustomPattern{OwnerID: org.ID, Name: "common", Pattern: `acme-key-[a-z0-9]{20}`, Keywords: secretscan_model.EncodeKeywords([]string{"the"}), Enabled: true}
	_, err := db.GetEngine(ctx).Insert(refused)
	require.NoError(t, err)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	for range 2 {
		rules, err := customRules(ctx, repo)
		require.NoError(t, err)
		assert.Empty(t, rules, "a keyword all over ordinary files")
	}
	key := sha256.Sum256([]byte(refused.Name + "\x00" + refused.Pattern + "\x00the"))
	storedRules.Lock()
	ok, has := storedRules.ok[key]
	storedRules.Unlock()
	assert.True(t, has)
	assert.False(t, ok)
}

// Custom alerts that only refs/pull/* reach (which any reader can write) have a quarter of the custom share, so a
// pull request can't fill it and push out a branch's secret.
func TestScanCustomPullAlertsHaveTheirOwnShare(t *testing.T) {
	repo := enable(t) // user2/repo1
	ctx := audit_model.WithSystem(t.Context(), "test")
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	w := newWork(t, repo)
	require.NoError(t, Scan(t.Context(), repo.ID))
	defer test.MockVariableValue(&setting.SecretScanning.MaxAlertsPerRepo, 64)() // custom share 32, pull-only 8
	_, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("acme"))
	require.NoError(t, err)

	w.git("checkout", "-q", "-b", "junk", repo.DefaultBranch)
	files := map[string]string{}
	for i := range 12 {
		files[fmt.Sprintf("j%d.env", i)] = "K=" + acme(fmt.Sprintf("junk-%d", i)) + "\n"
	}
	w.commit(files)
	w.push("refs/pull/1/head")
	require.NoError(t, Scan(t.Context(), repo.ID))
	n, err := secretscan_model.CountOpenAlertsByCap(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 8, n.CustomViaPull, "a quarter of the custom share")
	assert.EqualValues(t, 8, n.Custom)

	w.git("checkout", "-q", repo.DefaultBranch)
	w.commit(map[string]string{"real.env": "K=" + acme("real") + "\n"})
	w.pushDefault()
	require.NoError(t, Scan(t.Context(), repo.ID))
	n, err = secretscan_model.CountOpenAlertsByCap(t.Context(), repo.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 9, n.Custom, "the branch's secret has room")
	assert.EqualValues(t, 8, n.CustomViaPull)
}

// Test and a refused add run the pattern on the sample only after the engine bounded both: a keyword with a control
// character is refused before the engine's checks, so it must not let a huge pattern run on a huge sample.
func TestTestPatternRunsOnlyCheckedPatterns(t *testing.T) {
	in := PatternInput{
		Name: "big", Pattern: strings.Repeat(`(?:[a-z0-9]|x[0-9]y)`, 2000) + "q",
		Sample: strings.Repeat("a", 200<<10), Keywords: []string{"abc\x01"},
	}
	start := time.Now()
	res, err := TestPattern(in)
	require.ErrorIs(t, err, secretdetection.ErrKeywordMissing)
	require.NotErrorIs(t, err, secretdetection.ErrKeywordNotInMatch)
	assert.Nil(t, res)
	assert.Nil(t, FoundInSample(in, err))
	assert.Less(t, time.Since(start), 2*time.Second, "the pattern never ran (it took over 10 s when it did)")

	in.Keywords = []string{"abc"}
	res, err = TestPattern(in)
	require.ErrorIs(t, err, secretdetection.ErrTestStringTooLong)
	assert.Nil(t, res)

	// a keyword missing from the match, or a short secret: what was found is shown, masked
	in = acmeInput("x")
	in.Keywords = []string{"zork"}
	res, err = TestPattern(in)
	require.ErrorIs(t, err, secretdetection.ErrKeywordNotInMatch)
	require.NotNil(t, res)
	assert.Equal(t, res, FoundInSample(in, err))
	assert.Equal(t, "acme…", res.Masked)
	assert.Nil(t, FoundInSample(in, secretdetection.ErrPatternTooComplex))
}

func TestRenamePatternChecksTheName(t *testing.T) {
	ctx, admin := patternCtx(t)
	p, err := CreatePattern(ctx, admin, SitePatterns, acmeInput("rule"))
	require.NoError(t, err)
	for _, name := range []string{"a\u202eb", "a\u200bb", "a\u2066b", "a\ufeffb", "a\x00b", strings.Repeat("n", MaxPatternNameLen+1)} {
		require.ErrorIs(t, RenamePattern(ctx, SitePatterns, p.ID, name), secretdetection.ErrCustomNameInvalid, "%q", name)
	}
	err = RenamePattern(ctx, SitePatterns, p.ID, "leak "+token("rename"))
	var holds *secretdetection.HoldsSecretError
	require.ErrorAs(t, err, &holds)
	assert.Equal(t, "name", holds.Field)
	got := unittest.AssertExistsAndLoadBean(t, &secretscan_model.CustomPattern{ID: p.ID})
	assert.Equal(t, "rule", got.Name)
}

func TestDeletePatternConfirmed(t *testing.T) {
	ctx, admin := patternCtx(t)
	p, err := CreatePattern(ctx, admin, OrgPatterns(org3(t)), acmeInput("Rule One"))
	require.NoError(t, err)
	require.ErrorIs(t, DeletePatternConfirmed(ctx, OrgPatterns(org3(t)), p.ID, "rule"), ErrConfirmName)
	require.ErrorIs(t, DeletePatternConfirmed(ctx, SitePatterns, p.ID, "rule one"), ErrPatternNotFound, "another owner's")
	require.NoError(t, DeletePatternConfirmed(ctx, OrgPatterns(org3(t)), p.ID, "  rule one "))
	assert.NotZero(t, unittest.AssertExistsAndLoadBean(t, &secretscan_model.CustomPattern{ID: p.ID}).DeletedUnix)
}

// An owner keeps at most MaxLivePatterns, on or off; deleted ones don't count.
func TestLivePatternLimit(t *testing.T) {
	ctx, admin := patternCtx(t)
	org := org3(t)
	rows := make([]*secretscan_model.CustomPattern, MaxLivePatterns)
	for i := range rows {
		rows[i] = &secretscan_model.CustomPattern{OwnerID: org.ID, Name: fmt.Sprintf("off %d", i), Pattern: `acme-key-[a-z0-9]{20}`, Keywords: secretscan_model.EncodeKeywords([]string{"acme-key"})}
	}
	_, err := db.GetEngine(ctx).Insert(rows)
	require.NoError(t, err)
	_, err = CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("one more"))
	require.ErrorIs(t, err, ErrLivePatternLimit)
	_, err = CreatePattern(ctx, admin, SitePatterns, acmeInput("site"))
	require.NoError(t, err, "another owner")
	first := unittest.AssertExistsAndLoadBean(t, &secretscan_model.CustomPattern{OwnerID: org.ID, Name: "off 0"})
	require.NoError(t, DeletePattern(ctx, OrgPatterns(org), first.ID))
	_, err = CreatePattern(ctx, admin, OrgPatterns(org), acmeInput("one more"))
	require.NoError(t, err)
}
