// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"context"
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	system_model "forgejo.org/models/system"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/log"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
)

const (
	// MaxPatternNameLen is the longest name of a custom pattern, in bytes.
	MaxPatternNameLen = 64
	// MaxLivePatterns is how many patterns that are not deleted, on or off, an owner may keep: every page and alert
	// list reads them.
	MaxLivePatterns = 200
)

var (
	// ErrPatternLimit is a save that would make more than secretdetection.MaxCustomRules enabled patterns of the
	// site and the organization together (the site's come first, so the site's own count is the limit for a site
	// pattern).
	ErrPatternLimit = util.NewInvalidArgumentErrorf("too many custom patterns")
	// ErrLivePatternLimit is a new pattern of an owner that already keeps MaxLivePatterns, on or off.
	ErrLivePatternLimit = util.NewInvalidArgumentErrorf("too many custom patterns kept")
	// ErrConfirmName is a delete confirmed with a name that is not the pattern's.
	ErrConfirmName = util.NewInvalidArgumentErrorf("the name does not match")
	// ErrPatternNameTaken is a name another live pattern of the owner has.
	ErrPatternNameTaken = util.NewAlreadyExistErrorf("a pattern of that name exists")
	// ErrPatternNotFound is a pattern the owner doesn't have, or one that is deleted.
	ErrPatternNotFound = util.NewNotExistErrorf("pattern does not exist")
	// ErrPatternOwnerInvalid is a PatternOwner that is neither the site nor an organization.
	ErrPatternOwnerInvalid = util.NewInvalidArgumentErrorf("patterns belong to the site or an organization")
)

// PatternOwner is whose patterns a call changes: SitePatterns or OrgPatterns(org). The zero value, and an owner
// that is not an organization, are refused (ErrPatternOwnerInvalid).
type PatternOwner struct {
	site bool
	org  *user_model.User
}

// SitePatterns is the owner of the site's patterns, which run in every repository.
var SitePatterns = PatternOwner{site: true}

// OrgPatterns is the owner of an organization's patterns, which run in its repositories.
func OrgPatterns(org *user_model.User) PatternOwner { return PatternOwner{org: org} }

// id is the owner_id of the patterns: 0 for the site's, the organization's ID.
func (o PatternOwner) id() (int64, error) {
	switch {
	case o.site && o.org == nil:
		return 0, nil
	case !o.site && o.org != nil && o.org.IsOrganization():
		return o.org.ID, nil
	}
	return 0, ErrPatternOwnerInvalid
}

// PatternInput is what a user writes: the rule and a sample the rule must find a secret in (it is checked and then
// dropped, never stored).
type PatternInput struct {
	Name, Pattern, Sample string
	Keywords              []string
}

// normalize strips the name and the keywords and drops repeated keywords (compared in lower case).
func (in PatternInput) normalize() PatternInput {
	in.Name = strings.TrimSpace(in.Name)
	var keywords []string
	seen := map[string]bool{}
	for _, k := range in.Keywords {
		k = strings.TrimSpace(k)
		if !seen[strings.ToLower(k)] {
			seen[strings.ToLower(k)] = true
			keywords = append(keywords, k)
		}
	}
	in.Keywords = keywords
	return in
}

// ValidatePattern is the one check of a pattern on save and in the Test button: the engine's ValidateCustomRule, and
// the limits of the store. Nothing is stored.
func ValidatePattern(in PatternInput) error {
	return validate(in.normalize())
}

// validate is ValidatePattern of a normalized input. Text that isn't valid UTF-8 or holds a control character (NUL
// included) is refused: the database may refuse or cut it, and the name and keywords are shown. A name with
// bidirectional-control or zero-width characters is refused too: it could make a label read like another one.
func validate(in PatternInput) error {
	if !validName(in.Name) {
		return secretdetection.ErrCustomNameInvalid
	}
	if util.StripControl(in.Pattern) != in.Pattern {
		return secretdetection.ErrPatternInvalid
	}
	for _, k := range in.Keywords {
		if util.StripControl(k) != k {
			return secretdetection.ErrKeywordMissing
		}
	}
	return secretdetection.ValidateCustomRule(in.Name, in.Pattern, in.Sample, in.Keywords)
}

// validName is the store's check of a name; the engine checks it too (ValidateCustomRule).
func validName(name string) bool {
	return len(name) <= MaxPatternNameLen && util.StripControl(name) == name && util.StripFormatting(name) == name // StripControl also replaces bytes that aren't UTF-8
}

// capOwners are the owners whose enabled patterns count against the cap of the owner's patterns.
func capOwners(owner int64) []int64 {
	if owner == 0 {
		return []int64{0}
	}
	return []int64{0, owner}
}

func checkCap(ctx context.Context, owner int64) error {
	n, err := secretscan_model.CountActiveCustomPatterns(ctx, capOwners(owner)...)
	if err != nil {
		return err
	}
	if n >= secretdetection.MaxCustomRules {
		return ErrPatternLimit
	}
	return nil
}

func nameTaken(ctx context.Context, owner int64, name string, exceptID int64) (bool, error) {
	return db.GetEngine(ctx).Where("owner_id = ? AND name = ? AND deleted_unix = 0 AND id <> ?", owner, name, exceptID).
		Exist(new(secretscan_model.CustomPattern))
}

func checkName(ctx context.Context, owner int64, name string, exceptID int64) error {
	taken, err := nameTaken(ctx, owner, name, exceptID)
	if err == nil && taken {
		err = ErrPatternNameTaken
	}
	return err
}

// nameRace turns the error of a write that lost a race on the unique key into ErrPatternNameTaken. It runs after the
// transaction: on PostgreSQL a failed statement aborts it.
func nameRace(ctx context.Context, err error, owner int64, name string, exceptID int64) error {
	if err == nil || errors.Is(err, util.ErrAlreadyExist) || errors.Is(err, util.ErrInvalidArgument) || errors.Is(err, util.ErrNotExist) {
		return err
	}
	if taken, terr := nameTaken(ctx, owner, name, exceptID); terr == nil && taken {
		return ErrPatternNameTaken
	}
	return err
}

// lockPatterns serializes the saves that count against the cap: every save locks the row of the site's secret
// scanning configuration (created empty first if need be, as the settings page does), since an organization's cap
// counts the site's patterns too. Saves are rare; a scan never takes this lock.
func lockPatterns(ctx context.Context) error {
	key := setting.Config().SecretScanningConfig.DynKey()
	if err := system_model.EnsureSetting(ctx, key); err != nil {
		return err
	}
	_, _, err := system_model.GetSettingForUpdate(ctx, key)
	return err
}

// recordPattern writes the audit entry of a change. The audit log can be shipped to outside destinations, so it keeps
// a sha256 of the pattern, never its text.
func recordPattern(ctx context.Context, action string, p *secretscan_model.CustomPattern, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	data["name"], data["pattern_sha256"], data["keyword_count"] = p.Name, base.EncodeSha256(p.Pattern), len(p.KeywordList())
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, OwnerID: p.OwnerID,
		TargetType: "secret_pattern", TargetID: p.ID, TargetName: p.Name, Data: data,
	})
}

// levelAction picks the key of the organization's or the site's level; each key is a literal at its call site.
func levelAction(owner int64, a audit_model.LevelActions) string {
	if owner == 0 {
		return a.Admin
	}
	return a.Org
}

// CreatePattern validates and stores a pattern of the owner. The caller checked who may. It is enabled and counts
// against the cap from the start; history is not scanned again.
func CreatePattern(ctx context.Context, doer *user_model.User, o PatternOwner, in PatternInput) (*secretscan_model.CustomPattern, error) {
	owner, err := o.id()
	if err != nil {
		return nil, err
	}
	in = in.normalize()
	if err := validate(in); err != nil {
		return nil, err
	}
	p := &secretscan_model.CustomPattern{
		OwnerID: owner, Name: in.Name, Pattern: in.Pattern, Keywords: secretscan_model.EncodeKeywords(in.Keywords),
		Enabled: true, CreatedByID: doer.ID,
	}
	err = db.WithTx(ctx, func(ctx context.Context) error {
		if err := lockPatterns(ctx); err != nil {
			return err
		}
		if err := checkName(ctx, owner, p.Name, 0); err != nil {
			return err
		}
		if err := checkCap(ctx, owner); err != nil {
			return err
		}
		if n, err := secretscan_model.CountLiveCustomPatterns(ctx, owner); err != nil {
			return err
		} else if n >= MaxLivePatterns {
			return ErrLivePatternLimit
		}
		if _, err := db.GetEngine(ctx).Insert(p); err != nil {
			return err
		}
		return recordPattern(ctx, levelAction(owner, audit_model.LevelActions{Org: "org.secret_pattern.created", Admin: "admin.secret_pattern.created"}), p, nil)
	})
	if err != nil {
		return nil, nameRace(ctx, err, owner, p.Name, 0)
	}
	return p, nil
}

// load reads a live pattern of the owner for a change.
func load(ctx context.Context, owner, id int64) (*secretscan_model.CustomPattern, error) {
	p, err := secretscan_model.GetCustomPattern(ctx, owner, id)
	if err != nil {
		return nil, err
	}
	if p == nil || p.DeletedUnix != 0 {
		return nil, ErrPatternNotFound
	}
	return p, nil
}

// UpdatePattern replaces the name, pattern and keywords of a live pattern, which is checked again with the sample.
// A save that changes nothing records nothing. Alerts already found keep their rule.
func UpdatePattern(ctx context.Context, o PatternOwner, id int64, in PatternInput) (*secretscan_model.CustomPattern, error) {
	owner, err := o.id()
	if err != nil {
		return nil, err
	}
	in = in.normalize()
	if err := validate(in); err != nil {
		return nil, err
	}
	var p *secretscan_model.CustomPattern
	err = db.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if p, err = load(ctx, owner, id); err != nil {
			return err
		}
		keywords := secretscan_model.EncodeKeywords(in.Keywords)
		if p.Name == in.Name && p.Pattern == in.Pattern && p.Keywords == keywords {
			return nil
		}
		if err := checkName(ctx, owner, in.Name, id); err != nil {
			return err
		}
		prevName, prev := p.Name, p.Pattern
		n, err := db.GetEngine(ctx).Where("id = ? AND owner_id = ? AND deleted_unix = 0", id, owner).Cols("name", "pattern", "keywords").
			Update(&secretscan_model.CustomPattern{Name: in.Name, Pattern: in.Pattern, Keywords: keywords})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrPatternNotFound // deleted meanwhile
		}
		p.Name, p.Pattern, p.Keywords = in.Name, in.Pattern, keywords
		data := map[string]any{"previous_pattern_sha256": base.EncodeSha256(prev)}
		if prevName != p.Name {
			data["previous_name"] = prevName
		}
		return recordPattern(ctx, levelAction(owner, audit_model.LevelActions{Org: "org.secret_pattern.updated", Admin: "admin.secret_pattern.updated"}), p, data)
	})
	if err != nil {
		return nil, nameRace(ctx, err, owner, in.Name, id)
	}
	return p, nil
}

// SetPatternEnabled turns a live pattern on or off. Off stops it from the next scan on; its alerts stay as they are.
// Turning it on counts against the cap again.
func SetPatternEnabled(ctx context.Context, o PatternOwner, id int64, enabled bool) error {
	owner, err := o.id()
	if err != nil {
		return err
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		p, err := load(ctx, owner, id)
		if err != nil || p.Enabled == enabled {
			return err
		}
		if enabled {
			if err := lockPatterns(ctx); err != nil {
				return err
			}
			if err := checkCap(ctx, owner); err != nil {
				return err
			}
		}
		n, err := db.GetEngine(ctx).Where("id = ? AND owner_id = ? AND deleted_unix = 0 AND enabled = ?", id, owner, !enabled).Cols("enabled").
			Update(&secretscan_model.CustomPattern{Enabled: enabled})
		if err != nil || n == 0 {
			return err // nothing matched: someone else changed it, which is the state asked for or a delete
		}
		if enabled {
			return recordPattern(ctx, levelAction(owner, audit_model.LevelActions{Org: "org.secret_pattern.enabled", Admin: "admin.secret_pattern.enabled"}), p, nil)
		}
		return recordPattern(ctx, levelAction(owner, audit_model.LevelActions{Org: "org.secret_pattern.disabled", Admin: "admin.secret_pattern.disabled"}), p, nil)
	})
}

// DeletePattern marks a live pattern deleted and off. The row stays for the label of its alerts. Its tombstone time
// is made unique among the tombstones of the same name (the unique key has one per second).
func DeletePattern(ctx context.Context, o PatternOwner, id int64) error {
	return deletePattern(ctx, o, id, nil)
}

// DeletePatternConfirmed is DeletePattern of a pattern whose name is confirm (compared without case and surrounding
// spaces, in the delete's transaction), else ErrConfirmName.
func DeletePatternConfirmed(ctx context.Context, o PatternOwner, id int64, confirm string) error {
	return deletePattern(ctx, o, id, &confirm)
}

func deletePattern(ctx context.Context, o PatternOwner, id int64, confirm *string) error {
	owner, err := o.id()
	if err != nil {
		return err
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		p, err := load(ctx, owner, id)
		if err != nil {
			return err
		}
		if confirm != nil && !strings.EqualFold(strings.TrimSpace(*confirm), p.Name) {
			return ErrConfirmName
		}
		at, err := secretscan_model.FreeTombstoneTime(ctx, owner, p.Name)
		if err != nil {
			return err
		}
		n, err := db.GetEngine(ctx).Where("id = ? AND owner_id = ? AND deleted_unix = 0", id, owner).Cols("enabled", "deleted_unix").
			Update(&secretscan_model.CustomPattern{DeletedUnix: at})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrPatternNotFound
		}
		return recordPattern(ctx, levelAction(owner, audit_model.LevelActions{Org: "org.secret_pattern.deleted", Admin: "admin.secret_pattern.deleted"}), p, nil)
	})
}

// customRules are the rules of the enabled custom patterns that apply to the repository: the site's and, for a
// repository of an organization, the organization's (a site pattern can't be turned off by an organization). One
// query. A pattern the engine refuses now is skipped (logged once per process), and at most MaxCustomRules are taken,
// the site's first.
func customRules(ctx context.Context, repo *repo_model.Repository) ([]secretdetection.Rule, error) {
	if err := repo.LoadOwner(ctx); err != nil {
		return nil, err
	}
	owners := []int64{0}
	if repo.Owner.IsOrganization() {
		owners = append(owners, repo.OwnerID)
	}
	patterns, err := secretscan_model.FindActiveCustomPatterns(ctx, owners...)
	if err != nil {
		return nil, err
	}
	var rules []secretdetection.Rule
	for _, p := range patterns {
		if len(rules) >= secretdetection.MaxCustomRules {
			if overCapLogged.due(repo.OwnerID) {
				log.Warn("secret scanning: the repositories of owner %d have more than %d custom patterns, the rest are not used", repo.OwnerID, secretdetection.MaxCustomRules)
			}
			break
		}
		keywords := p.KeywordList()
		if !storedRuleOK(p, keywords) {
			continue
		}
		rules = append(rules, secretdetection.CustomRule(p.RuleID(), p.Name, p.Pattern, keywords))
	}
	return rules, nil
}

// storedRules caches ValidateStoredRule per process, by a hash of what it reads, so that a scan doesn't run the
// corpus check of every pattern again: the result only changes with the engine, which is part of the build. A refused
// pattern is logged when it is first checked, by ID and reason code (the error may quote the pattern).
var storedRules = struct {
	sync.Mutex
	ok map[[sha256.Size]byte]bool
}{ok: map[[sha256.Size]byte]bool{}}

func storedRuleOK(p *secretscan_model.CustomPattern, keywords []string) bool {
	key := sha256.Sum256([]byte(p.Name + "\x00" + p.Pattern + "\x00" + strings.Join(keywords, "\x00")))
	storedRules.Lock()
	ok, has := storedRules.ok[key]
	storedRules.Unlock()
	if has {
		return ok
	}
	err := secretdetection.ValidateStoredRule(p.Name, p.Pattern, keywords)
	if err != nil {
		log.Warn("secret scanning: custom pattern %d is skipped: %s", p.ID, secretdetection.RefusalCode(err))
	}
	storedRules.Lock()
	if len(storedRules.ok) >= 10000 { // edits add entries: start again rather than grow
		clear(storedRules.ok)
	}
	storedRules.ok[key] = err == nil
	storedRules.Unlock()
	return err == nil
}

// overCapLogged says when the over-cap warning of an owner is due: at most once an hour.
var overCapLogged = &hourly{last: map[int64]time.Time{}}

type hourly struct {
	sync.Mutex
	last map[int64]time.Time
}

func (h *hourly) due(id int64) bool {
	h.Lock()
	defer h.Unlock()
	if t, ok := h.last[id]; ok && time.Since(t) < time.Hour {
		return false
	}
	h.last[id] = time.Now()
	return true
}

// RenamePattern changes the name of a live pattern, which is all a saved pattern lets its owner change (the rule is
// fixed, so alerts keep meaning what they meant). No sample is needed. The name is checked as on create. A save that
// changes nothing records nothing.
func RenamePattern(ctx context.Context, o PatternOwner, id int64, name string) error {
	name = strings.TrimSpace(name)
	if name == "" || !validName(name) {
		return secretdetection.ErrCustomNameInvalid
	}
	if err := secretdetection.CheckHoldsSecret("name", name); err != nil {
		return err
	}
	owner, err := o.id()
	if err != nil {
		return err
	}
	err = db.WithTx(ctx, func(ctx context.Context) error {
		p, err := load(ctx, owner, id)
		if err != nil || p.Name == name {
			return err
		}
		if err := checkName(ctx, owner, name, id); err != nil {
			return err
		}
		prev := p.Name
		n, err := db.GetEngine(ctx).Where("id = ? AND owner_id = ? AND deleted_unix = 0", id, owner).Cols("name").Update(&secretscan_model.CustomPattern{Name: name})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrPatternNotFound // deleted meanwhile
		}
		p.Name = name
		return recordPattern(ctx, levelAction(owner, audit_model.LevelActions{Org: "org.secret_pattern.renamed", Admin: "admin.secret_pattern.renamed"}), p, map[string]any{"previous_name": prev})
	})
	return nameRace(ctx, err, owner, name, id)
}

// TestResult is what the Test button shows for a rule that is accepted: how long the secret found in the sample is
// and its first characters. Never the sample or the whole secret.
type TestResult struct {
	Masked    string
	SecretLen int
}

// TestPattern checks a pattern the way a save does and stores nothing. For a rule that is accepted, or refused only
// because a keyword is not in the match or the secret is too short, it also says what it found. The sample is
// neither returned whole nor logged.
func TestPattern(in PatternInput) (*TestResult, error) {
	in = in.normalize()
	err := validate(in)
	if err != nil && !sampleChecked(err) {
		return nil, err
	}
	return found(in), err
}

// FoundInSample is TestPattern's result for err, the refusal of a save of in: what the pattern found, for a refusal
// only because a keyword is not in the match or the secret is too short, else nil (the pattern is not run).
func FoundInSample(in PatternInput, err error) *TestResult {
	if !sampleChecked(err) {
		return nil
	}
	return found(in.normalize())
}

// sampleChecked: err is one the engine returns only after it checked the pattern's size and shape and the sample's
// length, so the pattern may run on the sample. Every other refusal may come before those checks.
func sampleChecked(err error) bool {
	return errors.Is(err, secretdetection.ErrKeywordNotInMatch) || errors.Is(err, secretdetection.ErrSecretTooShort)
}

// found runs the pattern on the sample: only for an input the engine checked (sampleChecked or accepted).
func found(in PatternInput) *TestResult {
	re, err := regexp.Compile(in.Pattern)
	if err != nil {
		return nil
	}
	m := re.FindStringSubmatchIndex(in.Sample)
	if m == nil {
		return nil
	}
	g := min(re.NumSubexp(), 1)
	secret := in.Sample[m[2*g]:m[2*g+1]]
	return &TestResult{SecretLen: len(secret), Masked: maskSecret(secret)}
}

// maskSecret keeps at most the first four characters of a third of the secret.
func maskSecret(s string) string {
	runes := []rune(s)
	return string(runes[:min(4, len(runes)/3)]) + "…"
}
