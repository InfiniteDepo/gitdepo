// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package migrations

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"unicode"

	"forgejo.org/models/db"
	git_model "forgejo.org/models/git"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	webhook_model "forgejo.org/models/webhook"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/modules/validation"
	webhook_module "forgejo.org/modules/webhook"
	"forgejo.org/services/branchworkflow"
	pull_service "forgejo.org/services/pull"
	webhook_service "forgejo.org/services/webhook"

	"github.com/gobwas/glob"
	"github.com/gobwas/glob/syntax"
)

type bitbucketRestriction struct {
	Type    string `json:"type"`
	Matcher struct {
		ID   string `json:"id"`
		Type struct {
			ID string `json:"id"`
		} `json:"type"`
	} `json:"matcher"`
	Users      []bitbucketAccount `json:"users"`
	Groups     []string           `json:"groups"`
	AccessKeys []struct {
		Key struct {
			ID int64 `json:"id"`
		} `json:"key"`
	} `json:"accessKeys"`
}

type bitbucketWebhook struct {
	ID            int64             `json:"id"`
	URL           string            `json:"url"`
	Active        bool              `json:"active"`
	Events        []string          `json:"events"`
	Configuration map[string]string `json:"configuration"`
}

// bitbucketGlob turns an Ant-style Bitbucket pattern into a glob with separator "/": every special character is
// quoted except "*" and "?", which mean the same, and "**" also matches no segment, as in Ant.
func bitbucketGlob(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if c := p[i]; c != '*' && c != '?' && (syntax.Special(c) || c == ',' || c == '!') { // "," and "!" mean something in braces and classes
			b.WriteByte('\\')
		}
		b.WriteByte(p[i])
	}
	s := strings.ReplaceAll(b.String(), "/**/", "/{,**/}")
	if strings.HasPrefix(s, "**/") {
		s = "{,**/}" + s[3:]
	}
	if strings.HasSuffix(s, "/**") {
		s = s[:len(s)-3] + "{,/**}"
	}
	return s
}

// bitbucketBranchRule translates a Bitbucket matcher into the name of a branch rule that matches every branch the
// matcher matched, or more. Bitbucket matches a pattern against a suffix of the full ref, tags included (tags reports
// that), and appends "**" to a pattern ending in "/". ok is false for a matcher no branch rule can stand for: a branch
// model, any ref, or refs other than branches.
func bitbucketBranchRule(matcherType, id string) (rule string, tags, ok bool) {
	switch matcherType {
	case "BRANCH":
		name, found := strings.CutPrefix(id, "refs/heads/")
		if !found || name == "" {
			return "", false, false
		}
		if git_model.IsRuleNameSpecial(name) {
			name = glob.QuoteMeta(name)
		}
		return name, false, true
	case "PATTERN":
		if strings.HasSuffix(id, "/") {
			id += "**"
		}
		switch {
		case id == "" || id == "refs/heads/":
			return "", false, false
		case strings.HasPrefix(id, "refs/heads/"):
			return bitbucketGlob(strings.TrimPrefix(id, "refs/heads/")), false, true
		case strings.HasPrefix(id, "refs/"), strings.HasPrefix(id, "tags/"):
			return "", false, false
		case strings.HasPrefix(id, "heads/"):
			return "{" + bitbucketGlob(strings.TrimPrefix(id, "heads/")) + ",**/" + bitbucketGlob(id) + "}", false, true
		}
		return "{" + bitbucketGlob(id) + ",**/" + bitbucketGlob(id) + "}", true, true
	}
	return "", false, false
}

// sameBitbucketRule reports whether an existing rule has exactly the fields of the rule the import would write:
// every exported field but the identity ones, with nil and empty lists alike and ID lists in any order.
func sameBitbucketRule(want, have *git_model.ProtectedBranch) bool {
	w, h := reflect.ValueOf(want).Elem(), reflect.ValueOf(have).Elem()
	for i := 0; i < w.NumField(); i++ {
		f := w.Type().Field(i)
		switch f.Name {
		case "ID", "RepoID", "OrgID", "GroupID", "Repo", "CreatedUnix", "UpdatedUnix":
			continue
		}
		if !f.IsExported() {
			continue
		}
		a, b := w.Field(i).Interface(), h.Field(i).Interface()
		if ids, ok := a.([]int64); ok {
			if !util.SliceSortedEqual(ids, b.([]int64)) {
				return false
			}
		} else if w.Field(i).Kind() == reflect.Slice && w.Field(i).Len() == 0 && h.Field(i).Len() == 0 {
			continue
		} else if !reflect.DeepEqual(a, b) {
			return false
		}
	}
	return true
}

// planRules plans the branch permissions of a project or repository as branch rules of that level, one per matcher.
func (p *bitbucketPlanner) planRules(owner *BitbucketImportItem, endpoint string) error {
	restrictions, err := callAPIPaged[bitbucketRestriction](p.d, endpoint)
	if err != nil {
		return err
	}
	type merged struct {
		item         *BitbucketImportItem
		tags         bool
		restrictions []bitbucketRestriction
	}
	var rules []*merged
	byName := map[string]*merged{}
	for _, r := range restrictions {
		name, tags, ok := bitbucketBranchRule(r.Matcher.Type.ID, r.Matcher.ID)
		known := slices.Contains([]string{"read-only", "pull-request-only", "no-deletes", "fast-forward-only"}, r.Type)
		item := &BitbucketImportItem{Kind: "rule", Bitbucket: util.StripControl(owner.Bitbucket + " " + r.Type + " " + r.Matcher.ID), Target: owner.Name}
		if !ok || !known {
			if p.skipUnmapped {
				p.add(item, BitbucketSkipped, "unmapped")
			} else {
				p.add(item, BitbucketConflict, "unmapped: pass --skip-unmapped to import without it")
			}
			continue
		}
		if _, err := glob.Compile(name, '/'); err != nil || strings.ContainsFunc(r.Matcher.ID, unicode.IsControl) {
			p.add(item, BitbucketConflict, "the pattern doesn't translate")
			continue
		}
		m := byName[name]
		if m == nil {
			item.Name, item.Bitbucket = name, util.StripControl(owner.Bitbucket+" "+r.Matcher.ID)
			m = &merged{item: item}
			byName[name] = m
			rules = append(rules, m)
		}
		m.tags = m.tags || tags
		m.restrictions = append(m.restrictions, r)
	}

	items := make([]*BitbucketImportItem, 0, len(rules))
	notes := map[*BitbucketImportItem][]string{}
	for _, m := range rules {
		n, err := p.buildRule(owner, m.item, m.restrictions, m.tags)
		if err != nil {
			return err
		}
		items, notes[m.item] = append(items, m.item), n
	}
	// Bitbucket applies every matching restriction, gitdepo only the first matching rule of a level: where rules may
	// overlap (a glob, or two plain names that differ only in case, since plain names match case-insensitively),
	// every rule of the level gets the strictest combination of them all
	names := map[string]bool{}
	overlapping := false
	for _, it := range items {
		overlapping = overlapping || git_model.IsRuleNameSpecial(it.Name) || names[strings.ToLower(it.Name)]
		names[strings.ToLower(it.Name)] = true
	}
	if overlapping && len(items) > 1 {
		if combineBitbucketRules(items) {
			for _, it := range items {
				notes[it] = append(notes[it], "stricter than Bitbucket (overlapping restrictions)")
			}
		}
	}
	for _, it := range items {
		if err := p.finishRule(owner, it, strings.Join(notes[it], "; ")); err != nil {
			return err
		}
	}
	return nil
}

// buildRule builds the rule of one matcher and returns its notes. An exception that can't be mapped is dropped, which
// only makes the rule stricter: an empty allowlist lets nobody through.
func (p *bitbucketPlanner) buildRule(owner, item *BitbucketImportItem, restrictions []bitbucketRestriction, tags bool) ([]string, error) {
	var dropped, notes []string
	type exceptions struct {
		users []int64
		keys  []*BitbucketImportItem
	}
	byType := map[string]*exceptions{}
	for _, r := range restrictions {
		e := &exceptions{}
		for _, u := range r.Users {
			if matched, err := matchBitbucketUser(p.ctx, u); err == nil {
				if why, err := p.cannotHold(owner, matched); err != nil {
					return nil, err
				} else if why != "" {
					dropped = append(dropped, matched.Name+" ("+why+")")
				} else {
					e.users = append(e.users, matched.ID)
				}
			} else if unmatched, ok := errors.AsType[bitbucketUnmatched](err); ok {
				dropped = append(dropped, util.StripControl(u.Name)+" ("+string(unmatched)+")")
			} else {
				return nil, err
			}
		}
		for _, g := range r.Groups {
			dropped = append(dropped, "group "+util.StripControl(g))
		}
		for _, k := range r.AccessKeys {
			// only a key of this repository that can write: a read key never pushes
			if key := p.keys[owner][k.Key.ID]; key != nil && owner.Kind == "repository" && key.mode == perm.AccessModeWrite {
				e.keys = append(e.keys, key)
			} else {
				dropped = append(dropped, fmt.Sprintf("key %d", k.Key.ID))
			}
		}
		if prev := byType[r.Type]; prev != nil { // the same type twice on one matcher: Bitbucket applies both
			e.users, e.keys = intersect(prev.users, e.users), intersect(prev.keys, e.keys)
		}
		byType[r.Type] = e
	}

	rule := &git_model.ProtectedBranch{RuleName: item.Name, ApplyToAdmins: true, CanPush: true}
	ro, pr := byType["read-only"], byType["pull-request-only"]
	if ro != nil || pr != nil {
		push := ro
		if push == nil {
			push = pr
		} else if pr != nil { // both: only someone both let through may push
			push = &exceptions{users: intersect(ro.users, pr.users), keys: intersect(ro.keys, pr.keys)}
		}
		// pushes only through the allowlist, empty = nobody
		rule.EnableWhitelist = true
		item.ruleOpts.UserIDs, item.pushKeys = push.users, push.keys
	}
	if ro != nil {
		rule.EnableMergeWhitelist = true
		item.ruleOpts.MergeUserIDs = ro.users
	}
	if e := byType["no-deletes"]; e != nil {
		item.ruleOpts.DeleteUserIDs, item.deleteKeys = e.users, e.keys
	} else {
		notes = append(notes, "deletion blocked; Bitbucket allowed it")
	}
	if e := byType["fast-forward-only"]; e != nil {
		item.ruleOpts.ForcePushUserIDs, item.forcePushKeys = e.users, e.keys
	} else {
		notes = append(notes, "force push blocked; Bitbucket allowed it")
	}
	if tags {
		notes = append(notes, "Bitbucket applied this to tags too; tag protection not imported")
	}
	if len(dropped) > 0 {
		notes = append(notes, "exceptions dropped: "+strings.Join(dropped, ", "))
	}
	item.parent, item.rule = owner, rule
	return notes, nil
}

// cannotHold tells why a rule of the project or repository can't hold the user in an allowlist: a project rule only
// org members, a repository rule only users who can write its code, now or by this plan.
func (p *bitbucketPlanner) cannotHold(owner *BitbucketImportItem, u *user_model.User) (string, error) {
	if owner.Kind == "project" {
		member, err := organization.IsOrganizationMember(p.ctx, p.org.ID, u.ID)
		if err != nil || member || p.members[u.ID] {
			return "", err
		}
		return "not an org member", nil
	}
	if p.writers[owner][u.ID] || p.writers[p.project][u.ID] {
		return "", nil
	}
	if owner.repo != nil {
		perm, err := access_model.GetUserRepoPermission(p.ctx, owner.repo, u)
		if err != nil || perm.CanWrite(unit.TypeCode) {
			return "", err
		}
	} else if owner, err := organization.IsOrganizationOwner(p.ctx, p.org.ID, u.ID); err != nil || owner {
		return "", err
	}
	return "no write access", nil
}

func intersect[T comparable](a, b []T) []T {
	var both []T
	for _, x := range a {
		if slices.Contains(b, x) {
			both = append(both, x)
		}
	}
	return both
}

// combineBitbucketRules gives every rule the strictest combination of all of them: pushes and merges only for whom
// every restricting rule lets through, deletes and force pushes only for whom every rule lets through. It reports
// whether a rule changed.
func combineBitbucketRules(items []*BitbucketImportItem) bool {
	var push, merge, del, force *[]int64
	var pushKeys, delKeys, forceKeys *[]*BitbucketImportItem
	both := func(acc **[]int64, ids []int64) {
		if *acc == nil {
			*acc = &ids
		} else {
			v := intersect(**acc, ids)
			*acc = &v
		}
	}
	bothKeys := func(acc **[]*BitbucketImportItem, keys []*BitbucketImportItem) {
		if *acc == nil {
			*acc = &keys
		} else {
			v := intersect(**acc, keys)
			*acc = &v
		}
	}
	for _, it := range items {
		if it.rule.EnableWhitelist {
			both(&push, it.ruleOpts.UserIDs)
			bothKeys(&pushKeys, it.pushKeys)
		}
		if it.rule.EnableMergeWhitelist {
			both(&merge, it.ruleOpts.MergeUserIDs)
		}
		both(&del, it.ruleOpts.DeleteUserIDs)
		bothKeys(&delKeys, it.deleteKeys)
		both(&force, it.ruleOpts.ForcePushUserIDs)
		bothKeys(&forceKeys, it.forcePushKeys)
	}
	changed := false
	for _, it := range items {
		before := fmt.Sprint(it.rule.EnableWhitelist, it.rule.EnableMergeWhitelist, it.ruleOpts, it.pushKeys, it.deleteKeys, it.forcePushKeys)
		if push != nil {
			it.rule.EnableWhitelist, it.ruleOpts.UserIDs, it.pushKeys = true, *push, *pushKeys
		}
		if merge != nil {
			it.rule.EnableMergeWhitelist, it.ruleOpts.MergeUserIDs = true, *merge
		}
		it.ruleOpts.DeleteUserIDs, it.deleteKeys = *del, *delKeys
		it.ruleOpts.ForcePushUserIDs, it.forcePushKeys = *force, *forceKeys
		changed = changed || before != fmt.Sprint(it.rule.EnableWhitelist, it.rule.EnableMergeWhitelist, it.ruleOpts, it.pushKeys, it.deleteKeys, it.forcePushKeys)
	}
	return changed
}

// finishRule decides whether the built rule is new, reused (an existing rule of the same name and level with exactly
// these fields) or a conflict (one in another shape).
func (p *bitbucketPlanner) finishRule(owner, item *BitbucketImportItem, note string) error {
	var existing *git_model.ProtectedBranch
	var err error
	if owner.Kind == "project" && owner.group != nil {
		existing, err = git_model.GetOrgProtectedBranchRuleByName(p.ctx, p.org.ID, owner.group.ID, item.Name)
	} else if owner.repo != nil {
		existing, err = git_model.GetProtectedBranchRuleByName(p.ctx, owner.repo.ID, item.Name)
	}
	if err != nil {
		return err
	}
	if existing == nil {
		p.add(item, BitbucketPlanned, note)
		return nil
	}
	want, _, err := bitbucketRuleToWrite(p.ctx, p.org, owner, item)
	if err != nil {
		return err
	}
	if same, err := sameBitbucketRuleWithApprovals(p.ctx, want, existing); err != nil {
		return err
	} else if !same {
		p.add(item, BitbucketConflict, "a rule of this name exists in another shape")
		return nil
	}
	p.add(item, BitbucketReused, note)
	return nil
}

func sameBitbucketRuleWithApprovals(ctx context.Context, want, have *git_model.ProtectedBranch) (bool, error) {
	if !sameBitbucketRule(want, have) {
		return false, nil
	}
	approvals, err := db.GetEngine(ctx).Exist(&git_model.ApprovalRule{ProtectedBranchID: have.ID})
	return !approvals, err
}

// bitbucketRuleToWrite returns the rule as it is stored: the allowlists keep only who the rule can hold (an org member
// on a project rule, a user who can write the code of a repository), and the key items as their public key IDs. It
// also returns the number of users it dropped.
func bitbucketRuleToWrite(ctx context.Context, org *organization.Organization, owner, item *BitbucketImportItem) (*git_model.ProtectedBranch, int, error) {
	rule := *item.rule
	dropped := 0
	keep := func(ids []int64) ([]int64, error) {
		kept := make([]int64, 0, len(ids))
		for _, id := range ids {
			var ok bool
			if owner.Kind == "project" {
				member, err := organization.IsOrganizationMember(ctx, org.ID, id)
				if err != nil {
					return nil, err
				}
				ok = member
			} else {
				u, err := user_model.GetUserByID(ctx, id)
				if err != nil {
					return nil, err
				}
				perm, err := access_model.GetUserRepoPermission(ctx, owner.repo, u)
				if err != nil {
					return nil, err
				}
				ok = perm.CanWrite(unit.TypeCode)
			}
			if ok {
				kept = append(kept, id)
			} else {
				dropped++
			}
		}
		return kept, nil
	}
	keyIDs := func(items []*BitbucketImportItem) []int64 {
		ids := make([]int64, 0, len(items))
		for _, k := range items {
			if k.keyID != 0 {
				ids = append(ids, k.keyID)
			}
		}
		return ids
	}
	var err error
	if rule.WhitelistUserIDs, err = keep(item.ruleOpts.UserIDs); err != nil {
		return nil, 0, err
	}
	if rule.MergeWhitelistUserIDs, err = keep(item.ruleOpts.MergeUserIDs); err != nil {
		return nil, 0, err
	}
	if rule.DeleteAllowlistUserIDs, err = keep(item.ruleOpts.DeleteUserIDs); err != nil {
		return nil, 0, err
	}
	if rule.ForcePushAllowlistUserIDs, err = keep(item.ruleOpts.ForcePushUserIDs); err != nil {
		return nil, 0, err
	}
	rule.WhitelistDeployKeyIDs, rule.DeleteAllowlistDeployKeyIDs, rule.ForcePushAllowlistDeployKeyIDs = keyIDs(item.pushKeys), keyIDs(item.deleteKeys), keyIDs(item.forcePushKeys)
	// an allowlist that lost everyone lets nobody through: the flags stay set. WhitelistDeployKeys would let every
	// deploy key push: the import names keys by ID only.
	rule.WhitelistDeployKeys = false
	return &rule, dropped, nil
}

// applyBitbucketRule writes a rule through the paths of the web and API, then checks the open pull requests it covers.
func applyBitbucketRule(ctx context.Context, org *organization.Organization, owner, item *BitbucketImportItem) error {
	rule, dropped, err := bitbucketRuleToWrite(ctx, org, owner, item)
	if err != nil {
		return err
	}
	if dropped > 0 {
		item.Reason = strings.TrimPrefix(item.Reason+fmt.Sprintf("; %d users who can't hold the rule dropped", dropped), "; ")
	}
	opts := git_model.WhitelistOptions{
		UserIDs: rule.WhitelistUserIDs, DeployKeyIDs: rule.WhitelistDeployKeyIDs, MergeUserIDs: rule.MergeWhitelistUserIDs,
		DeleteUserIDs: rule.DeleteAllowlistUserIDs, DeleteDeployKeyIDs: rule.DeleteAllowlistDeployKeyIDs,
		ForcePushUserIDs: rule.ForcePushAllowlistUserIDs, ForcePushDeployKeyIDs: rule.ForcePushAllowlistDeployKeyIDs,
	}
	if owner.Kind == "project" {
		if err := git_model.UpdateOrgProtectBranch(ctx, org.ID, owner.group.ID, rule, opts, nil); err != nil {
			return err
		}
		return pull_service.CheckPRsForOrgRule(ctx, rule)
	}
	rule.RepoID = owner.repo.ID
	if err := git_model.UpdateProtectBranch(ctx, owner.repo, rule, opts); err != nil {
		return err
	}
	return pull_service.CheckPRsForBaseBranch(ctx, owner.repo, rule.RuleName)
}

// bitbucketHookEvents maps the Bitbucket webhook events to the events of a gitdepo hook; the rest is returned unmapped.
func bitbucketHookEvents(events []string) (webhook_module.HookEvents, []string) {
	var e webhook_module.HookEvents
	var unmapped []string
	for _, name := range events {
		switch name {
		case "repo:refs_changed":
			e.Push, e.Create, e.Delete = true, true, true
		case "repo:modified":
			e.Repository = true
		case "repo:forked":
			e.Fork = true
		case "pr:opened", "pr:modified", "pr:merged", "pr:declined", "pr:deleted":
			e.PullRequest = true
		case "pr:from_ref_updated":
			e.PullRequestSync = true
		case "pr:reviewer:approved", "pr:reviewer:unapproved", "pr:reviewer:needs_work":
			e.PullRequestReview = true
		case "pr:reviewer:updated":
			e.PullRequestReviewRequest = true
		case "pr:comment:added", "pr:comment:edited", "pr:comment:deleted":
			e.PullRequestComment = true
		default:
			unmapped = append(unmapped, util.StripControl(name))
		}
	}
	return e, unmapped
}

// redactedHookURL is what the report shows of a hook URL: scheme and host (with port), never the user info, path,
// query or fragment, which often hold tokens.
func redactedHookURL(u *url.URL) string {
	return util.StripControl((&url.URL{Scheme: u.Scheme, Host: u.Host}).String())
}

// maxBitbucketHookURL caps the length of an imported hook URL.
const maxBitbucketHookURL = 2048

// planHooks plans the webhooks of a project or repository as native hooks of that level. A hook without a secret is
// created inactive.
func (p *bitbucketPlanner) planHooks(owner *BitbucketImportItem, endpoint string) error {
	hooks, err := callAPIPaged[bitbucketWebhook](p.d, endpoint)
	if err != nil {
		return err
	}
	for _, h := range hooks {
		item := &BitbucketImportItem{Kind: "hook", Bitbucket: fmt.Sprintf("%s hook %d", owner.Bitbucket, h.ID), Target: owner.Name, bitbucketPermission: bitbucketPermission{parent: owner}}
		u, err := url.Parse(h.URL)
		if err != nil || len(h.URL) > maxBitbucketHookURL || strings.ContainsFunc(h.URL, unicode.IsControl) {
			p.add(item, BitbucketSkipped, "invalid URL")
			continue
		}
		u.User = nil
		item.Name = redactedHookURL(u)
		if !validation.IsValidURL(u.String()) {
			p.add(item, BitbucketSkipped, "invalid URL")
			continue
		}
		if setting.DisableWebhooks {
			p.add(item, BitbucketSkipped, "webhooks are disabled")
			continue
		}
		if err := webhook_service.CheckTypeEnabled(p.ctx, webhook_module.FORGEJO); err != nil {
			p.add(item, BitbucketSkipped, "the hook type is disabled")
			continue
		}
		events, unmapped := bitbucketHookEvents(h.Events)
		var notes []string
		if len(unmapped) > 0 {
			notes = append(notes, "events not mapped: "+strings.Join(unmapped, ", "))
		}
		if events == (webhook_module.HookEvents{}) {
			p.add(item, BitbucketSkipped, strings.Join(append([]string{"no event gitdepo can send"}, notes...), "; "))
			continue
		}
		secret := h.Configuration["secret"]
		if secret == "" {
			notes = append(notes, "no secret: created inactive")
		}
		notes = append(notes, "payload format changes to gitdepo's")
		w := &webhook_model.Webhook{
			URL: u.String(), HTTPMethod: "POST", ContentType: webhook_model.ContentTypeJSON, Secret: secret,
			IsActive: h.Active && secret != "", Type: webhook_module.FORGEJO,
			HookEvent: &webhook_module.HookEvent{ChooseEvents: true, HookEvents: events},
		}
		if err := w.UpdateEvent(); err != nil {
			return err
		}
		item.hook = w

		var opts *webhook_model.ListWebhookOptions
		if owner.Kind == "project" && owner.group != nil {
			opts = &webhook_model.ListWebhookOptions{OwnerID: p.org.ID, GroupID: owner.group.ID}
		} else if owner.repo != nil {
			opts = &webhook_model.ListWebhookOptions{RepoID: owner.repo.ID}
		}
		status := BitbucketPlanned
		if opts != nil {
			existing, err := db.Find[webhook_model.Webhook](p.ctx, *opts)
			if err != nil {
				return err
			}
			for _, e := range existing {
				if e.URL != w.URL {
					continue
				}
				if e.Events == w.Events && e.Secret == w.Secret && e.IsActive == w.IsActive && e.Type == w.Type &&
					e.ContentType == w.ContentType && e.HTTPMethod == w.HTTPMethod && e.Meta == "" && len(e.HeaderAuthorizationEncrypted) == 0 {
					status = BitbucketReused
				} else {
					status = BitbucketConflict
				}
			}
		}
		if status == BitbucketConflict {
			p.add(item, status, "a hook with this URL exists in another shape")
		} else {
			p.add(item, status, strings.Join(notes, "; "))
		}
	}
	return nil
}

// applyBitbucketHook creates a hook; a project hook under the lock of its project, as the API does.
func applyBitbucketHook(ctx context.Context, org *organization.Organization, owner, item *BitbucketImportItem) error {
	w := *item.hook
	if owner.Kind == "repository" {
		w.RepoID = owner.repo.ID
		return webhook_model.CreateWebhook(ctx, &w, "")
	}
	w.OwnerID, w.GroupID = org.ID, owner.group.ID
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := repo_model.LockRepoGroup(ctx, org.ID, owner.group.ID); err != nil {
			return err
		}
		return webhook_model.CreateWebhook(ctx, &w, "")
	})
}

type bitbucketBranchModel struct {
	Development *struct {
		DisplayID string `json:"displayId"`
		IsDefault bool   `json:"isDefault"`
	} `json:"development"`
	Production *struct {
		DisplayID string `json:"displayId"`
	} `json:"production"`
	Types []struct {
		ID     string `json:"id"`
		Prefix string `json:"prefix"`
	} `json:"types"`
}

// planBranchingModel plans the branching model that applies to a Bitbucket repository, its own or its project's, as
// the repository's own branching model: the development branch (none when it is the default branch), the production
// branch and the release prefix. Bitbucket's automatic merging follows only release branches, so the other branch
// types are left out.
func (p *bitbucketPlanner) planBranchingModel(owner *BitbucketImportItem) error {
	var bm bitbucketBranchModel
	if err := p.d.callAPI("branch-utils/1.0/projects/"+p.project.key+"/repos/"+owner.slug+"/branchmodel", nil, &bm); errors.Is(err, errBitbucketNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	model := &repo_model.BranchingModel{}
	if bm.Development != nil && !bm.Development.IsDefault {
		model.DevelopmentBranch = bm.Development.DisplayID
	}
	if bm.Production != nil {
		model.ProductionBranch = bm.Production.DisplayID
	}
	for _, t := range bm.Types {
		if t.ID == "RELEASE" {
			model.ReleasePrefixes = append(model.ReleasePrefixes, t.Prefix)
		}
	}
	item := &BitbucketImportItem{Kind: "branching_model", Bitbucket: owner.Bitbucket + " branching model", Target: owner.Name, bitbucketPermission: bitbucketPermission{parent: owner}}
	model, err := branchworkflow.NormalizeBranchingModel(model)
	if err != nil {
		p.add(item, BitbucketSkipped, "not a valid branch name or prefix")
		return nil
	}
	if len(model.ReleasePrefixes) == 0 && model.ProductionBranch == "" {
		return nil
	}
	name := strings.Join(model.ReleasePrefixes, ", ")
	if model.ProductionBranch != "" {
		name = strings.TrimPrefix(name+", "+model.ProductionBranch, ", ")
	}
	item.Name = util.StripControl(name + " → " + cmp.Or(model.DevelopmentBranch, "default branch"))
	item.branchingModel = model

	status, reason := BitbucketPlanned, ""
	if _, locked, err := branchworkflow.GetOrgModel(p.ctx, p.org.AsUser()); err != nil {
		return err
	} else if locked {
		status, reason = BitbucketSkipped, "the organization enforces a branching model"
	} else if owner.repo != nil {
		eff, err := branchworkflow.GetEffectiveModel(p.ctx, owner.repo)
		if err != nil {
			return err
		}
		if eff.Configured != nil && reflect.DeepEqual(eff.Configured, model) {
			status = BitbucketReused
		} else if eff.Configured != nil {
			status, reason = BitbucketSkipped, "the repository has its own branching model, kept as is"
		}
	}
	p.add(item, status, reason)
	return nil
}
