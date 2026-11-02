// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package private

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	asymkey_model "forgejo.org/models/asymkey"
	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/private"
	"forgejo.org/modules/web"
	app_context "forgejo.org/services/context"
)

// hookActor is who pushes, for the audit log: the pusher, the deploy key or the Actions task the hook was given, with
// the credential the server set for the push (GITEA_AUDIT_CREDENTIAL). That value is checked again here: a type
// that isn't allowed, or a credential that doesn't exist or isn't the pusher's, is recorded as unknown. It never
// decides the push.
func hookActor(ctx context.Context, repo *repo_model.Repository, opts *private.HookOptions) *audit_model.Actor {
	a := &audit_model.Actor{Type: audit_model.ActorUser, ID: opts.UserID, Name: opts.UserName, RequestID: audit_model.Text(opts.AuditRequestID, 32)}
	if addr, err := netip.ParseAddr(opts.AuditIP); err == nil {
		a.IP = addr.Unmap().WithZone("").String()
	}
	switch {
	case opts.DeployKeyKeyID != 0:
		a.Type, a.ID, a.Name = audit_model.ActorDeployKey, 0, ""
		a.Credential = audit_model.Credential{Type: audit_model.CredentialUnknown}
		if key, err := asymkey_model.GetEffectiveDeployKey(ctx, opts.DeployKeyKeyID, repo); err == nil {
			a.Credential = deployKeyCredential(key, repo)
		}
	case opts.UserID == user_model.ActionsUserID:
		a.Type = audit_model.ActorActions
		a.Credential = audit_model.Credential{Type: audit_model.CredentialActionsTask, ID: opts.ActionTaskID}
	default:
		// API sudo: the credential is the sudoer's, so it must be theirs exactly, and they must be a usable admin now
		if sudoBy := opts.AuditSudoByID; sudoBy > 0 && sudoBy != opts.UserID && user_model.IsUsableAdmin(ctx, sudoBy) {
			a.Credential = hookCredential(ctx, sudoBy, opts.AuditCredential)
			if a.Credential.Type != audit_model.CredentialUnknown {
				a.SudoByID = sudoBy
			}
			break
		}
		a.Credential = hookCredential(ctx, opts.UserID, opts.AuditCredential)
	}
	return a
}

func hookCredential(ctx context.Context, uid int64, value string) audit_model.Credential {
	unknown := audit_model.Credential{Type: audit_model.CredentialUnknown}
	typ, idText, ok := strings.Cut(value, ":")
	id, err := strconv.ParseInt(idText, 10, 64)
	if !ok || err != nil {
		return unknown
	}
	c := audit_model.Credential{Type: typ, ID: id, OwnerID: uid}
	switch typ {
	case audit_model.CredentialSession, audit_model.CredentialPassword, audit_model.CredentialReverseProxy:
		c.ID = 0
		return c
	case audit_model.CredentialSystem: // a push the server makes by itself, e.g. a scheduled merge
		return audit_model.Credential{Type: typ}
	case audit_model.CredentialAccessToken:
		if t, has, err := db.GetByID[auth_model.AccessToken](ctx, id); err == nil && has && (t.UID == uid || !t.IsOwnedByUser() && user_model.AccessTokenBotID(t.ID) == uid) {
			c.Name = t.Name
			return c
		}
	case audit_model.CredentialOAuth2Grant:
		if g, has, err := db.GetByID[auth_model.OAuth2Grant](ctx, id); err == nil && has && g.UserID == uid {
			c.AppID = g.ApplicationID
			return c
		}
	case audit_model.CredentialAuthorizedIntegration:
		if i, has, err := db.GetByID[auth_model.AuthorizedIntegration](ctx, id); err == nil && has && i.UserID == uid {
			c.Name = i.Name
			return c
		}
	case audit_model.CredentialSSHKey:
		if k, err := asymkey_model.GetPublicKeyByID(ctx, id); err == nil && k.OwnerID == uid && k.Type != asymkey_model.KeyTypeDeploy {
			c.Name = k.Name
			return c
		}
	}
	return unknown
}

// recordPushRefused records a push to the hook's repository that the hook refused.
func recordPushRefused(ctx *app_context.PrivateContext, opts *private.HookOptions, reason, ref string) {
	repo := ctx.Repo.Repository
	repo_model.RecordPushRefused(audit_model.WithActor(ctx, hookActor(ctx, repo, opts)), repo, reason, audit_model.Text(ref, 255))
}

const (
	auditRefCap    = 100
	auditRefBudget = 24 * 1024 // bytes of JSON, so that an entry stays well under the 32 KB of data
)

// forcedBudget is the time all merge-base checks of one push may take together.
var forcedBudget = 30 * time.Second

type auditRef struct {
	Ref, Old, New string
	Forced        *bool // nil: not known (out of time, or git failed)
}

// checkForced sets Forced on every ref: false for a created or deleted ref, else whether the old commit is not an
// ancestor of the new one (git merge-base --is-ancestor in dir). Refs it doesn't reach within forcedBudget, and refs
// where git exits with anything but 0 or 1, stay nil.
func checkForced(ctx context.Context, dir string, refs []auditRef) {
	ctx, cancel := context.WithTimeout(ctx, forcedBudget)
	defer cancel()
	for i := range refs {
		r := &refs[i]
		if git.IsEmptyCommitID(r.Old, nil) || git.IsEmptyCommitID(r.New, nil) {
			r.Forced = new(false)
			continue
		}
		if ctx.Err() != nil {
			continue
		}
		err := git.NewCommand(ctx, "merge-base", "--is-ancestor").AddDynamicArguments(r.Old, r.New).Run(&git.RunOpts{Dir: dir})
		if err == nil {
			r.Forced = new(false)
		} else if git.IsErrorExitCode(err, 1) {
			r.Forced = new(true)
		}
	}
}

// auditRefList lists refs for the audit entry: forced, unknown and deleted refs first, then the others in push order,
// at most auditRefCap refs in auditRefBudget bytes. more counts the refs left out.
func auditRefList(refs []auditRef) (list []map[string]any, more int) {
	first := func(r auditRef) bool {
		return r.Forced == nil || *r.Forced || git.IsEmptyCommitID(r.New, nil)
	}
	sorted := slices.Clone(refs)
	slices.SortStableFunc(sorted, func(a, b auditRef) int {
		switch {
		case first(a) == first(b):
			return 0
		case first(a):
			return -1
		}
		return 1
	})
	size := 2
	for i, r := range sorted {
		e := map[string]any{"ref": audit_model.Text(r.Ref, 255), "old": audit_model.Text(r.Old, 64), "new": audit_model.Text(r.New, 64), "forced": r.Forced}
		b, _ := json.Marshal(e)
		if len(list) == auditRefCap || size+len(b)+1 > auditRefBudget {
			return list, len(sorted) - i
		}
		size += len(b) + 1
		list = append(list, e)
	}
	return list, 0
}

// HookPushAudit records a push once, after post-receive, with every ref of it except AGit's: refs/for/* and the
// refs/pull/*/head that proc-receive reports for them create or update pull requests rather than refs.
func HookPushAudit(ctx *app_context.PrivateContext) {
	opts := web.GetForm(ctx).(*private.HookOptions)
	repo := loadRepository(ctx)
	if ctx.Written() {
		return
	}
	var refs []auditRef
	for i, name := range opts.RefFullNames {
		if !name.IsFor() && !name.IsPull() && i < len(opts.OldCommitIDs) && i < len(opts.NewCommitIDs) {
			refs = append(refs, auditRef{Ref: name.String(), Old: opts.OldCommitIDs[i], New: opts.NewCommitIDs[i]})
		}
	}
	if len(refs) == 0 {
		ctx.PlainText(http.StatusOK, "ok")
		return
	}

	dir := repo.RepoPath()
	if opts.IsWiki {
		dir = repo.WikiPath()
	}
	checkForced(ctx, dir, refs)
	var forced, unknown, deleted int
	for _, r := range refs {
		switch {
		case r.Forced == nil:
			unknown++
		case *r.Forced:
			forced++
		}
		if git.IsEmptyCommitID(r.New, nil) {
			deleted++
		}
	}
	list, more := auditRefList(refs)
	data := map[string]any{"refs": list, "forced_count": forced, "deleted_count": deleted}
	if more > 0 {
		data["more"] = more
	}
	if unknown > 0 {
		data["forced_unknown"] = unknown
	}
	if opts.IsWiki {
		data["wiki"] = true
	}
	if opts.PushTrigger != "" {
		data["trigger"] = string(opts.PushTrigger)
	}
	audit_model.RecordActivity(audit_model.WithActor(ctx, hookActor(ctx, repo, opts)), audit_model.Event{
		Action: "activity.git.push", Result: audit_model.ResultSuccess, OwnerID: repo.OwnerID, GroupID: repo.GroupID,
		RepoID: repo.ID, TargetType: "git_push", TargetID: repo.ID, TargetName: repo.FullName(), Data: data,
	})
	ctx.PlainText(http.StatusOK, "ok")
}
