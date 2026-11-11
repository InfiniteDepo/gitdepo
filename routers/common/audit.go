// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	stdctx "context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	audit_model "forgejo.org/models/audit"
	auth_model "forgejo.org/models/auth"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/httplib"
	"forgejo.org/modules/log"
	"forgejo.org/modules/ratelimit"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	audit_service "forgejo.org/services/audit"
	auth_service "forgejo.org/services/auth"
	"forgejo.org/services/auth/source/db"
	"forgejo.org/services/authz"
	"forgejo.org/services/context"

	"github.com/go-chi/chi/v5"
)

// SetAuditActor stores the request's audit actor right after authentication: it fills in the anonymous actor that
// AuthShared stored before Verify, or stores a new one. It is stored once per request; API sudo changes it in place
// (Actor.SetSudo).
func SetAuditActor(ctx *context.Base, ar auth_service.AuthenticationResult) {
	a := audit_model.ActorFromContext(ctx)
	if a == nil || a.Type != audit_model.ActorAnonymous {
		a = RequestAuditActor(ctx.Req)
		ctx.AppendContextValue(audit_model.ActorContextKey, a)
	}
	a.Credential = ar.Credential()
	if u := ar.User(); u != nil {
		a.Type, a.ID, a.Name = audit_model.ActorUser, u.ID, u.Name
		if u.ID == user_model.ActionsUserID {
			a.Type = audit_model.ActorActions
		}
	}
	switch a.Credential.Type {
	case audit_model.CredentialDeployKey, audit_model.CredentialOrgDeployKey, audit_model.CredentialProjectDeployKey:
		// a deploy-key LFS token carries the repository owner as its user: the key is the actor, as in the hooks
		a.Type, a.ID, a.Name = audit_model.ActorDeployKey, 0, ""
	}
}

// RequestAuditActor is the anonymous actor of req: its client IP, user agent and a new request ID. req must have
// passed ProtocolMiddlewares, so that the client IP comes from trusted proxies only.
func RequestAuditActor(req *http.Request) *audit_model.Actor {
	a := &audit_model.Actor{
		Type:      audit_model.ActorAnonymous,
		UserAgent: audit_model.Text(req.UserAgent(), audit_model.MaxUserAgent), // capped here: actors are copied into aggregates
		RequestID: util.CryptoRandomString(util.RandomStringMedium),            // never the client's X-Request-ID
	}
	if peer, candidates, ok := httplib.AmbiguousClientIP(req); ok {
		a.IP, a.IPAmbiguous, a.IPCandidates = peer, true, slices.Clone(candidates[:min(len(candidates), audit_model.MaxIPCandidates)]) // never the parsed header's array
	} else {
		a.IP = auditPeer(req.RemoteAddr, ClientIP(req))
	}
	return a
}

// WithRequestAuditActor stores the request's anonymous actor for handlers that authenticate by themselves, such as
// the runner RPC, which fill in who it is once they know.
func WithRequestAuditActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req.WithContext(audit_model.WithActor(req.Context(), RequestAuditActor(req))))
	})
}

// UsableAuditReader reports whether the doer may read the audit log: a site admin or an auditor whose account can
// sign in. The callers check how the request was authenticated.
func UsableAuditReader(doer *user_model.User) bool {
	return doer != nil && doer.IsActive && !doer.ProhibitLogin && (doer.IsAdmin || doer.IsAuditor)
}

// ExportAudit streams the audit export of f as "csv" or "json" with its manifest headers; link is the URL path the
// continue link of a truncated export points to.
func ExportAudit(ctx *context.Base, f *audit_service.Filter, format, link string) {
	_, err := audit_service.Export(ctx, ctx.Resp, f, format, audit_service.ExportCap, func(m *audit_service.Manifest) error {
		contentType := "text/csv"
		if format == "json" {
			contentType = "application/json"
		}
		ctx.SetServeHeaders(&context.ServeHeaderOptions{
			ContentType: contentType, ContentTypeCharset: "utf-8",
			Filename: "audit-log-" + m.GeneratedAt.Format("20060102T150405Z") + "." + format,
		})
		h := ctx.Resp.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Audit-Filter", m.FilterHeader())
		h.Set("X-Audit-Generated-At", m.GeneratedAt.Format(time.RFC3339))
		h.Set("X-Audit-Truncated", strconv.FormatBool(m.Truncated))
		h.Set("X-Audit-Sealed-Through", fmt.Sprintf("%d:%s", m.SealedSeq, m.SealedHash))
		if m.Truncated {
			h.Set("X-Audit-Exported-Through", m.Through.Format(time.RFC3339))
			h.Set("Link", "<"+link+"?"+m.Next(f).Encode()+">; rel=\"next\"")
		}
		return nil
	})
	if err == nil {
		return
	}
	if ctx.Resp.WrittenStatus() == 0 {
		ctx.Resp.Header().Del("Content-Disposition")
		log.Error("ExportAudit: %v", err)
		http.Error(ctx.Resp, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Error("ExportAudit: %v", err)
	panic(http.ErrAbortHandler) // abort so the client sees a failed download, not a short file
}

// RecordAuthFailure records a request whose credential was refused, with an anonymous actor: an expired access token
// as expired, a token refused by the scope policy as a refusal, anything else as a failed sign-in. A request the auth
// rate limit refused is recorded by WriteIfRateLimited instead.
func RecordAuthFailure(b *context.Base, v *auth_service.AuthenticationAttemptedIncorrectCredential) {
	SetAuditActor(b, &auth_service.UnauthenticatedResult{})
	var limited *ratelimit.LimitedError
	var expired auth_model.ErrAccessTokenExpired
	subject := v.UserID
	switch {
	case errors.As(v.Error, &limited):
	case errors.As(v.Error, &expired):
		auth_service.RecordExpired(b, audit_model.CredentialAccessToken, expired.ID, expired.UID, expired.Name, expired.Expires)
	case errors.Is(v.Error, authz.ErrScopePolicyEnforced):
		auth_service.RecordRefusal(b, "scope_policy", 0, subject, audit_model.IPKey(audit_model.ActorFromContext(b), 48)+"|"+strconv.FormatInt(subject, 10), nil)
	default:
		if badPassword, ok := errors.AsType[db.ErrUserPasswordInvalid](v.Error); ok {
			subject = badPassword.UID
		} else if prohibited, ok := errors.AsType[user_model.ErrUserProhibitLogin](v.Error); ok {
			subject = prohibited.UID
		}
		auth_service.RecordSignInFailure(b, subject, "bad_credential")
	}
}

// AuthFailureReason is the refusal reason for the server log: the name or email of a failed password sign-in is left
// out (it can be a pasted token), and control characters are replaced so the text can't forge log lines.
func AuthFailureReason(err error) string {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		reasons := make([]string, 0, len(joined.Unwrap()))
		for _, e := range joined.Unwrap() {
			reasons = append(reasons, AuthFailureReason(e))
		}
		return strings.Join(reasons, "; ")
	}
	if user_model.IsErrUserNotExist(err) || user_model.IsErrEmailAddressNotExist(err) ||
		errors.As(err, &db.ErrUserPasswordInvalid{}) || errors.As(err, &db.ErrUserPasswordNotSet{}) {
		return "unknown user or bad password"
	}
	return util.StripControl(err.Error())
}

// CredentialUsed records the first use of the request's credential from its client IP per day; it runs after the
// rate limit and the IP allowlist, so a refused request records nothing here.
func CredentialUsed(method string) func(*context.Context) {
	return func(ctx *context.Context) {
		audit_model.RecordCredentialUsed(ctx, method)
	}
}

// CredentialUsedAPI is CredentialUsed for the API, before sudo changes the actor.
func CredentialUsedAPI(ctx *context.APIContext) {
	audit_model.RecordCredentialUsed(ctx, "api")
}

// APIActivity records, after the handler, every API request of an authenticated actor that is not a read
// (activity.api.write) and every request made with sudo (activity.api.sudo): its method, route pattern and status,
// never the path, query or body. The target is the repository or organization the request was assigned, if it got
// that far, else the actor.
func APIActivity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// deferred: a handler that panics (a refused form, FormRefused) must still be recorded
		defer func() {
			rec := recover()
			ctx := context.GetAPIContext(req)
			ev := audit_model.Event{}
			target := ""
			if r := ctx.Repo(); r != nil && r.Repository != nil && r.HasAccess() {
				ev.OwnerID, ev.GroupID, ev.RepoID, ev.TargetID, ev.TargetName = r.Repository.OwnerID, r.Repository.GroupID, r.Repository.ID, r.Repository.ID, r.Repository.FullName()
				target = "repo"
			} else if o := ctx.Org(); o != nil && o.Organization != nil {
				ev.OwnerID, ev.TargetID, ev.TargetName = o.Organization.ID, o.Organization.ID, o.Organization.Name
				target = "org"
			}
			private := false
			if r := ctx.Repo(); r != nil && r.Repository != nil && r.HasAccess() {
				private = r.Repository.IsPrivate || (r.Owner != nil && r.Owner.Visibility == api.VisibleTypePrivate)
			}
			recordRequest(req, panicStatus(ctx.Resp.WrittenStatus(), rec), ev, target, private && ctx.Data["AuditRecorded"] == nil)
			if rec != nil {
				panic(rec)
			}
		}()
		next.ServeHTTP(w, req)
	})
}

// PackageActivity is APIActivity for the package registries, whose target is the package owner. The PATCH chunks of
// a container blob upload are left out: the upload is recorded by its final PUT.
func PackageActivity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			rec := recover()
			if !(req.Method == http.MethodPatch && strings.HasPrefix(req.URL.Path, "/v2/")) {
				ctx := context.GetWebContext(req)
				ev := audit_model.Event{}
				target := ""
				if ctx.Package != nil && ctx.Package.Owner != nil {
					ev.OwnerID, ev.TargetID, ev.TargetName = ctx.Package.Owner.ID, ctx.Package.Owner.ID, ctx.Package.Owner.Name
					target = "owner"
				}
				recordRequest(req, panicStatus(ctx.Resp.WrittenStatus(), rec), ev, target, false)
			}
			if rec != nil {
				panic(rec)
			}
		}()
		next.ServeHTTP(w, req)
	})
}

// panicStatus is the status to record when the handler panicked: the one already written (FormRefused wrote its
// 400), else 500.
func panicStatus(written int, rec any) int {
	if rec != nil && written == 0 {
		return http.StatusInternalServerError
	}
	return written
}

// recordRequest records the request as a write, a request with sudo or, when readPrivate is set and [audit] LOG_READS is
// on, a read of a private repository, in that order.
func recordRequest(req *http.Request, status int, ev audit_model.Event, target string, readPrivate bool) {
	a := audit_model.ActorFromContext(req.Context())
	if a == nil || a.Type == audit_model.ActorAnonymous {
		return
	}
	switch {
	case req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != http.MethodOptions:
		ev.Action = "activity.api.write"
	case a.SudoByID != 0:
		ev.Action = "activity.api.sudo"
	case readPrivate && setting.Audit.LogReads:
		ev.Action = "activity.api.read"
	default:
		return
	}
	if target == "" {
		ev.OwnerID, ev.TargetID, ev.TargetName, target = a.ID, a.ID, a.Name, "user"
	}
	if status == 0 {
		status = http.StatusOK
	}
	ev.Result = audit_model.ResultSuccess
	if status >= http.StatusBadRequest {
		ev.Result = audit_model.ResultFailure
	}
	ev.SubjectUserID, ev.TargetType = a.ID, "api_request"
	ev.Data = map[string]any{"method": req.Method, "route": chi.RouteContext(req.Context()).RoutePattern(), "status": status, "target": target}
	if req.ContentLength >= 0 {
		ev.Data["bytes"] = req.ContentLength
	}
	if status < http.StatusBadRequest {
		audit_model.RecordActivity(req.Context(), ev)
		return
	}
	// failed requests are aggregated per client, credential, route and status
	key := strings.Join([]string{audit_model.IPKey(a, 48), a.Credential.Type, strconv.FormatInt(a.Credential.ID, 10), req.Method, chi.RouteContext(req.Context()).RoutePattern(), strconv.Itoa(status)}, "|")
	audit_model.RecordAggregated(req.Context(), ev, key)
}

// WebCredential reports whether c is a browser's: a session or reverse proxy authentication. Reads with it are
// recorded only when [audit] LOG_READS is on.
func WebCredential(c audit_model.Credential) bool {
	return c.Type == audit_model.CredentialSession || c.Type == audit_model.CredentialReverseProxy
}

// RecordDownload records, after it was served, a download of kind archive, raw, lfs, release_asset, attachment or sbom
// (activity.download) with the bytes written. It records nothing for an anonymous request, a 304 or an error, nor
// for a web session unless [audit] LOG_READS is on. A redirect (ServeDirect) is recorded without bytes and never
// with its URL. repo may be nil (an unlinked attachment): the target is then the actor. It marks the request, so that
// the API read of it isn't recorded again.
func RecordDownload(ctx *context.Base, repo *repo_model.Repository, kind, object string) {
	a := audit_model.ActorFromContext(ctx)
	status := ctx.Resp.WrittenStatus()
	if a == nil || a.Type == audit_model.ActorAnonymous || status == http.StatusNotModified || status >= http.StatusBadRequest ||
		(WebCredential(a.Credential) && !setting.Audit.LogReads) {
		return
	}
	ev := audit_model.Event{Action: "activity.download", Result: audit_model.ResultSuccess, TargetType: "download"}
	data := map[string]any{"kind": kind, "object": audit_model.Text(util.StripControl(object), 255)}
	if status < http.StatusMultipleChoices {
		data["bytes"] = ctx.Resp.Size()
	}
	ev.Data = data
	if a.Type == audit_model.ActorUser {
		ev.SubjectUserID = a.ID
	}
	switch {
	case repo != nil:
		ev.OwnerID, ev.GroupID, ev.RepoID, ev.TargetID, ev.TargetName = repo.OwnerID, repo.GroupID, repo.ID, repo.ID, repo.FullName()
	case a.ID != 0:
		ev.OwnerID, ev.TargetID, ev.TargetName = a.ID, a.ID, a.Name
	default:
		return // no target: never user 0
	}
	audit_model.RecordActivity(ctx, ev)
	ctx.Data["AuditRecorded"] = true
}

// RecordUpload records, after it succeeded, an upload that no API route record covers (activity.upload): kind is lfs,
// attachment, release or package, op create, update or delete, bytes the size (-1: not known). Nothing for an
// anonymous request or an error. The target is repo, else owner (a package), else the actor.
func RecordUpload(ctx *context.Base, repo *repo_model.Repository, owner *user_model.User, kind, op, object string, bytes int64) {
	a := audit_model.ActorFromContext(ctx)
	if a == nil || a.Type == audit_model.ActorAnonymous || ctx.Resp.WrittenStatus() >= http.StatusBadRequest {
		return
	}
	ev := audit_model.Event{Action: "activity.upload", Result: audit_model.ResultSuccess, TargetType: "upload"}
	ev.Data = map[string]any{"kind": kind, "op": op, "object": audit_model.Text(util.StripControl(object), 255)}
	if bytes >= 0 {
		ev.Data["bytes"] = bytes
	}
	if a.Type == audit_model.ActorUser {
		ev.SubjectUserID = a.ID
	}
	switch {
	case repo != nil:
		ev.OwnerID, ev.GroupID, ev.RepoID, ev.TargetID, ev.TargetName = repo.OwnerID, repo.GroupID, repo.ID, repo.ID, repo.FullName()
	case owner != nil:
		ev.OwnerID, ev.TargetID, ev.TargetName = owner.ID, owner.ID, owner.Name
	case a.ID != 0:
		ev.OwnerID, ev.TargetID, ev.TargetName = a.ID, a.ID, a.Name
	default:
		return // no target: never user 0
	}
	audit_model.RecordActivity(ctx, ev)
}

// RecordGitRead records a read of a repository with git (activity.git.read): service upload-pack or upload-archive,
// protocol ssh or http, bytes for HTTP (-1: not known). It records nothing for an anonymous request, nor for a web
// session unless [audit] LOG_READS is on. A failed read is aggregated per client, credential and repository.
func RecordGitRead(ctx stdctx.Context, repo *repo_model.Repository, service, protocol string, bytes int64, wiki, failed bool) {
	a := audit_model.ActorFromContext(ctx)
	if a == nil || a.Type == audit_model.ActorAnonymous || (WebCredential(a.Credential) && !setting.Audit.LogReads) {
		return
	}
	data := map[string]any{"service": service, "protocol": protocol}
	if bytes >= 0 {
		data["bytes"] = bytes
	}
	if wiki {
		data["wiki"] = true
	}
	ev := audit_model.Event{
		Action: "activity.git.read", Result: audit_model.ResultSuccess, OwnerID: repo.OwnerID, GroupID: repo.GroupID,
		RepoID: repo.ID, TargetType: "git_read", TargetID: repo.ID, TargetName: repo.FullName(), Data: data,
	}
	if a.Type == audit_model.ActorUser {
		ev.SubjectUserID = a.ID
	}
	if !failed {
		audit_model.RecordActivity(ctx, ev)
		return
	}
	ev.Result = audit_model.ResultFailure
	audit_model.RecordAggregated(ctx, ev, strings.Join([]string{audit_model.IPKey(a, 48), a.Credential.Type, strconv.FormatInt(a.Credential.ID, 10), strconv.FormatInt(repo.ID, 10), service, protocol}, "|"))
}
