// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package context

import (
	"context"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	redirect_service "forgejo.org/services/redirect"

	"github.com/go-chi/chi/v5"
	"xorm.io/builder"
)

// A web path of a repository in a project (`org/project/repo`) is first routed like any other path, as if segment
// 2 were a root repository. That always fails, because a project and a root repository never share a name: in
// RepoAssignment (no root repository) or in the router's NotFound handler. Only there, after authentication,
// ResolveRepoGroupPath reads the path as `org/project[/repo]` and, if the viewer can see the target, has
// RepoGroupResolver serve the request a second time on an internal route: `/org/@<repoID>/rest` for a repository,
// `/org/{org}/groups/{id}/rest` for a project. A hidden or missing target keeps the response of the first pass,
// so it is the response of a path that doesn't exist, produced by the same code.

type repoGroupContextKey int

const (
	repoGroupStateKey repoGroupContextKey = iota
	repoGroupMarkKey
)

// repoGroupState is the first pass of a request: its path as received, and the second pass, once the fallback
// decided on one.
type repoGroupState struct {
	segments  []string // escaped path segments as received
	target    string   // internal route path of the second pass
	canonical string   // escaped external path of the second pass
	mark      *RepoGroupMark
	req       *http.Request // the first pass's request, which holds the parsed form
}

// RepoGroupMark is set on the second pass of a request resolved to a repository or project; only
// RepoGroupResolver sets it.
type RepoGroupMark struct {
	OwnerID int64
	GroupID int64
	RepoID  int64
}

// GetRepoGroupMark returns the mark of a resolved request, nil for any other request.
func GetRepoGroupMark(ctx context.Context) *RepoGroupMark {
	mark, _ := ctx.Value(repoGroupMarkKey).(*RepoGroupMark)
	return mark
}

var nameSegment = regexp.MustCompile(`^[-.\w]+$`)

// refusedPath reports a path whose owner, project or repository segment is escaped in a way no name can be:
// an encoded slash, backslash, dot or percent in the owner, anything but [-.\w] in the next two segments
// (`@` included, which only the internal form uses). The answer depends on the request alone.
func refusedPath(segments []string) bool {
	for i, s := range segments {
		if i == 3 || s == "-" {
			break
		}
		if s == "." || s == ".." {
			return true
		}
		if i == 0 {
			lower := strings.ToLower(s)
			if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") || strings.Contains(lower, "%25") {
				return true
			}
		} else if !nameSegment.MatchString(s) {
			return true
		}
	}
	return false
}

// repoGroupWriter drops everything the first pass writes once the fallback chose a second pass.
type repoGroupWriter struct {
	http.ResponseWriter
	st *repoGroupState
}

func (w *repoGroupWriter) WriteHeader(code int) {
	if w.st.target == "" {
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *repoGroupWriter) Write(b []byte) (int, error) {
	if w.st.target != "" {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *repoGroupWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok && w.st.target == "" {
		f.Flush()
	}
}

func (w *repoGroupWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func setEscapedPath(u *url.URL, escaped string) *url.URL {
	c := *u
	c.RawPath = escaped
	c.Path, _ = url.PathUnescape(escaped) // the segments were checked, the rest is as received
	return &c
}

// RepoGroupResolver refuses impossible owner, project and repository segments, accepts `/-/` after a root
// repository, and serves the second pass of a request resolved by ResolveRepoGroupPath.
func RepoGroupResolver(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rctx := chi.RouteContext(req.Context())
		segments := strings.Split(strings.TrimPrefix(rctx.RoutePath, "/"), "/")
		if len(segments) < 2 || segments[1] == "-" || user_model.IsReservedUsername(segments[0]) {
			next.ServeHTTP(w, req)
			return
		}
		if refusedPath(segments) {
			http.Error(w, "Not found.", http.StatusNotFound)
			return
		}

		st := &repoGroupState{segments: segments}
		first := req.WithContext(context.WithValue(req.Context(), repoGroupStateKey, st))
		if len(segments) > 2 && segments[2] == "-" {
			// `/owner/repo/-/rest` is `/owner/repo/rest`
			path := "/" + strings.Join(slices.Delete(slices.Clone(segments), 2, 3), "/")
			rctx.RoutePath = path
			first.URL = setEscapedPath(req.URL, path)
		}
		header := w.Header().Clone()
		next.ServeHTTP(&repoGroupWriter{ResponseWriter: w, st: st}, first)
		if st.target == "" {
			return
		}

		// the first pass charged the rate limit of the route group and the second skips it, so its headers stay
		for _, k := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
			if v := w.Header().Values(k); v != nil {
				header[http.CanonicalHeaderKey(k)] = v
			}
		}
		clear(w.Header())
		maps.Copy(w.Header(), header)
		routes := rctx.Routes
		rctx.Reset()
		rctx.Routes = routes
		rctx.RoutePath = st.target
		// a shallow copy of the first pass's request, so the parsed form and the unread body carry over
		second := st.req.WithContext(context.WithValue(req.Context(), repoGroupMarkKey, st.mark))
		second.URL = setEscapedPath(req.URL, st.canonical)
		next.ServeHTTP(w, second)
	})
}

// gitSuffixes are the git and LFS endpoints, which aren't resolved here.
var gitSuffixes = []string{"info", "git-upload-pack", "git-receive-pack", "git-upload-archive", "objects", "HEAD"}

// ResolveRepoGroupPath is called where a request's path failed as `owner/repo`. If the path names a project or
// a repository in one that the viewer can see, it arranges the second pass and returns true; the response is then
// marked as written and nothing of this pass reaches the client. Otherwise (hidden, missing, any error) it
// changes nothing and returns false.
func (ctx *Context) ResolveRepoGroupPath() bool {
	st, _ := ctx.Req.Context().Value(repoGroupStateKey).(*repoGroupState)
	if st == nil || st.target != "" || ctx.Written() {
		return false
	}
	resolved, err := ctx.resolveRepoGroupPath(st)
	if err != nil {
		log.Error("ResolveRepoGroupPath: %v", err)
		return false
	}
	if !resolved {
		return false
	}
	if ctx.Written() { // a redirect
		return true
	}
	// the second pass removes the uploaded files when it ends, not this one
	multipartForm := ctx.Req.MultipartForm
	ctx.Req.MultipartForm = nil
	st.req = ctx.Req.WithContext(ctx.Req.Context())
	st.req.MultipartForm = multipartForm
	ctx.Resp.WriteHeader(http.StatusOK) // stops this pass; dropped by repoGroupWriter
	return true
}

func (ctx *Context) resolveRepoGroupPath(st *repoGroupState) (bool, error) {
	s := st.segments
	ownerName, err := url.PathUnescape(s[0])
	if err != nil {
		return false, nil
	}
	owner, err := user_model.GetUserByName(ctx, ownerName)
	if user_model.IsErrUserNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if !owner.IsOrganization() {
		return false, nil
	}
	group, err := repo_model.GetRepoGroupByName(ctx, owner.ID, s[1])
	if err == repo_model.ErrRepoGroupNotExist {
		return ctx.redirectRepoGroupPath(owner, s)
	} else if err != nil {
		return false, err
	}

	if len(s) == 2 || s[2] == "-" {
		if visible, err := ctx.CanSeeRepoGroup(owner, group); err != nil || !visible {
			return false, err
		}
		rest := ""
		if len(s) > 3 {
			rest = "/" + strings.Join(s[3:], "/")
		}
		st.target = "/org/" + url.PathEscape(owner.Name) + "/groups/" + strconv.FormatInt(group.ID, 10) + rest
		st.canonical = "/" + strings.Join(s, "/")
		st.mark = &RepoGroupMark{OwnerID: owner.ID, GroupID: group.ID}
		return true, nil
	}

	rest := s[3:]
	if len(rest) > 0 && rest[0] == "-" {
		rest = rest[1:]
	}
	if strings.HasSuffix(s[2], ".git") || len(rest) > 0 && slices.Contains(gitSuffixes, rest[0]) {
		return false, nil
	}
	repo, err := ctx.VisibleGroupRepository(owner, group.Name, s[2])
	if repo_model.IsErrRepoNotExist(err) {
		return ctx.redirectRepoGroupPath(owner, s)
	} else if err != nil {
		return false, err
	}
	restPath := ""
	if len(rest) > 0 {
		restPath = "/" + strings.Join(rest, "/")
	}
	st.target = "/" + url.PathEscape(owner.Name) + "/@" + strconv.FormatInt(repo.ID, 10) + restPath
	st.canonical = "/" + url.PathEscape(owner.Name) + "/" + url.PathEscape(group.Name) + "/" + url.PathEscape(repo.Name) + restPath
	st.mark = &RepoGroupMark{OwnerID: owner.ID, GroupID: group.ID, RepoID: repo.ID}
	return true, nil
}

// redirectRepoGroupPath answers a GET or HEAD of a path of a renamed project, or of a repository renamed or moved
// out of a project, with a 301 to where it is now, if the viewer can see that; otherwise it changes nothing.
func (ctx *Context) redirectRepoGroupPath(owner *user_model.User, s []string) (bool, error) {
	if ctx.Req.Method != http.MethodGet && ctx.Req.Method != http.MethodHead {
		return false, nil
	}
	var link string
	var rest []string
	if len(s) == 2 || s[2] == "-" {
		groupID, err := repo_model.GetRepoGroupRedirect(ctx, owner.ID, s[1])
		if err == repo_model.ErrRepoGroupNotExist {
			return false, nil
		} else if err != nil {
			return false, err
		}
		group, err := repo_model.GetRepoGroupByID(ctx, owner.ID, groupID)
		if err != nil {
			return false, err
		}
		if visible, err := ctx.CanSeeRepoGroup(owner, group); err != nil || !visible {
			return false, err
		}
		link, rest = group.Link(owner.Name), s[2:]
	} else {
		if strings.HasSuffix(s[2], ".git") || len(s) > 3 && slices.Contains(gitSuffixes, s[3]) {
			return false, nil
		}
		repo, err := redirect_service.LookupGroupRepoRedirect(ctx, ctx.Doer, ctx.Authentication.Reducer(), owner, s[1], s[2])
		if repo_model.IsErrRedirectNotExist(err) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		link, rest = repo.Link(), s[3:]
	}
	if len(rest) > 0 {
		link += "/" + strings.Join(rest, "/")
	}
	if ctx.Req.URL.RawQuery != "" {
		link += "?" + ctx.Req.URL.RawQuery
	}
	ctx.Redirect(link, http.StatusMovedPermanently)
	return true, nil
}

// VisibleGroupRepository returns the repository repoName in the project groupName of the owner if the viewer can
// see it, judged like the repository's pages; a hidden repository is not found.
func (ctx *Context) VisibleGroupRepository(owner *user_model.User, groupName, repoName string) (*repo_model.Repository, error) {
	repo, err := repo_model.GetRepositoryByPath(ctx, owner.ID, groupName, repoName)
	if err != nil {
		return nil, err
	}
	repo.Owner = owner
	perm, err := ctx.repoPermission(repo)
	if err != nil {
		return nil, err
	}
	if !perm.HasAccess() {
		return nil, repo_model.ErrRepoNotExist{OwnerName: owner.Name, Name: repoName}
	}
	return repo, nil
}

// CanSeeRepoGroup reports whether the viewer may see the project: a site admin, an acting member of the
// organization, or someone who can see a repository in it.
func (ctx *Context) CanSeeRepoGroup(org *user_model.User, group *repo_model.RepoGroup) (bool, error) {
	if ctx.IsUserSiteAdmin() {
		return true, nil
	}
	if ctx.IsSigned {
		isMember, err := organization.IsOrganizationMember(ctx, org.ID, ctx.Doer.ID)
		if err != nil {
			return false, err
		}
		if isMember {
			blocked, err := ctx.Doer.TwoFactorBlocked(ctx, org)
			if err != nil {
				return false, err
			} else if !blocked {
				return true, nil
			}
		}
	}
	return db.GetEngine(ctx).Where(builder.And(
		repo_model.AccessibleRepositoryCondition(ctx.Doer, unit.TypeInvalid),
		builder.Eq{"owner_id": org.ID, "group_id": group.ID, "trashed_unix": 0},
	)).Exist(new(repo_model.Repository))
}

// markedRepository returns the repository of an internal `@<id>` name, only on the second pass that resolved it.
func markedRepository(ctx *Context, owner *user_model.User, name string) (*repo_model.Repository, error) {
	notExist := repo_model.ErrRepoNotExist{OwnerName: owner.Name, Name: name}
	mark := GetRepoGroupMark(ctx)
	if mark == nil || mark.RepoID == 0 || mark.OwnerID != owner.ID || name != "@"+strconv.FormatInt(mark.RepoID, 10) {
		return nil, notExist
	}
	repo, err := repo_model.GetRepositoryByID(ctx, mark.RepoID)
	if repo_model.IsErrRepoNotExist(err) || err == nil && (repo.OwnerID != owner.ID || repo.GroupID == 0 || repo.GroupID != mark.GroupID) {
		return nil, notExist
	}
	return repo, err
}

// RepoGroupAssignment loads the project of `/org/{org}/groups/{id}` after OrgAssignment; a project of another
// organization, or one the viewer can't see, is not found.
func RepoGroupAssignment(ctx *Context) {
	org := ctx.Org.Organization.AsUser()
	group, err := repo_model.GetRepoGroupByID(ctx, org.ID, ctx.ParamsInt64(":id"))
	if err == repo_model.ErrRepoGroupNotExist {
		ctx.NotFound("GetRepoGroupByID", nil)
		return
	} else if err != nil {
		ctx.ServerError("GetRepoGroupByID", err)
		return
	}
	if visible, err := ctx.CanSeeRepoGroup(org, group); err != nil {
		ctx.ServerError("CanSeeRepoGroup", err)
		return
	} else if !visible {
		ctx.NotFound("CanSeeRepoGroup", nil)
		return
	}
	ctx.Data["RepoGroup"] = group
}
