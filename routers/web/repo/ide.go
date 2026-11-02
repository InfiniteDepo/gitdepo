// Copyright 2026 The gitdepo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"cmp"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"forgejo.org/models"
	git_model "forgejo.org/models/git"
	issues_model "forgejo.org/models/issues"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/modules/git"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	files_service "forgejo.org/services/repository/files"
)

const (
	tplIDE base.TplName = "repo/ide"

	// ideTreePageSize entries per tree page, so a large repository's tree arrives in parts
	ideTreePageSize = 5000
	// ideSearchFiles and ideSearchMatchesPerFile cap a search across the repository
	ideSearchFiles          = 200
	ideSearchMatchesPerFile = 50
)

var ideCommitID = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// ideConfig is what the Web IDE needs to start; the IDE reads and writes the repository only through the web routes.
type ideConfig struct {
	RepoLink        string            `json:"repoLink"`
	RepoName        string            `json:"repoName"`
	RefType         string            `json:"refType"`
	RefName         string            `json:"refName"`
	CommitID        string            `json:"commitID"`
	TreePath        string            `json:"treePath"`
	DefaultBranch   string            `json:"defaultBranch"`
	CanCommit       bool              `json:"canCommit"`
	CanCreateBranch bool              `json:"canCreateBranch"`
	CanCreatePull   bool              `json:"canCreatePull"`
	MaxFileSize     int64             `json:"maxFileSize"`
	Theme           string            `json:"theme"`
	ThemeName       string            `json:"themeName"`
	AssetURLPrefix  string            `json:"assetUrlPrefix"`
	Strings         map[string]string `json:"strings"`
}

// MustEnableIDE answers 404 when the Web IDE is off or its files aren't deployed.
func MustEnableIDE(ctx *context.Context) {
	if !setting.IDEAvailable() {
		ctx.NotFound("MustEnableIDE", nil)
	}
}

// ideCanCommit reports whether the doer may commit to the viewed branch, and whether they may create a branch.
func ideCanCommit(ctx *context.Context) (toBranch, newBranch bool) {
	if !ctx.Repo.IsViewBranch || !ctx.Repo.Repository.CanEnableEditor() || ctx.Repo.Repository.IsArchived {
		return false, false
	}
	res, err := ctx.Repo.CanCommitToBranch(ctx, ctx.Doer)
	if err != nil {
		log.Error("CanCommitToBranch: %v", err)
	}
	return res.CanCommitToBranch, ctx.Repo.CanWrite(unit.TypeCode)
}

// WebIDE serves the Web IDE on a branch, tag or commit; it is read-only unless the doer can commit to the branch.
func WebIDE(ctx *context.Context) {
	refType := "branch"
	if ctx.Repo.IsViewTag {
		refType = "tag"
	} else if ctx.Repo.IsViewCommit {
		refType = "commit"
	}
	canCommit, canCreateBranch := ideCanCommit(ctx)
	theme := cmp.Or(ctx.Doer.Theme, setting.UI.DefaultTheme)
	ctx.Data["Title"] = ctx.Tr("repo.ide.title", ctx.Repo.Repository.FullName())
	ctx.Data["IDEConfig"] = ideConfig{
		RepoLink:        ctx.Repo.RepoLink,
		RepoName:        ctx.Repo.Repository.FullName(),
		RefType:         refType,
		RefName:         ctx.Repo.RefName,
		CommitID:        ctx.Repo.CommitID,
		TreePath:        ctx.Repo.TreePath,
		DefaultBranch:   ctx.Repo.Repository.DefaultBranch,
		CanCommit:       canCommit,
		CanCreateBranch: canCreateBranch,
		CanCreatePull:   canCreateBranch && ctx.Repo.Repository.UnitEnabled(ctx, unit.TypePullRequests),
		MaxFileSize:     setting.IDE.MaxFileSize,
		Theme:           ideTheme(theme),
		ThemeName:       theme,
		AssetURLPrefix:  setting.StaticURLPrefix + "/assets",
		Strings: map[string]string{
			"commit":                   ctx.Locale.TrString("repo.ide.commit"),
			"commitMessage":            ctx.Locale.TrString("repo.ide.commit_message"),
			"commitMessagePlaceholder": ctx.Locale.TrString("repo.ide.commit_message_placeholder"),
			"commitToBranch":           ctx.Locale.TrString("repo.ide.commit_to_branch"),
			"commitToNewBranch":        ctx.Locale.TrString("repo.ide.commit_to_new_branch"),
			"targetNewBranch":          ctx.Locale.TrString("repo.ide.target_new_branch"),
			"targetNewBranchPull":      ctx.Locale.TrString("repo.ide.target_new_branch_pull"),
			"newBranchName":            ctx.Locale.TrString("repo.ide.new_branch_name"),
			"committed":                ctx.Locale.TrString("repo.ide.committed"),
			"pullCreated":              ctx.Locale.TrString("repo.ide.pull_created"),
			"openPull":                 ctx.Locale.TrString("repo.ide.open_pull"),
			"nothingToCommit":          ctx.Locale.TrString("repo.ide.nothing_to_commit"),
			"changes":                  ctx.Locale.TrString("repo.ide.changes"),
			"viewChanges":              ctx.Locale.TrString("repo.ide.view_changes"),
			"discard":                  ctx.Locale.TrString("repo.ide.discard"),
			"discardAll":               ctx.Locale.TrString("repo.ide.discard_all"),
			"discardAllConfirm":        ctx.Locale.TrString("repo.ide.discard_all_confirm"),
			"preview":                  ctx.Locale.TrString("repo.ide.preview"),
			"openInRepository":         ctx.Locale.TrString("repo.ide.open_in_repository"),
			"open":                     ctx.Locale.TrString("repo.ide.open"),
			"added":                    ctx.Locale.TrString("repo.ide.added"),
			"modified":                 ctx.Locale.TrString("repo.ide.modified"),
			"deleted":                  ctx.Locale.TrString("repo.ide.deleted"),
			"renamed":                  ctx.Locale.TrString("repo.ide.renamed"),
			"signoff":                  ctx.Locale.TrString("repo.ide.signoff"),
			"readOnly":                 ctx.Locale.TrString("repo.ide.read_only"),
			"readOnlyShort":            ctx.Locale.TrString("repo.ide.read_only_short"),
			"submodule":                ctx.Locale.TrString("repo.ide.submodule"),
			"tooLarge":                 ctx.Locale.TrString("repo.ide.too_large"),
			"lfs":                      ctx.Locale.TrString("repo.ide.lfs"),
			"restoredOnOlderCommit":    ctx.Locale.TrString("repo.ide.restored_on_older_commit"),
		},
	}
	// the workbench needs inline styles and runs WebAssembly (syntax highlighting); the Markdown preview loads
	// gitdepo's own styles, which may come from STATIC_URL_PREFIX
	assets := ideAssetOrigin()
	ctx.Resp.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "+
		"style-src 'self' 'unsafe-inline'"+assets+"; img-src 'self' data: blob:"+assets+"; font-src 'self' data:"+assets+"; "+
		"worker-src 'self' blob:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; "+
		"frame-ancestors 'none'")
	ctx.HTML(http.StatusOK, tplIDE)
}

// ideAssetOrigin is " <origin>" when STATIC_URL_PREFIX serves the assets from another origin
func ideAssetOrigin() string {
	u, err := url.Parse(setting.StaticURLPrefix)
	if err != nil || u.Host == "" {
		return ""
	}
	return " " + u.Scheme + "://" + u.Host
}

// ideTheme maps a gitdepo theme to the VS Code theme family
func ideTheme(theme string) string {
	switch {
	case strings.Contains(theme, "high-contrast"):
		return "high-contrast"
	case strings.HasSuffix(theme, "-dark") || strings.Contains(theme, "-dark-"):
		return "dark"
	case strings.Contains(theme, "auto"):
		return "auto"
	}
	return "light"
}

// WebIDETree lists a commit's tree recursively, one page at a time.
func WebIDETree(ctx *context.Context) {
	sha := ctx.Params("sha")
	if !ideCommitID.MatchString(sha) {
		ctx.NotFound("WebIDETree", nil)
		return
	}
	tree, err := files_service.GetTreeBySHA(ctx, ctx.Repo.Repository, ctx.Repo.GitRepo, sha, max(ctx.FormInt("page"), 1), ideTreePageSize, true)
	if err != nil {
		if models.IsErrSHANotFound(err) {
			ctx.NotFound("GetTreeBySHA", err)
			return
		}
		ctx.ServerError("GetTreeBySHA", err)
		return
	}
	ctx.JSON(http.StatusOK, tree)
}

type ideSearchMatch struct {
	Path  string   `json:"path"`
	Lines []int    `json:"lines"`
	Codes []string `json:"codes"`
}

// WebIDESearch searches a commit's files with git grep (case-insensitive; the IDE narrows the matches itself).
func WebIDESearch(ctx *context.Context) {
	sha := ctx.Params("sha")
	query := ctx.FormTrim("q")
	if !ideCommitID.MatchString(sha) || query == "" {
		ctx.NotFound("WebIDESearch", nil)
		return
	}
	mode := git.FixedGrepMode
	if ctx.FormBool("regexp") {
		mode = git.RegExpGrepMode
	}
	res, err := git.GrepSearch(ctx, ctx.Repo.GitRepo, query, git.GrepOptions{
		RefName:        sha,
		MaxResultLimit: ideSearchFiles,
		MatchesPerFile: ideSearchMatchesPerFile,
		Mode:           mode,
	})
	if err != nil {
		// an invalid regular expression is the usual cause
		log.Debug("GrepSearch: %v", err)
		ctx.JSON(http.StatusUnprocessableEntity, map[string]any{"errorMessage": ctx.Locale.TrString("repo.ide.search_failed")})
		return
	}
	matches := make([]ideSearchMatch, 0, len(res))
	for _, r := range res {
		matches = append(matches, ideSearchMatch{Path: r.Filename, Lines: r.LineNumbers, Codes: r.LineCodes})
	}
	ctx.JSON(http.StatusOK, matches)
}

type ideCommitForm struct {
	LastCommit string                     `json:"last_commit"`
	NewBranch  string                     `json:"new_branch"`
	Message    string                     `json:"message"`
	Signoff    bool                       `json:"signoff"`
	Files      []*api.ChangeFileOperation `json:"files"`
}

func ideCommitError(ctx *context.Context, status int, code, message string) {
	ctx.JSON(status, map[string]any{"error": code, "errorMessage": message})
}

// WebIDECommit commits the IDE's changes as one commit, to the viewed branch or to a new branch made from it.
func WebIDECommit(ctx *context.Context) {
	var form ideCommitForm
	if err := json.NewDecoder(ctx.Req.Body).Decode(&form); err != nil {
		ctx.Error(http.StatusBadRequest)
		return
	}
	form.Message = strings.TrimSpace(form.Message)
	form.NewBranch = strings.TrimSpace(form.NewBranch)
	if form.Message == "" || len(form.Files) == 0 {
		ideCommitError(ctx, http.StatusUnprocessableEntity, "invalid", ctx.Locale.TrString("repo.ide.nothing_to_commit"))
		return
	}

	canCommit, canCreateBranch := ideCanCommit(ctx)
	branch := ctx.Repo.BranchName
	if form.NewBranch != "" {
		if !canCreateBranch {
			ideCommitError(ctx, http.StatusForbidden, "forbidden", ctx.Locale.TrString("repo.ide.cannot_create_branch"))
			return
		}
		if !git.IsValidRefPattern(form.NewBranch) || len(form.NewBranch) > 100 {
			ideCommitError(ctx, http.StatusUnprocessableEntity, "invalid", ctx.Locale.TrString("form.git_ref_name_error", form.NewBranch))
			return
		}
		branch = form.NewBranch
	} else {
		if !canCommit && !canCreateBranch {
			ideCommitError(ctx, http.StatusForbidden, "forbidden", ctx.Locale.TrString("repo.editor.fork_before_edit"))
			return
		}
		if !canCommit {
			ideCommitError(ctx, http.StatusForbidden, "protected", ctx.Locale.TrString("repo.editor.cannot_commit_to_protected_branch", branch))
			return
		}
		if form.LastCommit != ctx.Repo.CommitID {
			ideCommitError(ctx, http.StatusConflict, "branch_moved", ctx.Locale.TrString("repo.ide.branch_moved", branch))
			return
		}
	}

	files := make([]*files_service.ChangeRepoFile, 0, len(form.Files))
	for _, file := range form.Files {
		switch file.Operation {
		case "create", "update", "delete":
		default:
			ctx.Error(http.StatusBadRequest)
			return
		}
		content, err := base64.StdEncoding.DecodeString(file.ContentBase64)
		if err != nil {
			ctx.Error(http.StatusBadRequest)
			return
		}
		files = append(files, &files_service.ChangeRepoFile{
			Operation:     file.Operation,
			TreePath:      file.Path,
			FromTreePath:  file.FromPath,
			ContentReader: strings.NewReader(string(content)),
			SHA:           file.SHA,
		})
	}

	res, err := files_service.ChangeRepoFiles(ctx, ctx.Repo.Repository, ctx.Doer, &files_service.ChangeRepoFilesOptions{
		LastCommitID: form.LastCommit,
		OldBranch:    ctx.Repo.BranchName,
		NewBranch:    branch,
		Message:      form.Message,
		Files:        files,
		Signoff:      form.Signoff,
	})
	if err != nil {
		switch {
		case git.IsErrPushRejected(err):
			rejectErr := err.(*git.ErrPushRejected)
			rejectErr.GenerateMessage()
			message := ctx.Locale.TrString("repo.editor.push_rejected_no_message")
			if rejectErr.Message != "" {
				message = ctx.Locale.TrString("repo.editor.push_rejected") + "\n" + rejectErr.Message
			}
			ideCommitError(ctx, http.StatusForbidden, "rejected", message)
		case models.IsErrUserCannotCommit(err), models.IsErrFilePathProtected(err):
			ideCommitError(ctx, http.StatusForbidden, "protected", err.Error())
		case models.IsErrCommitIDDoesNotMatch(err), models.IsErrSHADoesNotMatch(err):
			ideCommitError(ctx, http.StatusConflict, "branch_moved", ctx.Locale.TrString("repo.ide.branch_moved", ctx.Repo.BranchName))
		case git_model.IsErrBranchAlreadyExists(err):
			ideCommitError(ctx, http.StatusUnprocessableEntity, "branch_exists", ctx.Locale.TrString("repo.editor.branch_already_exists", branch))
		case models.IsErrFilenameInvalid(err), models.IsErrSHAOrCommitIDNotProvided(err), models.IsErrFilePathInvalid(err),
			models.IsErrRepoFileAlreadyExists(err), models.IsErrRepoFileDoesNotExist(err), git_model.IsErrLFSFileLocked(err):
			ideCommitError(ctx, http.StatusUnprocessableEntity, "invalid", err.Error())
		case git_model.IsErrBranchNotExist(err), git.IsErrBranchNotExist(err):
			ideCommitError(ctx, http.StatusNotFound, "branch_missing", ctx.Locale.TrString("repo.editor.branch_does_not_exist", ctx.Repo.BranchName))
		default:
			log.Error("ChangeRepoFiles: %v", err)
			ideCommitError(ctx, http.StatusInternalServerError, "failed", ctx.Locale.TrString("repo.ide.commit_failed"))
		}
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"branch": branch, "commit": res.Commit.SHA})
}

// ideLink is the Web IDE link of a pull request's head branch, or "" unless the doer can push to it
func ideLink(ctx *context.Context, pull *issues_model.PullRequest) string {
	if ctx.Doer == nil || pull.Flow == issues_model.PullRequestFlowAGit || !setting.IDEAvailable() {
		return ""
	}
	if err := pull.LoadHeadRepo(ctx); err != nil || pull.HeadRepo == nil || !pull.HeadRepo.CanEnableEditor() || pull.HeadRepo.IsArchived {
		return ""
	}
	perm, err := access_model.GetUserRepoPermission(ctx, pull.HeadRepo, ctx.Doer)
	if err != nil {
		log.Error("GetUserRepoPermission: %v", err)
		return ""
	}
	if !issues_model.CanMaintainerWriteToBranch(ctx, perm, pull.HeadBranch, ctx.Doer, access_model.GetUserRepoPermission) {
		return ""
	}
	return pull.HeadRepo.Link() + "/-/ide/branch/" + util.PathEscapeSegments(pull.HeadBranch)
}
