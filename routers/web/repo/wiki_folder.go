// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPLv3-or-later

package repo

import (
	"bytes"
	"cmp"
	"io"
	"net/http"
	"path"
	"strings"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/models/unit"
	"forgejo.org/modules/base"
	"forgejo.org/modules/git"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/markup"
	"forgejo.org/modules/markup/markdown"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
)

const (
	tplWikiFolder base.TplName = "repo/wiki/folder_view"

	wikiFolderMaxPages   = 500
	wikiFolderMaxEntries = 5000 // tree entries the page list visits, so a big folder with few pages stays cheap
	wikiFolderSidebar    = "_Sidebar.md"
)

// wikiFolderHomes are the home page names, matched case-insensitively in this order
var wikiFolderHomes = []string{"readme.md", "index.md", "home.md"}

// wikiFolder is a folder of the code repository published as the wiki
type wikiFolder struct {
	commit *git.Commit
	tree   *git.Tree
	folder string
	branch string
}

type wikiFolderPage struct {
	Path  string // relative to the folder
	Title string
	Depth int
	Dirs  []wikiFolderDir // directories that start at this page, for the indented list
	blob  *git.Blob
}

type wikiFolderDir struct {
	Name  string
	Depth int
}

// wikiFolderConfig returns the wiki config when the wiki is a folder of the code repository, else nil.
func wikiFolderConfig(ctx *context.Context) *repo_model.WikiConfig {
	if cfg := ctx.Repo.Repository.MustGetUnit(ctx, unit.TypeWiki).WikiConfig(); cfg.FromFolder() {
		return cfg
	}
	return nil
}

// WikiNotFromFolder answers 404 for the wiki routes a folder wiki doesn't have
func WikiNotFromFolder(ctx *context.Context) {
	if wikiFolderConfig(ctx) != nil {
		ctx.NotFound("WikiNotFromFolder", nil)
	}
}

// openWikiFolder returns the configured folder. Otherwise it writes the response and returns nil: 404 without code
// read permission (the folder is code, the Wiki unit alone doesn't allow reading it), else the "folder missing" page,
// or 404 for raw files.
func openWikiFolder(ctx *context.Context, cfg *repo_model.WikiConfig, raw bool) *wikiFolder {
	if !ctx.Repo.CanRead(unit.TypeCode) {
		ctx.NotFound("openWikiFolder", nil)
		return nil
	}
	wf := &wikiFolder{folder: repo_model.CleanWikiFolder(cfg.Folder), branch: cmp.Or(cfg.Branch, ctx.Repo.Repository.DefaultBranch)}
	if wf.folder != "" && ctx.Repo.GitRepo != nil {
		var entry *git.TreeEntry
		var err error
		if wf.commit, err = ctx.Repo.GitRepo.GetBranchCommit(wf.branch); err == nil {
			if entry, err = wf.commit.GetTreeEntryByPath(wf.folder); err == nil && entry.IsDir() {
				wf.tree, err = wf.commit.SubTree(wf.folder)
			}
		}
		if err != nil && !git.IsErrNotExist(err) {
			ctx.ServerError("openWikiFolder", err)
			return nil
		}
		if wf.tree != nil {
			return wf
		}
	}
	if raw {
		ctx.NotFound("openWikiFolder", nil)
		return nil
	}
	ctx.Data["Title"] = ctx.Tr("repo.wiki")
	ctx.Data["WikiFolderMissing"] = true
	ctx.Data["WikiFolder"] = cfg.Folder
	ctx.Data["WikiBranch"] = wf.branch
	ctx.HTML(http.StatusOK, tplWikiFolder)
	return nil
}

// entry returns the regular file at the request path p below the folder, or nil.
func (wf *wikiFolder) entry(p string) (*git.TreeEntry, string) {
	full := path.Join(wf.folder, path.Clean("/"+p))
	if !strings.HasPrefix(full, wf.folder+"/") {
		return nil, ""
	}
	entry, err := wf.commit.GetTreeEntryByPath(full)
	if err != nil || !entry.IsRegular() {
		return nil, ""
	}
	return entry, full
}

func (wf *wikiFolder) renderContext(ctx *context.Context, full string) *markup.RenderContext {
	return &markup.RenderContext{
		Ctx:          ctx,
		RelativePath: full,
		Links: markup.Links{
			Base:       ctx.Repo.RepoLink,
			BranchPath: "branch/" + util.PathEscapeSegments(wf.branch),
			TreePath:   path.Dir(full),
		},
		Metas:   ctx.Repo.Repository.ComposeDocumentMetas(ctx),
		GitRepo: ctx.Repo.GitRepo,
	}
}

func isWikiFolderPage(p string) bool {
	return markup.Type(p) == markdown.MarkupName
}

// listWikiFolderPages appends the Markdown files below tree, at most limit+1 so the caller can tell the list was cut.
// Each visited tree entry takes one from *budget; it stops once that goes below zero. Git sorts tree entries as if
// directory names ended in "/", so this depth-first walk yields the paths in byte order and reads only the
// directories it needs.
func listWikiFolderPages(tree *git.Tree, dir string, limit int, budget *int, pages []wikiFolderPage) ([]wikiFolderPage, error) {
	entries, err := tree.ListEntries()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if *budget--; len(pages) > limit || *budget < 0 {
			break
		}
		p := dir + e.Name()
		switch {
		case e.IsDir():
			sub, err := tree.SubTree(e.Name())
			if err != nil {
				return nil, err
			}
			if pages, err = listWikiFolderPages(sub, p+"/", limit, budget, pages); err != nil {
				return nil, err
			}
		case e.IsRegular() && p != wikiFolderSidebar && isWikiFolderPage(p):
			pages = append(pages, wikiFolderPage{Path: p, Title: strings.TrimSuffix(e.Name(), path.Ext(e.Name())), Depth: strings.Count(p, "/"), blob: e.Blob()})
		}
	}
	return pages, nil
}

// wikiFolderHome returns the home page name in the folder root, or "".
func wikiFolderHome(tree *git.Tree) (string, error) {
	entries, err := tree.ListEntries()
	if err != nil {
		return "", err
	}
	for _, home := range wikiFolderHomes {
		for _, e := range entries {
			if e.IsRegular() && strings.EqualFold(e.Name(), home) {
				return e.Name(), nil
			}
		}
	}
	return "", nil
}

// wikiFolderTitle returns the first "# " heading of content, or fallback.
func wikiFolderTitle(content []byte, fallback string) string {
	for line := range bytes.Lines(content) {
		if title, ok := bytes.CutPrefix(line, []byte("# ")); ok {
			if title = bytes.TrimSpace(title); len(title) > 0 {
				return string(title)
			}
		}
	}
	return fallback
}

func readBlobPrefix(blob *git.Blob, limit int64) ([]byte, error) {
	rc, _, err := blob.NewTruncatedReader(limit)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// loadWikiFolderPages sets the page list and returns false after writing an error.
func loadWikiFolderPages(ctx *context.Context, wf *wikiFolder) ([]wikiFolderPage, bool) {
	budget := wikiFolderMaxEntries
	pages, err := listWikiFolderPages(wf.tree, "", wikiFolderMaxPages, &budget, nil)
	if err != nil {
		ctx.ServerError("listWikiFolderPages", err)
		return nil, false
	}
	if len(pages) > wikiFolderMaxPages || budget < 0 {
		pages = pages[:min(len(pages), wikiFolderMaxPages)]
		ctx.Data["WikiFolderTruncated"] = len(pages)
	}
	// the paths are sorted, so each directory's pages are contiguous: label it once, at its first page
	var prev []string
	for i := range pages {
		dirs := strings.Split(pages[i].Path, "/")
		dirs = dirs[:len(dirs)-1]
		same := 0
		for same < len(dirs) && same < len(prev) && dirs[same] == prev[same] {
			same++
		}
		for d := same; d < len(dirs); d++ {
			pages[i].Dirs = append(pages[i].Dirs, wikiFolderDir{Name: dirs[d], Depth: d})
		}
		prev = dirs
	}
	ctx.Data["WikiFolderPages"] = pages
	return pages, true
}

func wikiFolderPages(ctx *context.Context, cfg *repo_model.WikiConfig) {
	wf := openWikiFolder(ctx, cfg, false)
	if wf == nil {
		return
	}
	pages, ok := loadWikiFolderPages(ctx, wf)
	if !ok {
		return
	}
	// ponytail: one blob read per page (at most 500); cache titles if this list gets slow
	for i := range pages {
		head, err := readBlobPrefix(pages[i].blob, 4096)
		if err != nil {
			ctx.ServerError("readBlobPrefix", err)
			return
		}
		pages[i].Title = wikiFolderTitle(head, pages[i].Title)
	}
	ctx.Data["Title"] = ctx.Tr("repo.wiki.pages")
	ctx.Data["WikiFolderPageList"] = true
	ctx.HTML(http.StatusOK, tplWikiFolder)
}

func wikiFolderView(ctx *context.Context, cfg *repo_model.WikiConfig) {
	wf := openWikiFolder(ctx, cfg, false)
	if wf == nil {
		return
	}
	if _, ok := loadWikiFolderPages(ctx, wf); !ok {
		return
	}

	reqPath := ctx.Params("*")
	if path.Clean("/"+reqPath) == "/" {
		home, err := wikiFolderHome(wf.tree)
		if err != nil {
			ctx.ServerError("wikiFolderHome", err)
			return
		}
		if home == "" {
			ctx.Data["Title"] = ctx.Tr("repo.wiki.pages")
			ctx.Data["WikiFolderPageList"] = true
			ctx.HTML(http.StatusOK, tplWikiFolder)
			return
		}
		reqPath = home
	}
	var entry *git.TreeEntry
	var full string
	for _, p := range []string{reqPath, reqPath + ".md"} {
		if entry, full = wf.entry(p); entry != nil && isWikiFolderPage(full) {
			break
		}
		entry = nil
	}
	if entry == nil {
		ctx.NotFound("wikiFolderView", nil)
		return
	}

	pagePath := strings.TrimPrefix(full, wf.folder+"/")
	ctx.Data["Title"] = strings.TrimSuffix(path.Base(full), path.Ext(full))
	ctx.Data["WikiFolderPage"] = pagePath
	ctx.Data["WikiFolderHistoryLink"] = ctx.Repo.RepoLink + "/commits/branch/" + util.PathEscapeSegments(wf.branch) + "/" + util.PathEscapeSegments(full)
	if ctx.IsSigned && !ctx.Repo.Repository.IsArchived && !ctx.Repo.Repository.IsMirror {
		ctx.Data["WikiFolderEditLink"] = ctx.Repo.RepoLink + "/_edit/" + util.PathEscapeSegments(wf.branch) + "/" + util.PathEscapeSegments(full)
	}

	content, ok := renderWikiFolderFile(ctx, wf, entry.Blob(), full)
	if !ok {
		return
	}
	if content != nil {
		ctx.Data["Title"] = wikiFolderTitle(content, ctx.Data["Title"].(string))
	}

	if pagePath != wikiFolderSidebar {
		if sidebar, sidebarPath := wf.entry(wikiFolderSidebar); sidebar != nil && sidebar.Blob().Size() <= setting.UI.MaxDisplayFileSize {
			data, err := readBlobPrefix(sidebar.Blob(), setting.UI.MaxDisplayFileSize)
			if err != nil {
				ctx.ServerError("readBlobPrefix", err)
				return
			}
			ctx.Data["sidebarEscapeStatus"], ctx.Data["sidebarContent"], err = markupRender(ctx, wf.renderContext(ctx, sidebarPath), bytes.NewReader(data))
			if err != nil {
				ctx.ServerError("Render", err)
				return
			}
		}
	}

	ctx.HTML(http.StatusOK, tplWikiFolder)
}

// renderWikiFolderFile renders a page into ctx.Data and returns its content, nil when it is too large or stored in
// LFS; false after writing an error.
func renderWikiFolderFile(ctx *context.Context, wf *wikiFolder, blob *git.Blob, full string) ([]byte, bool) {
	if blob.Size() > setting.UI.MaxDisplayFileSize {
		ctx.Data["IsFileTooLarge"] = true
		return nil, true
	}
	data, err := readBlobPrefix(blob, setting.UI.MaxDisplayFileSize)
	if err != nil {
		ctx.ServerError("readBlobPrefix", err)
		return nil, false
	}
	if pointer, _ := lfs.ReadPointerFromBuffer(data); pointer.IsValid() {
		ctx.Data["IsLFSFile"] = true
		return nil, true
	}
	ctx.Data["EscapeStatus"], ctx.Data["content"], err = markupRender(ctx, wf.renderContext(ctx, full), bytes.NewReader(data))
	if err != nil {
		ctx.ServerError("Render", err)
		return nil, false
	}
	return data, true
}

func wikiFolderRaw(ctx *context.Context, cfg *repo_model.WikiConfig) {
	wf := openWikiFolder(ctx, cfg, true)
	if wf == nil {
		return
	}
	entry, full := wf.entry(ctx.Params("*"))
	if entry == nil {
		ctx.NotFound("wikiFolderRaw", nil)
		return
	}
	ctx.Repo.TreePath = full
	if err := ServeBlobOrLFS(ctx, entry.Blob(), nil); err != nil {
		ctx.ServerError("ServeBlobOrLFS", err)
	}
}
