// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	vulnerability_model "forgejo.org/models/vulnerability"
	"forgejo.org/modules/base"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/vulnerability"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
	vulnerability_service "forgejo.org/services/vulnerability"
)

// MustEnableDependencyGraph answers 404 while the dependency graph is off for the repository (site, organization
// or repository switch), as if the page didn't exist.
func MustEnableDependencyGraph(ctx *context.Context) {
	if !dependency_service.Enabled(ctx, ctx.Repo.Repository) {
		ctx.NotFound("MustEnableDependencyGraph", nil)
	}
}

// DependenciesSBOM downloads the SBOM of the repository (?format=spdx|cyclonedx), made from the stored dependencies.
func DependenciesSBOM(ctx *context.Context) {
	format, ok := dependency_service.ParseFormat(ctx.FormString("format"))
	if !ok {
		ctx.Error(http.StatusBadRequest, "format must be spdx or cyclonedx")
		return
	}
	repo := ctx.Repo.Repository
	sbom, err := dependency_service.LoadSBOM(ctx, repo)
	if err != nil {
		ctx.ServerError("LoadSBOM", err)
		return
	}
	if sbom == nil {
		dependency_service.EnqueueIfUnscanned(ctx, repo.ID)
		ctx.Error(http.StatusConflict, "the repository has not been scanned yet")
		return
	}
	if !common.ServeSBOM(ctx.Base, repo, sbom, format) {
		ctx.ServerError("ServeSBOM", errors.New("the SBOM could not be made"))
	}
}

// dependencyPageSize is the number of rows on a page of the Dependencies page.
const dependencyPageSize = 50

// maxHintPaths is the number of manifests a "no lock file" hint lists by name.
const maxHintPaths = 10

// unpinnedGroup is the manifests of one ecosystem that were read without a lock file, with the lock files that
// would pin them; Outside is the lock file above them that doesn't list them as its projects ("" if none).
type unpinnedGroup struct {
	Paths   []string // the first maxHintPaths
	More    int
	Count   int
	Locks   string
	Outside string
	PyPI    bool
}

func unpinnedManifests(ctx *context.Context, manifests []repo_model.DependencyFacet) []*unpinnedGroup {
	read := map[string]bool{} // the manifests with rows, the lock files the scan read among them
	for _, m := range manifests {
		read[m.Value] = true
	}
	has := func(p string) bool { return read[p] }
	var out []*unpinnedGroup
	groups := map[[2]string]*unpinnedGroup{}
	for _, m := range manifests {
		f := dependency.FormatForPath(m.Value)
		if f == nil || !f.Unpinned {
			continue
		}
		outside := f.LockAbove(m.Value, has)
		key := [2]string{f.Ecosystem, outside}
		g := groups[key]
		if g == nil {
			locks := f.Locks[len(f.Locks)-1]
			if n := len(f.Locks); n > 1 {
				locks = ctx.Locale.TrString("repo.dependencies.locks_or", strings.Join(f.Locks[:n-1], ", "), locks)
			}
			g = &unpinnedGroup{Locks: locks, Outside: outside, PyPI: f.Ecosystem == dependency.PyPI}
			groups[key] = g
			out = append(out, g)
		}
		if len(g.Paths) < maxHintPaths {
			g.Paths = append(g.Paths, m.Value)
		} else {
			g.More++
		}
		g.Count++
	}
	return out
}

// SetDependencyGraphNav tells the Activity menu whether to show the Dependencies item.
func SetDependencyGraphNav(ctx *context.Context) {
	ctx.Data["DependencyGraphEnabled"] = dependency_service.Enabled(ctx, ctx.Repo.Repository)
}

// Dependencies renders the list of the packages of the default branch, with the filters and the SBOM export.
func Dependencies(ctx *context.Context) {
	repo := ctx.Repo.Repository
	ctx.Data["Title"] = ctx.Tr("repo.dependencies.title")
	ctx.Data["PageIsActivity"] = true
	ctx.Data["PageIsDependencies"] = true
	ctx.Data["SBOMSPDXName"] = dependency_service.SBOMFileName(repo, dependency_service.FormatSPDX)
	ctx.Data["SBOMCycloneDXName"] = dependency_service.SBOMFileName(repo, dependency_service.FormatCycloneDX)
	ctx.Data["SkipCodes"] = repo_model.DependencySkipCodes

	scan, err := repo_model.GetRepoDependencyScan(ctx, repo.ID)
	if err != nil {
		ctx.ServerError("GetRepoDependencyScan", err)
		return
	}
	if scan == nil {
		// the first read queues the scan (see the API); the page says it is running
		dependency_service.Enqueue(repo.ID)
		ctx.HTML(http.StatusOK, tplActivity)
		return
	}
	ctx.Data["Scan"] = scan
	ctx.Data["ScanFailed"] = scan.Status == repo_model.DependencyScanFailed
	ctx.Data["ScanNeverRead"] = scan.CommitSHA == ""
	var skipped, partial []repo_model.SkippedManifest
	for _, m := range scan.SkippedManifests() {
		if m.Code == repo_model.DependencySkipPartial {
			partial = append(partial, m)
		} else {
			skipped = append(skipped, m)
		}
	}
	ctx.Data["Skipped"] = skipped
	ctx.Data["Partial"] = partial
	ctx.Data["ScannedTime"] = scan.ScannedUnix
	if scan.CommitSHA != "" {
		ctx.Data["ShortSHA"] = base.ShortSha(scan.CommitSHA)
		// "rescanning" is true: the scan is queued again (the unique queue dedupes) unless the last one failed
		if head, err := ctx.Repo.GitRepo.GetBranchCommitID(repo.DefaultBranch); err == nil && head != scan.CommitSHA && scan.Status == repo_model.DependencyScanOK {
			ctx.Data["StaleHead"] = base.ShortSha(head)
			dependency_service.Enqueue(repo.ID)
		}
	}
	if scan.CommitSHA == "" {
		ctx.HTML(http.StatusOK, tplActivity)
		return
	}

	facets, err := repo_model.GetDependencyFacets(ctx, repo.ID)
	if err != nil {
		ctx.ServerError("GetDependencyFacets", err)
		return
	}
	ctx.Data["Facets"] = facets
	ctx.Data["TotalPackages"] = facets.Direct + facets.Transitive
	ctx.Data["ManifestsWithPackages"] = len(facets.Manifests)
	ctx.Data["UnpinnedManifests"] = unpinnedManifests(ctx, facets.Manifests)

	opts := &repo_model.DependencySearchOptions{
		ListOptions: db.ListOptions{Page: max(ctx.FormInt("page"), 1), PageSize: dependencyPageSize},
		RepoID:      repo.ID,
	}
	if q := ctx.FormTrim("q"); len(q) <= repo_model.MaxDependencyQuery {
		opts.Q = q
	}
	if eco := ctx.FormString("ecosystem"); eco != "" {
		if !dependency.IsEcosystem(eco) { // as the API does
			ctx.Error(http.StatusUnprocessableEntity, "unknown ecosystem")
			return
		}
		opts.Ecosystem = eco
	}
	relationship := ctx.FormString("relationship")
	switch relationship {
	case "direct":
		opts.Direct = optional.Some(true)
	case "transitive":
		opts.Direct = optional.Some(false)
	default:
		relationship = ""
	}
	if m := ctx.FormString("manifest"); slices.ContainsFunc(facets.Manifests, func(f repo_model.DependencyFacet) bool { return f.Value == m }) {
		opts.Manifest = m
	}
	ctx.Data["Query"], ctx.Data["Ecosystem"], ctx.Data["Relationship"], ctx.Data["Manifest"] = opts.Q, opts.Ecosystem, relationship, opts.Manifest
	ctx.Data["HasFilter"] = opts.Q != "" || opts.Ecosystem != "" || relationship != "" || opts.Manifest != ""

	rows, total, err := db.FindAndCount[repo_model.Dependency](ctx, opts)
	if err != nil {
		ctx.ServerError("FindAndCount", err)
		return
	}
	ctx.Data["Dependencies"] = rows
	// the alert counts per package: for those who may see the alerts only, one query for the page's rows
	if vulnerability_service.CanSeeAlerts(&ctx.Repo.Permission, ctx.IsAlertAuditorView()) && len(rows) > 0 {
		counts, err := vulnerability_model.CountOpenAlerts(ctx, repo.ID)
		if err != nil {
			ctx.ServerError("CountOpenAlerts", err)
			return
		}
		perRow := make(map[int64]int64, len(rows))
		for _, r := range rows {
			perRow[r.ID] = counts[[3]string{r.Ecosystem, vulnerability.NormalizeName(r.Ecosystem, r.Name), r.ManifestPath}]
		}
		ctx.Data["ShowAlertCounts"] = true
		ctx.Data["AlertCounts"] = perRow
	}
	ctx.Data["Total"] = total
	pager := context.NewPagination(int(total), dependencyPageSize, opts.Page, 5)
	for k, v := range map[string]string{"q": opts.Q, "ecosystem": opts.Ecosystem, "relationship": relationship, "manifest": opts.Manifest} {
		if v != "" {
			pager.AddParamString(k, v)
		}
	}
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplActivity)
}
