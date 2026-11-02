// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"net/http"
	"strconv"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/optional"
	api "forgejo.org/modules/structs"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"
)

// MustEnableDependencyGraph answers 404 while the dependency graph is off for the repository (site, organization
// or repository switch), as if the routes didn't exist.
func MustEnableDependencyGraph(ctx *context.APIContext) {
	if !dependency_service.Enabled(ctx, ctx.Repo().Repository) {
		ctx.NotFound()
	}
}

// ToAPIDependencyScan converts a scan row; nil is a repository that was not scanned yet.
func ToAPIDependencyScan(scan *repo_model.DependencyScan) api.DependencyScan {
	if scan == nil {
		return api.DependencyScan{Status: "pending", SkippedManifests: []api.SkippedManifest{}}
	}
	out := api.DependencyScan{
		Status: scan.Status, Error: scan.Error, CommitSHA: scan.CommitSHA,
		ManifestCount: scan.ManifestCount, DependencyCount: scan.DependencyCount,
		SkippedManifests: []api.SkippedManifest{},
	}
	if scan.ScannedUnix != 0 {
		at := scan.ScannedUnix.AsTime().Truncate(time.Second)
		out.ScannedAt = &at
	}
	for _, m := range scan.SkippedManifests() {
		out.SkippedManifests = append(out.SkippedManifests, api.SkippedManifest{Path: m.Path, Code: m.Code, Lines: m.Lines})
	}
	return out
}

// ListDependencies lists the dependencies of a repository
func ListDependencies(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/dependencies repository repoListDependencies
	// ---
	// summary: List the dependencies the manifests of a repository's default branch declare
	// description: Answers 404 while the dependency graph is turned off. A repository that was not scanned yet is
	//   queued and answers an empty list with the scan status "pending".
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: q
	//   in: query
	//   description: part of the name of the dependency (at most 100 characters)
	//   type: string
	// - name: ecosystem
	//   in: query
	//   description: only this ecosystem (Go, npm, PyPI, Maven, NuGet, crates.io, RubyGems or Packagist)
	//   type: string
	// - name: direct
	//   in: query
	//   description: only the direct (true) or only the transitive (false) dependencies; any value strconv.ParseBool accepts (1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False)
	//   type: boolean
	// - name: manifest
	//   in: query
	//   description: only the dependencies of this manifest (its path in the repository)
	//   type: string
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/DependencyList"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"

	opts := &repo_model.DependencySearchOptions{
		ListOptions: utils.GetListOptions(ctx),
		RepoID:      ctx.Repo().Repository.ID,
		Q:           ctx.FormString("q"),
		Ecosystem:   ctx.FormString("ecosystem"),
		Manifest:    ctx.FormString("manifest"),
	}
	if v := ctx.FormString("direct"); v != "" {
		direct, err := strconv.ParseBool(v)
		if err != nil {
			ctx.Error(http.StatusUnprocessableEntity, "", "direct must be a boolean")
			return
		}
		opts.Direct = optional.Some(direct)
	}
	if opts.Ecosystem != "" && !dependency.IsEcosystem(opts.Ecosystem) {
		ctx.Error(http.StatusUnprocessableEntity, "", "unknown ecosystem")
		return
	}
	if len(opts.Q) > repo_model.MaxDependencyQuery || len(opts.Manifest) > dependency.MaxPathLen {
		ctx.Error(http.StatusUnprocessableEntity, "", "the search text is too long")
		return
	}
	opts.SetDefaultValues()

	scan, err := repo_model.GetRepoDependencyScan(ctx, opts.RepoID)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "GetRepoDependencyScan", err)
		return
	}
	if scan == nil {
		dependency_service.Enqueue(opts.RepoID)
	}
	rows, total, err := db.FindAndCount[repo_model.Dependency](ctx, opts)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "FindAndCount", err)
		return
	}
	resp := api.DependencyList{Scan: ToAPIDependencyScan(scan), Dependencies: make([]*api.Dependency, 0, len(rows))}
	for _, d := range rows {
		resp.Dependencies = append(resp.Dependencies, &api.Dependency{
			Ecosystem: d.Ecosystem, Name: d.Name, Version: d.Version, Requirement: d.Requirement, PURL: dependency.PURL(d.Ecosystem, d.Name, d.Version),
			ManifestPath: d.ManifestPath, Direct: d.Direct, License: d.License,
		})
	}
	ctx.SetLinkHeader(int(total), opts.PageSize)
	ctx.SetTotalCountHeader(total)
	ctx.JSON(http.StatusOK, resp)
}

// GetSBOM downloads the SBOM of a repository
func GetSBOM(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/sbom repository repoGetSBOM
	// ---
	// summary: Download the software bill of materials (SBOM) of a repository's default branch
	// description: Answers 404 while the dependency graph is turned off, and 409 while the repository has not been
	//   scanned yet (it is queued). The document is made from the stored dependencies, as a file to save.
	// produces:
	// - application/json
	// parameters:
	// - name: owner
	//   in: path
	//   description: owner of the repo
	//   type: string
	//   required: true
	// - name: repo
	//   in: path
	//   description: name of the repo
	//   type: string
	//   required: true
	// - name: format
	//   in: query
	//   description: spdx (SPDX 2.3, the default) or cyclonedx (CycloneDX 1.6)
	//   type: string
	//   enum: [spdx, cyclonedx]
	// responses:
	//   "200":
	//     "$ref": "#/responses/SBOM"
	//   "400":
	//     "$ref": "#/responses/error"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     "$ref": "#/responses/error"

	format, ok := dependency_service.ParseFormat(ctx.FormString("format"))
	if !ok {
		ctx.Error(http.StatusBadRequest, "", "format must be spdx or cyclonedx")
		return
	}
	repo := ctx.Repo().Repository
	sbom, err := dependency_service.LoadSBOM(ctx, repo)
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "LoadSBOM", err)
		return
	}
	if sbom == nil {
		dependency_service.EnqueueIfUnscanned(ctx, repo.ID)
		ctx.Error(http.StatusConflict, "", "the repository has not been scanned yet")
		return
	}
	if !common.ServeSBOM(ctx.Base, repo, sbom, format) {
		ctx.Error(http.StatusInternalServerError, "ServeSBOM", "the SBOM could not be made")
	}
}
