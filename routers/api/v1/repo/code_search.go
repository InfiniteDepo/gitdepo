// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	code_indexer "forgejo.org/modules/indexer/code"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
)

// SearchCode searches the indexed code of a repository
func SearchCode(ctx *context.APIContext) {
	// swagger:operation GET /repos/{owner}/{repo}/search/code repository repoSearchCode
	// ---
	// summary: Search the code of a repository
	// description: Only the default branch and the branches repo admins chose for code search are indexed.
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
	//   description: the search term, at most 256 characters
	//   type: string
	//   required: true
	// - name: branch
	//   in: query
	//   description: an indexed branch, or "all" for every indexed branch. Default is the default branch.
	//   type: string
	// - name: mode
	//   in: query
	//   description: how to match the term. "fuzzy" needs fuzzy search to be enabled, "regex" a code indexer that supports it.
	//   type: string
	//   enum: [exact, union, fuzzy, regex]
	//   default: exact
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
	//     "$ref": "#/responses/CodeSearchResults"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"
	//   "503":
	//     description: the code indexer is not available

	if !setting.Indexer.RepoIndexerEnabled {
		ctx.Error(http.StatusServiceUnavailable, "", "code search is not enabled")
		return
	}

	keyword := strings.TrimSpace(ctx.FormString("q"))
	if keyword == "" {
		ctx.Error(http.StatusUnprocessableEntity, "", "q is required")
		return
	}

	var mode code_indexer.SearchMode
	switch m := ctx.FormString("mode"); m {
	case "", "exact":
		mode = code_indexer.SearchModeExact
	case "union":
		mode = code_indexer.SearchModeUnion
	case "fuzzy":
		if !setting.Indexer.RepoIndexerEnableFuzzy {
			ctx.Error(http.StatusUnprocessableEntity, "", "fuzzy search is not enabled")
			return
		}
		mode = code_indexer.SearchModeFuzzy
	case "regex":
		if !code_indexer.SupportsRegex() {
			ctx.Error(http.StatusUnprocessableEntity, "", "regex search is not supported by the code indexer")
			return
		}
		mode = code_indexer.SearchModeRegex
	default:
		ctx.Error(http.StatusUnprocessableEntity, "", "unknown mode "+m)
		return
	}

	repo := ctx.Repo().Repository
	branch := ctx.FormString("branch")
	allBranches := branch == "all"
	if branch == repo.DefaultBranch {
		branch = ""
	}
	if branch != "" && !allBranches {
		branches, err := code_indexer.IndexedBranchNames(ctx, repo)
		if err != nil {
			ctx.InternalServerError(err)
			return
		}
		if !slices.Contains(branches, branch) {
			ctx.Error(http.StatusUnprocessableEntity, "", "branch is not indexed")
			return
		}
	}

	listOptions := utils.GetListOptions(ctx)
	total, results, _, err := code_indexer.PerformSearch(ctx, &code_indexer.SearchOptions{
		RepoIDs:     []int64{repo.ID},
		Keyword:     keyword,
		Mode:        mode,
		Branch:      branch,
		AllBranches: allBranches,
		Paginator:   &listOptions,
	})
	if errors.Is(err, code_indexer.ErrInvalidQuery) {
		ctx.Error(http.StatusUnprocessableEntity, "", err.Error())
		return
	} else if err != nil {
		if !code_indexer.IsAvailable(ctx) {
			ctx.Error(http.StatusServiceUnavailable, "", "the code indexer is not available")
			return
		}
		ctx.InternalServerError(err)
		return
	}

	apiResults := make([]api.CodeSearchResult, 0, len(results))
	for _, r := range results {
		if r.Branch == "" || r.Branch == "HEAD" {
			r.Branch = repo.DefaultBranch
		}
		lines := make([]int, 0, len(r.Lines))
		for _, l := range r.Lines {
			lines = append(lines, l.Num)
		}
		apiResults = append(apiResults, api.CodeSearchResult{
			Filename:    r.Filename,
			Branch:      r.Branch,
			CommitID:    r.CommitID,
			Language:    r.Language,
			LineNumbers: lines,
		})
	}

	ctx.SetTotalCountHeader(int64(total))
	ctx.SetLinkHeader(total, listOptions.PageSize)
	ctx.JSON(http.StatusOK, apiResults)
}
