// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2018 The Gitea Authors. All rights reserved.
// Copyright 2024 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	go_context "context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"forgejo.org/models"
	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	unit_model "forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/git"
	"forgejo.org/modules/indexer/code"
	"forgejo.org/modules/indexer/issues"
	"forgejo.org/modules/indexer/stats"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/log"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/validation"
	"forgejo.org/modules/web"
	actions_service "forgejo.org/services/actions"
	asymkey_service "forgejo.org/services/asymkey"
	"forgejo.org/services/context"
	"forgejo.org/services/federation"
	"forgejo.org/services/forms"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"
	mirror_service "forgejo.org/services/mirror"
	repo_service "forgejo.org/services/repository"
	wiki_service "forgejo.org/services/wiki"
)

const (
	tplSettingsOptions base.TplName = "repo/settings/options"
	tplSettingsUnits   base.TplName = "repo/settings/units"
	tplCollaboration   base.TplName = "repo/settings/collaboration"
	tplBranches        base.TplName = "repo/settings/branches"
	tplGithooks        base.TplName = "repo/settings/githooks"
	tplGithookEdit     base.TplName = "repo/settings/githook_edit"
	tplDeployKeys      base.TplName = "repo/settings/deploy_keys"
)

// SettingsCtxData is a middleware that sets all the general context data for the
// settings template.
func SettingsCtxData(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("repo.settings.options")
	ctx.Data["PageIsSettingsOptions"] = true
	ctx.Data["ForcePrivate"] = setting.Repository.ForcePrivate
	ctx.Data["TrashRetentionDays"] = setting.Trash.RetentionDays
	ctx.Data["TrashRestoreHelpURL"] = setting.Trash.RestoreHelpURL
	allowed, err := repo_module.AllowedByOrgPolicy(ctx, ctx.Doer, ctx.Repo.Repository, repo_module.OrgPolicyVisibility, nil)
	if err != nil {
		ctx.ServerError("AllowedByOrgPolicy", err)
		return
	}
	ctx.Data["OrgPolicyBlocksVisibility"] = !allowed
	ctx.Data["MirrorsEnabled"] = setting.Mirror.Enabled
	ctx.Data["DisableNewPullMirrors"] = setting.Mirror.DisableNewPull
	ctx.Data["DisableNewPushMirrors"] = setting.Mirror.DisableNewPush
	ctx.Data["DefaultMirrorInterval"] = setting.Mirror.DefaultInterval
	ctx.Data["MinimumMirrorInterval"] = setting.Mirror.MinInterval
	ctx.Data["MaxAvatarFileSize"] = setting.Avatar.MaxFileSize
	ctx.Data["MaxAvatarWidth"] = setting.Avatar.MaxWidth
	ctx.Data["MaxAvatarHeight"] = setting.Avatar.MaxHeight

	signing, _ := asymkey_service.SigningKey(ctx, ctx.Repo.Repository.RepoPath())
	ctx.Data["SigningKeyAvailable"] = len(signing) > 0
	ctx.Data["SigningSettings"] = setting.Repository.Signing
	ctx.Data["CodeIndexerEnabled"] = setting.Indexer.RepoIndexerEnabled
	ctx.Data["MaxIndexedBranches"] = setting.Indexer.MaxIndexedBranchesPerRepo
	if ru, err := ctx.Repo.Repository.GetUnit(ctx, unit_model.TypeCode); err == nil {
		ctx.Data["IndexedBranches"] = ru.CodeConfig().IndexedBranches
	}

	// the places a repository of an organization can move to: its root and its projects
	if ctx.Repo.IsOwner() && ctx.Repo.Owner.IsOrganization() {
		groups, err := repo_model.GetRepoGroupsByOwnerIDs(ctx, []int64{ctx.Repo.Owner.ID})
		if err != nil {
			ctx.ServerError("GetRepoGroupsByOwnerIDs", err)
			return
		}
		ctx.Data["MoveGroups"] = groups
	}

	if ctx.Doer.IsAdmin {
		if setting.Indexer.RepoIndexerEnabled {
			status, err := repo_model.GetIndexerStatus(ctx, ctx.Repo.Repository, repo_model.RepoIndexerTypeCode)
			if err != nil {
				ctx.ServerError("repo.indexer_status", err)
				return
			}
			ctx.Data["CodeIndexerStatus"] = status
		}
		status, err := repo_model.GetIndexerStatus(ctx, ctx.Repo.Repository, repo_model.RepoIndexerTypeStats)
		if err != nil {
			ctx.ServerError("repo.indexer_status", err)
			return
		}
		ctx.Data["StatsIndexerStatus"] = status
	}
	pushMirrors, _, err := repo_model.GetPushMirrorsByRepoID(ctx, ctx.Repo.Repository.ID, db.ListOptions{})
	if err != nil {
		ctx.ServerError("GetPushMirrorsByRepoID", err)
		return
	}
	ctx.Data["PushMirrors"] = pushMirrors
	ctx.Data["CanUseSSHMirroring"] = git.HasSSHExecutable
}

// Units show a repository's unit settings page
func Units(ctx *context.Context) {
	ctx.Data["Title"] = ctx.Tr("repo.settings.units.units")
	ctx.Data["PageIsRepoSettingsUnits"] = true
	ctx.Data["UnitHidden"] = repo_model.HiddenUnits(ctx, ctx.Repo.Owner)

	ctx.HTML(http.StatusOK, tplSettingsUnits)
}

func UnitsPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.RepoUnitSettingForm)
	if ctx.HasError() {
		ctx.Redirect(ctx.Repo.Repository.Link() + "/settings/units")
		return
	}

	repo := ctx.Repo.Repository
	// units the site policy hides are neither enabled nor deleted, so they come back when allowed again
	hidden := repo_model.HiddenUnits(ctx, ctx.Repo.Owner)
	disabled := func(t unit_model.Type) bool { return t.UnitGlobalDisabled() || hidden.Contains(t) }

	var repoChanged bool
	var units []repo_model.RepoUnit
	var deleteUnitTypes []unit_model.Type

	// This section doesn't require repo_name/RepoName to be set in the form, don't show it
	// as an error on the UI for this action
	ctx.Data["Err_RepoName"] = nil

	if repo.CloseIssuesViaCommitInAnyBranch != form.EnableCloseIssuesViaCommitInAnyBranch {
		repo.CloseIssuesViaCommitInAnyBranch = form.EnableCloseIssuesViaCommitInAnyBranch
		repoChanged = true
	}

	if form.EnableCode && !disabled(unit_model.TypeCode) {
		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypeCode,
			Config: repo.MustGetUnit(ctx, unit_model.TypeCode).Config, // keep the indexed branches
		})
	} else if !disabled(unit_model.TypeCode) {
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeCode)
	}

	if form.EnableWiki && form.EnableExternalWiki && !disabled(unit_model.TypeExternalWiki) {
		if !validation.IsValidExternalURL(form.ExternalWikiURL) {
			ctx.Flash.Error(ctx.Tr("repo.settings.external_wiki_url_error"))
			ctx.Redirect(repo.Link() + "/settings/units")
			return
		}

		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypeExternalWiki,
			Config: &repo_model.ExternalWikiConfig{
				ExternalWikiURL: form.ExternalWikiURL,
			},
		})
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeWiki)
	} else if form.EnableWiki && !form.EnableExternalWiki && !disabled(unit_model.TypeWiki) {
		wikiPermissions := repo_model.UnitAccessModeUnset
		if form.GloballyWriteableWiki {
			wikiPermissions = repo_model.UnitAccessModeWrite
		}
		// a form without the wiki source keeps the saved one
		wikiConfig := repo.MustGetUnit(ctx, unit_model.TypeWiki).WikiConfig()
		switch form.WikiSource {
		case "separate":
			wikiConfig = &repo_model.WikiConfig{}
		case repo_model.WikiSourceFolder:
			folder := repo_model.CleanWikiFolder(form.WikiFolder)
			if folder == "" {
				ctx.Flash.Error(ctx.Tr("repo.settings.wiki_folder_error"))
				ctx.Redirect(repo.Link() + "/settings/units")
				return
			}
			if form.WikiBranch != "" && (ctx.Repo.GitRepo == nil || !ctx.Repo.GitRepo.IsBranchExist(form.WikiBranch)) {
				ctx.Flash.Error(ctx.Tr("repo.settings.wiki_branch_error"))
				ctx.Redirect(repo.Link() + "/settings/units")
				return
			}
			wikiConfig = &repo_model.WikiConfig{Source: repo_model.WikiSourceFolder, Folder: folder, Branch: form.WikiBranch}
		}
		units = append(units, repo_model.RepoUnit{
			RepoID:             repo.ID,
			Type:               unit_model.TypeWiki,
			Config:             wikiConfig,
			DefaultPermissions: wikiPermissions,
		})
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeExternalWiki)
	} else {
		if !disabled(unit_model.TypeExternalWiki) {
			deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeExternalWiki)
		}
		if !disabled(unit_model.TypeWiki) {
			deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeWiki)
		}
	}

	if form.EnableIssues && form.EnableExternalTracker && !disabled(unit_model.TypeExternalTracker) {
		if !validation.IsValidExternalURL(form.ExternalTrackerURL) {
			ctx.Flash.Error(ctx.Tr("repo.settings.external_tracker_url_error"))
			ctx.Redirect(repo.Link() + "/settings/units")
			return
		}
		if len(form.TrackerURLFormat) != 0 && !validation.IsValidExternalTrackerURLFormat(form.TrackerURLFormat) {
			ctx.Flash.Error(ctx.Tr("repo.settings.tracker_url_format_error"))
			ctx.Redirect(repo.Link() + "/settings/units")
			return
		}
		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypeExternalTracker,
			Config: &repo_model.ExternalTrackerConfig{
				ExternalTrackerURL:           form.ExternalTrackerURL,
				ExternalTrackerFormat:        form.TrackerURLFormat,
				ExternalTrackerStyle:         form.TrackerIssueStyle,
				ExternalTrackerRegexpPattern: form.ExternalTrackerRegexpPattern,
			},
		})
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeIssues)
	} else if form.EnableIssues && !form.EnableExternalTracker && !disabled(unit_model.TypeIssues) {
		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypeIssues,
			Config: &repo_model.IssuesConfig{
				EnableTimetracker:                form.EnableTimetracker,
				AllowOnlyContributorsToTrackTime: form.AllowOnlyContributorsToTrackTime,
				EnableDependencies:               form.EnableIssueDependencies,
			},
		})
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeExternalTracker)
	} else {
		if !disabled(unit_model.TypeExternalTracker) {
			deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeExternalTracker)
		}
		if !disabled(unit_model.TypeIssues) {
			deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeIssues)
		}
	}

	if form.EnableProjects && !disabled(unit_model.TypeProjects) {
		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypeProjects,
		})
	} else if !disabled(unit_model.TypeProjects) {
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeProjects)
	}

	if form.EnableReleases && !disabled(unit_model.TypeReleases) {
		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypeReleases,
		})
	} else if !disabled(unit_model.TypeReleases) {
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeReleases)
	}

	if form.EnablePackages && !disabled(unit_model.TypePackages) {
		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypePackages,
		})
	} else if !disabled(unit_model.TypePackages) {
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypePackages)
	}

	if form.EnableActions && !disabled(unit_model.TypeActions) {
		// the Actions settings page owns this config; keep it when this form is saved
		actionsUnit := repo_model.RepoUnit{RepoID: repo.ID, Type: unit_model.TypeActions}
		if u, err := repo.GetUnit(ctx, unit_model.TypeActions); err == nil {
			actionsUnit.Config = u.ActionsConfig()
		}
		units = append(units, actionsUnit)
	} else if !disabled(unit_model.TypeActions) {
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypeActions)
	}

	if form.EnablePulls && !disabled(unit_model.TypePullRequests) {
		// the branch workflow page owns the delete-branch setting; keep it when this form is saved
		oldPulls := &repo_model.PullRequestsConfig{}
		if u, err := repo.GetUnit(ctx, unit_model.TypePullRequests); err == nil {
			oldPulls = u.PullRequestsConfig()
		}
		units = append(units, repo_model.RepoUnit{
			RepoID: repo.ID,
			Type:   unit_model.TypePullRequests,
			Config: &repo_model.PullRequestsConfig{
				IgnoreWhitespaceConflicts:     form.PullsIgnoreWhitespace,
				AllowMerge:                    form.PullsAllowMerge,
				AllowRebase:                   form.PullsAllowRebase,
				AllowRebaseMerge:              form.PullsAllowRebaseMerge,
				AllowSquash:                   form.PullsAllowSquash,
				AllowFastForwardOnly:          form.PullsAllowFastForwardOnly,
				AllowManualMerge:              form.PullsAllowManualMerge,
				AutodetectManualMerge:         form.EnableAutodetectManualMerge,
				AllowRebaseUpdate:             form.PullsAllowRebaseUpdate,
				DefaultDeleteBranchAfterMerge: oldPulls.DefaultDeleteBranchAfterMerge,
				DeleteBranchAfterMerge:        oldPulls.DeleteBranchAfterMerge,
				DefaultMergeStyle:             repo_model.MergeStyle(form.PullsDefaultMergeStyle),
				DefaultUpdateStyle:            repo_model.UpdateStyle(form.PullsDefaultUpdateStyle),
				DefaultAllowMaintainerEdit:    form.DefaultAllowMaintainerEdit,
				CancelAutoMergeOnPush:         form.CancelAutoMergeOnPush,
			},
		})
	} else if !disabled(unit_model.TypePullRequests) {
		deleteUnitTypes = append(deleteUnitTypes, unit_model.TypePullRequests)
	}

	if len(units) == 0 {
		ctx.Flash.Error(ctx.Tr("repo.settings.update_settings_no_unit"))
		ctx.Redirect(ctx.Repo.RepoLink + "/settings/units")
		return
	}

	if err := repo_service.UpdateRepositoryUnits(ctx, repo, units, deleteUnitTypes); err != nil {
		ctx.ServerError("UpdateRepositoryUnits", err)
		return
	}
	if repoChanged {
		if err := repo_service.UpdateRepository(ctx, repo, false); err != nil {
			ctx.ServerError("UpdateRepository", err)
			return
		}
	}
	log.Trace("Repository advanced settings updated: %s/%s", ctx.Repo.Owner.Name, repo.Name)

	ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
	ctx.Redirect(ctx.Repo.RepoLink + "/settings/units")
}

// Settings show a repository's settings page
func Settings(ctx *context.Context) {
	ctx.HTML(http.StatusOK, tplSettingsOptions)
}

// SettingsPost response for changes of a repository
// confirmsRepoName tells whether a typed or pasted confirmation names the repository. Mobile keyboards append a blank
// and copying the label can bring zero-width characters, so those and surrounding space are ignored, as is the case.
func confirmsRepoName(input string, repo *repo_model.Repository) bool {
	input = strings.Map(func(r rune) rune {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060':
			return -1
		}
		return r
	}, input)
	return strings.EqualFold(strings.TrimSpace(input), repo.FullName())
}

func SettingsPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.RepoSettingForm)

	ctx.Data["ForcePrivate"] = setting.Repository.ForcePrivate
	ctx.Data["MirrorsEnabled"] = setting.Mirror.Enabled
	ctx.Data["DisableNewPullMirrors"] = setting.Mirror.DisableNewPull
	ctx.Data["DisableNewPushMirrors"] = setting.Mirror.DisableNewPush
	ctx.Data["DefaultMirrorInterval"] = setting.Mirror.DefaultInterval
	ctx.Data["MinimumMirrorInterval"] = setting.Mirror.MinInterval

	signing, _ := asymkey_service.SigningKey(ctx, ctx.Repo.Repository.RepoPath())
	ctx.Data["SigningKeyAvailable"] = len(signing) > 0
	ctx.Data["SigningSettings"] = setting.Repository.Signing
	ctx.Data["CodeIndexerEnabled"] = setting.Indexer.RepoIndexerEnabled

	repo := ctx.Repo.Repository

	switch ctx.FormString("action") {
	case "update":
		if ctx.HasError() {
			ctx.HTML(http.StatusOK, tplSettingsOptions)
			return
		}

		newRepoName := form.RepoName
		// Check if repository name has been changed.
		if repo.LowerName != strings.ToLower(newRepoName) {
			// Close the GitRepo if open
			if ctx.Repo.GitRepo != nil {
				ctx.Repo.GitRepo.Close()
				ctx.Repo.GitRepo = nil
			}
			if err := repo_service.ChangeRepositoryName(ctx, ctx.Doer, repo, newRepoName); err != nil {
				ctx.Data["Err_RepoName"] = true
				switch {
				case repo_model.IsErrRepoAlreadyExist(err):
					ctx.RenderWithErr(ctx.Tr("form.repo_name_been_taken"), tplSettingsOptions, &form)
				case db.IsErrNameReserved(err):
					ctx.RenderWithErr(ctx.Tr("repo.form.name_reserved", err.(db.ErrNameReserved).Name), tplSettingsOptions, &form)
				case repo_model.IsErrRepoFilesAlreadyExist(err):
					ctx.Data["Err_RepoName"] = true
					switch {
					case ctx.IsUserSiteAdmin() || (setting.Repository.AllowAdoptionOfUnadoptedRepositories && setting.Repository.AllowDeleteOfUnadoptedRepositories):
						ctx.RenderWithErr(ctx.Tr("form.repository_files_already_exist.adopt_or_delete"), tplSettingsOptions, form)
					case setting.Repository.AllowAdoptionOfUnadoptedRepositories:
						ctx.RenderWithErr(ctx.Tr("form.repository_files_already_exist.adopt"), tplSettingsOptions, form)
					case setting.Repository.AllowDeleteOfUnadoptedRepositories:
						ctx.RenderWithErr(ctx.Tr("form.repository_files_already_exist.delete"), tplSettingsOptions, form)
					default:
						ctx.RenderWithErr(ctx.Tr("form.repository_files_already_exist"), tplSettingsOptions, form)
					}
				case db.IsErrNamePatternNotAllowed(err):
					ctx.RenderWithErr(ctx.Tr("repo.form.name_pattern_not_allowed", err.(db.ErrNamePatternNotAllowed).Pattern), tplSettingsOptions, &form)
				default:
					ctx.ServerError("ChangeRepositoryName", err)
				}
				return
			}

			log.Trace("Repository name changed: %s/%s -> %s", ctx.Repo.Owner.Name, repo.Name, newRepoName)
		}
		// In case it's just a case change.
		repo.Name = newRepoName
		repo.LowerName = strings.ToLower(newRepoName)
		repo.Description = form.Description
		repo.Website = form.Website
		repo.IsTemplate = form.Template

		// Visibility of forked repository is forced sync with base repository.
		if repo.IsFork {
			form.Private = repo.BaseRepo.IsPrivate || repo.BaseRepo.Owner.Visibility == structs.VisibleTypePrivate
		}

		visibilityChanged := repo.IsPrivate != form.Private
		// when ForcePrivate enabled, you could change public repo to private, but only admin users can change private to public
		if visibilityChanged && setting.Repository.ForcePrivate && !form.Private && !ctx.Doer.IsAdmin {
			ctx.RenderWithErr(ctx.Tr("form.repository_force_private"), tplSettingsOptions, form)
			return
		}
		if visibilityChanged {
			var policyErr repo_module.ErrOrgPolicy
			if err := repo_module.CheckOrgPolicy(ctx, ctx.Doer, repo, repo_module.OrgPolicyVisibility, nil); errors.As(err, &policyErr) {
				ctx.RenderWithErr(ctx.Tr("repo.settings.blocked_by_org_policy", ctx.Tr("org.settings."+policyErr.Policy)), tplSettingsOptions, form)
				return
			} else if err != nil {
				ctx.ServerError("CheckOrgPolicy", err)
				return
			}
		}
		if visibilityChanged && !form.Private {
			if policyErr, ok := errors.AsType[repo_module.ErrPersonalRepoPolicy](repo_module.CheckPersonalRepoPolicy(ctx, ctx.Doer, ctx.Repo.Owner, false)); ok {
				ctx.RenderWithErr(ctx.Tr("repo.personal_repos."+policyErr.Mode), tplSettingsOptions, form)
				return
			}
		}

		repo.IsPrivate = form.Private
		if err := repo_service.UpdateRepository(ctx, repo, visibilityChanged); err != nil {
			ctx.ServerError("UpdateRepository", err)
			return
		}
		log.Trace("Repository basic settings updated: %s/%s", ctx.Repo.Owner.Name, repo.Name)

		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(repo.Link() + "/settings")

	case "federation":
		if !setting.Federation.Enabled {
			ctx.Flash.Info(ctx.Tr("repo.settings.federation_not_enabled"))
			ctx.NotFound("", nil)
			return
		}
		followingRepos := strings.TrimSpace(form.FollowingRepos)
		followingRepos = strings.TrimSuffix(followingRepos, ";")

		maxFollowingRepoStrLength := 2048
		errs := validation.ValidateMaxLen(followingRepos, maxFollowingRepoStrLength, "federationRepos")
		if len(errs) > 0 {
			ctx.Data["ERR_FollowingRepos"] = true
			ctx.Flash.Error(ctx.Tr("repo.form.string_too_long", maxFollowingRepoStrLength))
			ctx.Redirect(repo.Link() + "/settings")
			return
		}

		federationRepoSplit := []string{}
		if followingRepos != "" {
			federationRepoSplit = strings.Split(followingRepos, ";")
		}
		for idx, repo := range federationRepoSplit {
			federationRepoSplit[idx] = strings.TrimSpace(repo)
		}

		if _, _, err := federation.StoreFollowingRepoList(ctx, ctx.Repo.Repository.ID, federationRepoSplit); err != nil {
			ctx.ServerError("UpdateRepository", err)
			return
		}

		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(repo.Link() + "/settings")

	case "mirror":
		if !setting.Mirror.Enabled || !repo.IsMirror || repo.IsArchived {
			ctx.NotFound("", nil)
			return
		}

		pullMirror, err := repo_model.GetMirrorByRepoID(ctx, ctx.Repo.Repository.ID)
		if err == repo_model.ErrMirrorNotExist {
			ctx.NotFound("", nil)
			return
		}
		if err != nil {
			ctx.ServerError("GetMirrorByRepoID", err)
			return
		}
		// This section doesn't require repo_name/RepoName to be set in the form, don't show it
		// as an error on the UI for this action
		ctx.Data["Err_RepoName"] = nil

		interval, err := time.ParseDuration(form.Interval)
		if err != nil || (interval != 0 && interval < setting.Mirror.MinInterval) {
			ctx.Data["Err_Interval"] = true
			ctx.RenderWithErr(ctx.Tr("repo.mirror_interval_invalid"), tplSettingsOptions, &form)
			return
		}

		branchFilter, err := repo_model.NormalizeRefFilter(form.MirrorBranchFilter)
		if err == nil {
			form.MirrorBranchFilter = branchFilter
			form.MirrorTagFilter, err = repo_model.NormalizeRefFilter(form.MirrorTagFilter)
		}
		if err != nil {
			ctx.Data["Err_MirrorBranchFilter"] = true
			ctx.RenderWithErr(ctx.Tr("repo.settings.mirror_filter_invalid", err.Error()), tplSettingsOptions, &form)
			return
		}
		if !repo.IsEmpty && repo_model.CheckDefaultBranchFilter(form.MirrorBranchFilter, repo.DefaultBranch) != nil {
			ctx.Data["Err_MirrorBranchFilter"] = true
			ctx.RenderWithErr(ctx.Tr("repo.settings.mirror_filter_default_branch", repo.DefaultBranch), tplSettingsOptions, &form)
			return
		}
		filtersChanged := pullMirror.BranchFilter != form.MirrorBranchFilter || pullMirror.TagFilter != form.MirrorTagFilter
		pullMirror.BranchFilter = form.MirrorBranchFilter
		pullMirror.TagFilter = form.MirrorTagFilter

		pullMirror.EnablePrune = form.EnablePrune
		pullMirror.Interval = interval
		pullMirror.ScheduleNextUpdate()
		cols := []string{"enable_prune", "interval", "next_update_unix", "branch_filter", "tag_filter"}
		if !pullMirror.HasFilter() && pullMirror.FilterError != "" { // nothing is filtered any more
			pullMirror.FilterError = ""
			cols = append(cols, "filter_error")
		}
		if err := repo_model.UpdateMirrorSettings(ctx, pullMirror, cols...); err != nil {
			ctx.ServerError("UpdateMirror", err)
			return
		}

		u, err := mirror_service.DecryptOrRecoverRemoteAddress(ctx, pullMirror)
		if err != nil {
			ctx.ServerError("DecryptOrRecoverRemoteAddress", err)
			return
		}

		if u.User != nil && form.MirrorPassword == "" && form.MirrorUsername == u.User.Username() {
			form.MirrorPassword, _ = u.User.Password()
		}

		address, err := forms.ParseRemoteAddr(form.MirrorAddress, form.MirrorUsername, form.MirrorPassword)
		if err == nil {
			err = migrations_allowlist.IsMigrateURLAllowed(address, ctx.Doer)
		}
		if err != nil {
			ctx.Data["Err_MirrorAddress"] = true
			handleSettingRemoteAddrError(ctx, err, form)
			return
		}

		if err := mirror_service.SaveRemoteAddress(ctx, pullMirror, address); err != nil {
			ctx.Data["Err_MirrorAddress"] = true
			handleSettingRemoteAddrError(ctx, err, form)
			return
		}

		// Update the unencrypted address stored in the git config, so that future `git fetch` will access the right
		// address. pullMirror.RemoteAddress is the sanitized no-creds version from UpdateRemoteAddress.
		if maybeSanitizedURL, err := pullMirror.SanitizedRemoteAddress(); err != nil {
			ctx.ServerError("SanitizedRemoteAddress", err)
			return
		} else if has, sanitizedURL := maybeSanitizedURL.Get(); !has {
			// SanitizedRemoteAddress must be present after we just stored it
			ctx.ServerError("SanitizedRemoteAddress", err)
			return
		} else if err := mirror_service.UpdateAddress(ctx, pullMirror, sanitizedURL); err != nil {
			ctx.ServerError("UpdateAddress", err)
			return
		}

		form.LFS = form.LFS && setting.LFS.StartServer

		if len(form.LFSEndpoint) > 0 {
			ep := lfs.DetermineEndpoint("", form.LFSEndpoint)
			if ep == nil {
				ctx.Data["Err_LFSEndpoint"] = true
				ctx.RenderWithErr(ctx.Tr("repo.migrate.invalid_lfs_endpoint"), tplSettingsOptions, &form)
				return
			}
			err = migrations_allowlist.IsMigrateURLAllowed(ep.String(), ctx.Doer)
			if err != nil {
				ctx.Data["Err_LFSEndpoint"] = true
				handleSettingRemoteAddrError(ctx, err, form)
				return
			}
		}

		pullMirror.LFS = form.LFS
		pullMirror.LFSEndpoint = form.LFSEndpoint
		if err := repo_model.UpdateMirrorSettings(ctx, pullMirror, "lfs_enabled", "lfs_endpoint"); err != nil {
			ctx.ServerError("UpdateMirror", err)
			return
		}

		if filtersChanged {
			mirror_service.AddPullMirrorToQueue(repo.ID)
		}

		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(repo.Link() + "/settings")

	case "mirror-sync":
		if !setting.Mirror.Enabled || !repo.IsMirror || repo.IsArchived {
			ctx.NotFound("", nil)
			return
		}

		ok, err := quota_model.EvaluateForUser(ctx, repo.OwnerID, quota_model.LimitSubjectSizeReposAll)
		if err != nil {
			ctx.ServerError("quota_model.EvaluateForUser", err)
			return
		}
		if !ok {
			// This section doesn't require repo_name/RepoName to be set in the form, don't show it
			// as an error on the UI for this action
			ctx.Data["Err_RepoName"] = nil

			ctx.RenderWithErr(ctx.Tr("repo.settings.pull_mirror_sync_quota_exceeded"), tplSettingsOptions, &form)
			return
		}

		mirror_service.AddPullMirrorToQueue(repo.ID)

		sanitizedOriginalURL, err := util.SanitizeURL(repo.OriginalURL)
		if err != nil {
			ctx.ServerError("SanitizeURL", err)
			return
		}

		ctx.Flash.Info(ctx.Tr("repo.settings.pull_mirror_sync_in_progress", sanitizedOriginalURL))
		ctx.Redirect(repo.Link() + "/settings")

	case "push-mirror-sync":
		if !setting.Mirror.Enabled {
			ctx.NotFound("", nil)
			return
		}

		m, err := selectPushMirrorByForm(ctx, form, repo)
		if err != nil {
			ctx.NotFound("", nil)
			return
		}

		if err := repo_model.RecordPushMirrorSync(ctx, m); err != nil {
			ctx.ServerError("RecordPushMirrorSync", err)
			return
		}
		mirror_service.AddPushMirrorToQueue(m.ID)

		ctx.Flash.Info(ctx.Tr("repo.settings.push_mirror_sync_in_progress", m.RemoteAddress))
		ctx.Redirect(repo.Link() + "/settings")

	case "push-mirror-update":
		if !setting.Mirror.Enabled || repo.IsArchived {
			ctx.NotFound("", nil)
			return
		}

		// This section doesn't require repo_name/RepoName to be set in the form, don't show it
		// as an error on the UI for this action
		ctx.Data["Err_RepoName"] = nil

		m, err := selectPushMirrorByForm(ctx, form, repo)
		if err != nil {
			ctx.NotFound("", nil)
			return
		}

		interval, err := time.ParseDuration(form.PushMirrorInterval)
		if err != nil || (interval != 0 && interval < setting.Mirror.MinInterval) {
			ctx.RenderWithErr(ctx.Tr("repo.mirror_interval_invalid"), tplSettingsOptions, &forms.RepoSettingForm{})
			return
		}

		m.Interval = interval
		filterChanged := m.BranchFilter != form.PushMirrorBranchFilter
		m.BranchFilter = form.PushMirrorBranchFilter
		if err := db.WithTx(ctx, func(ctx go_context.Context) error {
			if err := repo_model.UpdatePushMirrorSettings(ctx, m, "interval", "branch_filter"); err != nil {
				return err
			}
			if filterChanged {
				// replace `remote.<remote>.push` in the repo config
				return mirror_service.UpdatePushMirrorBranchFilter(ctx, m)
			}
			return nil
		}); err != nil {
			ctx.ServerError("UpdatePushMirrorSettings", err)
			return
		}

		// Background why we are adding it to Queue
		// If we observed its implementation in the context of `push-mirror-sync` where it
		// is evident that pushing to the queue is necessary for updates.
		// So, there are updates within the given interval, it is necessary to update the queue accordingly.
		mirror_service.AddPushMirrorToQueue(m.ID)
		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(repo.Link() + "/settings")

	case "push-mirror-remove":
		if !setting.Mirror.Enabled || repo.IsArchived {
			ctx.NotFound("", nil)
			return
		}

		// This section doesn't require repo_name/RepoName to be set in the form, don't show it
		// as an error on the UI for this action
		ctx.Data["Err_RepoName"] = nil

		m, err := selectPushMirrorByForm(ctx, form, repo)
		if err != nil {
			ctx.NotFound("", nil)
			return
		}

		if err = mirror_service.RemovePushMirrorRemote(ctx, m); err != nil {
			ctx.ServerError("RemovePushMirrorRemote", err)
			return
		}

		if err = repo_model.DeletePushMirrors(ctx, repo_model.PushMirrorOptions{ID: m.ID, RepoID: m.RepoID}); err != nil {
			ctx.ServerError("DeletePushMirrorByID", err)
			return
		}

		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(repo.Link() + "/settings")

	case "push-mirror-add":
		if setting.Mirror.DisableNewPush || repo.IsArchived {
			ctx.NotFound("", nil)
			return
		}

		// This section doesn't require repo_name/RepoName to be set in the form, don't show it
		// as an error on the UI for this action
		ctx.Data["Err_RepoName"] = nil

		interval, err := time.ParseDuration(form.PushMirrorInterval)
		if err != nil || (interval != 0 && interval < setting.Mirror.MinInterval) {
			ctx.Data["Err_PushMirrorInterval"] = true
			ctx.RenderWithErr(ctx.Tr("repo.mirror_interval_invalid"), tplSettingsOptions, &form)
			return
		}

		if form.PushMirrorUseSSH && (form.PushMirrorUsername != "" || form.PushMirrorPassword != "") {
			ctx.Data["Err_PushMirrorUseSSH"] = true
			ctx.RenderWithErr(ctx.Tr("repo.mirror_denied_combination"), tplSettingsOptions, &form)
			return
		}

		if form.PushMirrorUseSSH && !git.HasSSHExecutable {
			ctx.RenderWithErr(ctx.Tr("repo.mirror_use_ssh.not_available"), tplSettingsOptions, &form)
			return
		}

		address, err := forms.ParseRemoteAddr(form.PushMirrorAddress, form.PushMirrorUsername, form.PushMirrorPassword)
		if err == nil {
			err = migrations_allowlist.IsPushMirrorURLAllowed(address, ctx.Doer)
		}
		if err != nil {
			ctx.Data["Err_PushMirrorAddress"] = true
			handleSettingRemoteAddrError(ctx, err, form)
			return
		}

		remoteSuffix := util.CryptoRandomString(util.RandomStringLow)

		remoteAddress, err := util.SanitizeURL(address)
		if err != nil {
			ctx.Data["Err_PushMirrorAddress"] = true
			handleSettingRemoteAddrError(ctx, err, form)
			return
		}

		m := &repo_model.PushMirror{
			RepoID:        repo.ID,
			Repo:          repo,
			RemoteName:    fmt.Sprintf("remote_mirror_%s", remoteSuffix),
			SyncOnCommit:  form.PushMirrorSyncOnCommit,
			Interval:      interval,
			RemoteAddress: remoteAddress,
			BranchFilter:  form.PushMirrorBranchFilter,
		}

		var plainPrivateKey []byte
		if form.PushMirrorUseSSH {
			publicKey, privateKey, err := util.GenerateSSHKeypair()
			if err != nil {
				ctx.ServerError("GenerateSSHKeypair", err)
				return
			}
			plainPrivateKey = privateKey
			m.PublicKey = string(publicKey)
		}

		if err := repo_model.InsertPushMirror(ctx, m, address != remoteAddress); err != nil {
			ctx.ServerError("InsertPushMirror", err)
			return
		}

		if form.PushMirrorUseSSH {
			if err := m.SetPrivatekey(ctx, plainPrivateKey); err != nil {
				ctx.ServerError("SetPrivatekey", err)
				return
			}
		}

		if err := mirror_service.AddPushMirrorRemote(ctx, m, address); err != nil {
			if err := repo_model.DeletePushMirrors(ctx, repo_model.PushMirrorOptions{ID: m.ID, RepoID: m.RepoID}); err != nil {
				log.Error("DeletePushMirrors %v", err)
			}
			ctx.ServerError("AddPushMirrorRemote", err)
			return
		}

		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(repo.Link() + "/settings")

	case "signing":
		changed := false
		trustModel := repo_model.ToTrustModel(form.TrustModel)
		if trustModel != repo.TrustModel {
			repo.TrustModel = trustModel
			changed = true
		}

		if changed {
			if err := repo_service.UpdateRepository(ctx, repo, false); err != nil {
				ctx.ServerError("UpdateRepository", err)
				return
			}
		}
		log.Trace("Repository signing settings updated: %s/%s", ctx.Repo.Owner.Name, repo.Name)

		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(ctx.Repo.RepoLink + "/settings")

	case "admin":
		if !ctx.Doer.IsAdmin {
			ctx.Error(http.StatusForbidden)
			return
		}

		if repo.IsFsckEnabled != form.EnableHealthCheck {
			repo.IsFsckEnabled = form.EnableHealthCheck
		}

		if err := repo_service.UpdateRepository(ctx, repo, false); err != nil {
			ctx.ServerError("UpdateRepository", err)
			return
		}

		log.Trace("Repository admin settings updated: %s/%s", ctx.Repo.Owner.Name, repo.Name)

		ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
		ctx.Redirect(ctx.Repo.RepoLink + "/settings")

	case "admin_index":
		if !ctx.Doer.IsAdmin {
			ctx.Error(http.StatusForbidden)
			return
		}

		switch form.RequestReindexType {
		case "stats":
			if err := stats.UpdateRepoIndexer(ctx.Repo.Repository); err != nil {
				ctx.ServerError("UpdateStatsRepondexer", err)
				return
			}
		case "code":
			if !setting.Indexer.RepoIndexerEnabled {
				ctx.Error(http.StatusForbidden)
				return
			}
			code.UpdateRepoIndexer(ctx.Repo.Repository)
		case "issues":
			issues.UpdateRepoIndexer(ctx, ctx.Repo.Repository.ID)
		default:
			ctx.NotFound("", nil)
			return
		}

		log.Trace("Repository reindex for %s requested: %s/%s", form.RequestReindexType, ctx.Repo.Owner.Name, repo.Name)

		ctx.Flash.Success(ctx.Tr("repo.settings.reindex_requested"))
		ctx.Redirect(ctx.Repo.RepoLink + "/settings")

	case "convert":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}
		if !confirmsRepoName(form.RepoName, repo) {
			ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_repo_name"), tplSettingsOptions, nil)
			return
		}

		if !repo.IsMirror {
			ctx.Error(http.StatusNotFound)
			return
		}

		if err := repo_service.ConvertMirrorToNormalRepo(ctx, ctx.Repo.Repository); err != nil {
			ctx.ServerError("ConvertMirror", err)
			return
		}
		log.Trace("Repository converted from mirror to regular: %s", repo.FullName())
		ctx.Flash.Success(ctx.Tr("repo.settings.convert_succeed"))
		ctx.Redirect(repo.Link())

	case "convert_fork":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}
		if err := repo.LoadOwner(ctx); err != nil {
			ctx.ServerError("Convert Fork", err)
			return
		}
		if !confirmsRepoName(form.RepoName, repo) {
			ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_repo_name"), tplSettingsOptions, nil)
			return
		}

		if !repo.IsFork {
			ctx.Error(http.StatusNotFound)
			return
		}

		if !ctx.Repo.Owner.CanCreateRepo() {
			maxCreationLimit := ctx.Repo.Owner.MaxCreationLimit()
			msg := ctx.TrN(maxCreationLimit, "repo.form.reach_limit_of_creation_1", "repo.form.reach_limit_of_creation_n", maxCreationLimit)
			ctx.Flash.Error(msg)
			ctx.Redirect(repo.Link() + "/settings")
			return
		}

		if err := repo_service.ConvertForkToNormalRepository(ctx, repo); err != nil {
			log.Error("Unable to convert repository %-v from fork. Error: %v", repo, err)
			ctx.ServerError("Convert Fork", err)
			return
		}

		log.Trace("Repository converted from fork to regular: %s", repo.FullName())
		ctx.Flash.Success(ctx.Tr("repo.settings.convert_fork_succeed"))
		ctx.Redirect(repo.Link())

	case "transfer":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}
		if !confirmsRepoName(form.RepoName, repo) {
			ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_repo_name"), tplSettingsOptions, nil)
			return
		}

		newOwner, err := user_model.GetUserByName(ctx, ctx.FormString("new_owner_name"))
		if err != nil {
			if user_model.IsErrUserNotExist(err) {
				ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_owner_name"), tplSettingsOptions, nil)
				return
			}
			ctx.ServerError("IsUserExist", err)
			return
		}

		if newOwner.Type == user_model.UserTypeOrganization {
			if !ctx.Doer.IsAdmin && newOwner.Visibility == structs.VisibleTypePrivate && !organization.OrgFromUser(newOwner).HasMemberWithUserID(ctx, ctx.Doer.ID) {
				// The user shouldn't know about this organization
				ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_owner_name"), tplSettingsOptions, nil)
				return
			}
		}

		// Check the quota of the new owner
		ok, err := quota_model.EvaluateForUser(ctx, newOwner.ID, quota_model.LimitSubjectSizeReposAll)
		if err != nil {
			ctx.ServerError("quota_model.EvaluateForUser", err)
			return
		}
		if !ok {
			ctx.RenderWithErr(ctx.Tr("repo.settings.transfer_quota_exceeded", newOwner.Name), tplSettingsOptions, &form)
			return
		}

		// Close the GitRepo if open
		if ctx.Repo.GitRepo != nil {
			ctx.Repo.GitRepo.Close()
			ctx.Repo.GitRepo = nil
		}

		oldFullname := repo.FullName()
		if err := repo_service.StartRepositoryTransfer(ctx, ctx.Doer, newOwner, repo, nil); err != nil {
			if refusal, refused := ctx.PersonalRepoRefusal(err); refused {
				ctx.RenderWithErr(refusal, tplSettingsOptions, nil)
			} else if organization.IsErrOrgArchived(err) {
				ctx.RenderWithErr(ctx.Tr("org.archived.readonly"), tplSettingsOptions, nil)
			} else if errors.Is(err, user_model.ErrBlockedByUser) {
				ctx.RenderWithErr(ctx.Tr("repo.settings.new_owner_blocked_doer"), tplSettingsOptions, nil)
			} else if repo_model.IsErrRepoAlreadyExist(err) {
				ctx.RenderWithErr(ctx.Tr("repo.settings.new_owner_has_same_repo"), tplSettingsOptions, nil)
			} else if models.IsErrRepoTransferInProgress(err) {
				ctx.RenderWithErr(ctx.Tr("repo.settings.transfer_in_progress"), tplSettingsOptions, nil)
			} else if errors.Is(err, audit_model.ErrNotOwnAct) {
				ctx.RenderWithErr(ctx.Tr("settings.credential_not_own_act"), tplSettingsOptions, nil)
			} else {
				ctx.ServerError("TransferOwnership", err)
			}

			return
		}

		if ctx.Repo.Repository.Status == repo_model.RepositoryPendingTransfer {
			log.Trace("Repository transfer process was started: %s/%s -> %s", ctx.Repo.Owner.Name, repo.Name, newOwner)
			ctx.Flash.Success(ctx.Tr("repo.settings.transfer_started", newOwner.DisplayName()))
		} else {
			log.Trace("Repository transferred: %s -> %s", oldFullname, ctx.Repo.Repository.FullName())
			ctx.Flash.Success(ctx.Tr("repo.settings.transfer_succeed"))
		}
		ctx.Redirect(repo.Link() + "/settings")

	case "move":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}
		// the confirmation holds a path with "/", so the binding error of the repository name field doesn't apply
		delete(ctx.Data, "Err_RepoName")
		if !confirmsRepoName(form.RepoName, repo) {
			ctx.Data["Err_MoveRepoName"] = true
			ctx.RenderWithErr(ctx.Tr("repo.settings.move.confirm_mismatch", repo.FullName()), tplSettingsOptions, nil)
			return
		}
		groupID := ctx.FormInt64("group_id")
		if groupID == repo.GroupID {
			ctx.RenderWithErr(ctx.Tr("repo.settings.move.already_there"), tplSettingsOptions, nil)
			return
		}
		if repo.Status == repo_model.RepositoryBeingMigrated {
			ctx.RenderWithErr(ctx.Tr("repo.settings.move.migrating"), tplSettingsOptions, nil)
			return
		}
		if ctx.Repo.GitRepo != nil {
			ctx.Repo.GitRepo.Close()
			ctx.Repo.GitRepo = nil
		}
		if err := repo_service.MoveRepository(ctx, ctx.Doer, repo, groupID); err != nil {
			switch {
			case repo_model.IsErrRepoAlreadyExist(err), repo_model.IsErrRepoFilesAlreadyExist(err):
				ctx.RenderWithErr(ctx.Tr("repo.settings.move.name_taken"), tplSettingsOptions, nil)
			case organization.IsErrOrgArchived(err):
				ctx.RenderWithErr(ctx.Tr("org.archived.readonly"), tplSettingsOptions, nil)
			case models.IsErrRepoTransferInProgress(err):
				ctx.RenderWithErr(ctx.Tr("repo.settings.transfer_in_progress"), tplSettingsOptions, nil)
			case errors.Is(err, repo_model.ErrRepoGroupNotExist), errors.Is(err, util.ErrPermissionDenied):
				ctx.NotFound("MoveRepository", nil)
			case errors.Is(err, repo_service.ErrRepoMoved):
				ctx.RenderWithErr(ctx.Tr("repo.settings.move.moved_meanwhile"), tplSettingsOptions, nil)
			case errors.Is(err, util.ErrInvalidArgument):
				log.Warn("MoveRepository %s: %v", repo.FullName(), err)
				ctx.RenderWithErr(ctx.Tr("repo.settings.move.failed"), tplSettingsOptions, nil)
			default:
				ctx.ServerError("MoveRepository", err)
			}
			return
		}
		ctx.Flash.Success(ctx.Tr("repo.settings.move.success", repo.FullName()))
		ctx.Redirect(repo.Link() + "/settings")

	case "cancel_transfer":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}

		repoTransfer, err := models.GetPendingRepositoryTransfer(ctx, ctx.Repo.Repository)
		if err != nil {
			if models.IsErrNoPendingTransfer(err) {
				ctx.Flash.Error("repo.settings.transfer_abort_invalid")
				ctx.Redirect(repo.Link() + "/settings")
			} else {
				ctx.ServerError("GetPendingRepositoryTransfer", err)
			}

			return
		}

		if err := repoTransfer.LoadAttributes(ctx); err != nil {
			ctx.ServerError("LoadRecipient", err)
			return
		}

		if err := repo_service.CancelRepositoryTransfer(ctx, ctx.Repo.Repository, false); err != nil {
			ctx.ServerError("CancelRepositoryTransfer", err)
			return
		}

		log.Trace("Repository transfer process was cancelled: %s/%s ", ctx.Repo.Owner.Name, repo.Name)
		ctx.Flash.Success(ctx.Tr("repo.settings.transfer_abort_success", repoTransfer.Recipient.Name))
		ctx.Redirect(repo.Link() + "/settings")

	case "delete":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}
		if !confirmsRepoName(form.RepoName, repo) {
			ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_repo_name"), tplSettingsOptions, nil)
			return
		}

		// Close the gitrepository before doing this.
		if ctx.Repo.GitRepo != nil {
			ctx.Repo.GitRepo.Close()
		}

		if err := repo_service.DeleteRepository(ctx, ctx.Doer, ctx.Repo.Repository, true); err != nil {
			ctx.ServerError("DeleteRepository", err)
			return
		}
		log.Trace("Repository deleted: %s/%s", ctx.Repo.Owner.Name, repo.Name)

		ctx.Flash.Success(ctx.Tr("repo.settings.deletion_success"))
		ctx.Redirect(ctx.Repo.Owner.DashboardLink())

	case "delete-wiki":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}
		if !confirmsRepoName(form.RepoName, repo) {
			ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_repo_name"), tplSettingsOptions, nil)
			return
		}

		err := wiki_service.DeleteWiki(ctx, repo)
		if err != nil {
			log.Error("Delete Wiki: %v", err.Error())
		}
		log.Trace("Repository wiki deleted: %s/%s", ctx.Repo.Owner.Name, repo.Name)

		ctx.Flash.Success(ctx.Tr("repo.settings.wiki_deletion_success"))
		ctx.Redirect(ctx.Repo.RepoLink + "/settings")

	case "rename-wiki-branch":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusNotFound)
			return
		}
		if !confirmsRepoName(form.RepoName, repo) {
			ctx.RenderWithErr(ctx.Tr("form.enterred_invalid_repo_name"), tplSettingsOptions, nil)
			return
		}

		if err := wiki_service.NormalizeWikiBranch(ctx, repo, setting.Repository.DefaultBranch); err != nil {
			log.Error("Normalize Wiki branch: %v", err.Error())
			ctx.Flash.Error(ctx.Tr("repo.settings.wiki_branch_rename_failure"))
			ctx.Redirect(ctx.Repo.RepoLink + "/settings")
			return
		}
		log.Trace("Repository wiki normalized: %s#%s", repo.FullName(), setting.Repository.DefaultBranch)

		ctx.Flash.Success(ctx.Tr("repo.settings.wiki_branch_rename_success"))
		ctx.Redirect(ctx.Repo.RepoLink + "/settings")

	case "archive":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusForbidden)
			return
		}

		if repo.IsMirror {
			ctx.Flash.Error(ctx.Tr("repo.settings.archive.error_ismirror"))
			ctx.Redirect(ctx.Repo.RepoLink + "/settings")
			return
		}

		if err := repo_service.SetArchiveRepoState(ctx, repo, true); err != nil {
			log.Error("Tried to archive a repo: %s", err)
			ctx.Flash.Error(ctx.Tr("repo.settings.archive.error"))
			ctx.Redirect(ctx.Repo.RepoLink + "/settings")
			return
		}

		if err := actions_service.CleanRepoScheduleTasks(ctx, repo, true); err != nil {
			log.Error("CleanRepoScheduleTasks for archived repo %s/%s: %v", ctx.Repo.Owner.Name, repo.Name, err)
		}

		ctx.Flash.Success(ctx.Tr("repo.settings.archive.success"))

		log.Trace("Repository was archived: %s/%s", ctx.Repo.Owner.Name, repo.Name)
		ctx.Redirect(ctx.Repo.RepoLink + "/settings")

	case "unarchive":
		if !ctx.Repo.IsOwner() {
			ctx.Error(http.StatusForbidden)
			return
		}

		if err := repo_service.SetArchiveRepoState(ctx, repo, false); err != nil {
			log.Error("Tried to unarchive a repo: %s", err)
			ctx.Flash.Error(ctx.Tr("repo.settings.unarchive.error"))
			ctx.Redirect(ctx.Repo.RepoLink + "/settings")
			return
		}

		if ctx.Repo.Repository.UnitEnabled(ctx, unit_model.TypeActions) {
			if err := actions_service.DetectAndHandleSchedules(ctx, repo); err != nil {
				log.Error("DetectAndHandleSchedules for un-archived repo %s/%s: %v", ctx.Repo.Owner.Name, repo.Name, err)
			}
		}

		ctx.Flash.Success(ctx.Tr("repo.settings.unarchive.success"))

		log.Trace("Repository was un-archived: %s/%s", ctx.Repo.Owner.Name, repo.Name)
		ctx.Redirect(ctx.Repo.RepoLink + "/settings")

	default:
		ctx.NotFound("", nil)
	}
}

func handleSettingRemoteAddrError(ctx *context.Context, err error, form *forms.RepoSettingForm) {
	if models.IsErrInvalidCloneAddr(err) {
		addrErr := err.(*models.ErrInvalidCloneAddr)
		switch {
		case addrErr.IsProtocolInvalid:
			ctx.RenderWithErr(ctx.Tr("repo.mirror_address_protocol_invalid"), tplSettingsOptions, form)
		case addrErr.IsURLError:
			ctx.RenderWithErr(ctx.Tr("form.url_error", addrErr.Host), tplSettingsOptions, form)
		case addrErr.IsPermissionDenied:
			if addrErr.LocalPath {
				ctx.RenderWithErr(ctx.Tr("repo.migrate.permission_denied"), tplSettingsOptions, form)
			} else {
				ctx.RenderWithErr(ctx.Tr("repo.migrate.permission_denied_blocked"), tplSettingsOptions, form)
			}
		case addrErr.IsInvalidPath:
			ctx.RenderWithErr(ctx.Tr("repo.migrate.invalid_local_path"), tplSettingsOptions, form)
		case addrErr.HasCredentials:
			ctx.RenderWithErr(ctx.Tr("migrate.form.error.url_credentials"), tplSettingsOptions, form)
		default:
			ctx.ServerError("Unknown error", err)
		}
		return
	}
	ctx.RenderWithErr(ctx.Tr("repo.mirror_address_url_invalid"), tplSettingsOptions, form)
}

func selectPushMirrorByForm(ctx *context.Context, form *forms.RepoSettingForm, repo *repo_model.Repository) (*repo_model.PushMirror, error) {
	id, err := strconv.ParseInt(form.PushMirrorID, 10, 64)
	if err != nil {
		return nil, err
	}

	pushMirrors, _, err := repo_model.GetPushMirrorsByRepoID(ctx, repo.ID, db.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, m := range pushMirrors {
		if m.ID == id {
			m.Repo = repo
			return m, nil
		}
	}

	return nil, fmt.Errorf("PushMirror[%v] not associated to repository %v", id, repo)
}

// CodeSearchPost saves the branches, besides the default one, that code search indexes
func CodeSearchPost(ctx *context.Context) {
	form := web.GetForm(ctx).(*forms.RepoCodeSearchForm)
	repo := ctx.Repo.Repository
	redirect := repo.Link() + "/settings"

	if !repo.UnitEnabled(ctx, unit_model.TypeCode) {
		ctx.NotFound("CodeSearchPost", nil)
		return
	}
	if ctx.HasError() {
		ctx.Redirect(redirect)
		return
	}
	patterns, err := code.ParseIndexedBranchPatterns(form.IndexedBranches)
	if err != nil {
		ctx.Flash.Error(ctx.Tr("repo.settings.code_search.invalid_branches", err.Error()))
		ctx.Redirect(redirect)
		return
	}

	codeUnit := repo.MustGetUnit(ctx, unit_model.TypeCode)
	if err := repo_service.UpdateRepositoryUnits(ctx, repo, []repo_model.RepoUnit{{
		RepoID:             repo.ID,
		Type:               unit_model.TypeCode,
		Config:             &repo_model.CodeConfig{IndexedBranches: patterns},
		DefaultPermissions: codeUnit.DefaultPermissions,
	}}, nil); err != nil {
		ctx.ServerError("UpdateRepositoryUnits", err)
		return
	}
	if setting.Indexer.RepoIndexerEnabled {
		code.UpdateRepoIndexer(repo)
	}

	ctx.Flash.Success(ctx.Tr("repo.settings.update_settings_success"))
	ctx.Redirect(redirect)
}
