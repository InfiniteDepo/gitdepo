// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	gocontext "context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"forgejo.org/models"
	"forgejo.org/models/db"
	"forgejo.org/models/organization"
	"forgejo.org/models/perm"
	access_model "forgejo.org/models/perm/access"
	quota_model "forgejo.org/models/quota"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/graceful"
	"forgejo.org/modules/lfs"
	"forgejo.org/modules/log"
	base "forgejo.org/modules/migration"
	repo_module "forgejo.org/modules/repository"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/web"
	"forgejo.org/modules/web/middleware"
	"forgejo.org/routers/api/v1/utils"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	"forgejo.org/services/forms"
	"forgejo.org/services/migrations"
	migrations_allowlist "forgejo.org/services/migrations/allowlist"
	notify_service "forgejo.org/services/notify"
	repo_service "forgejo.org/services/repository"
)

// Migrate migrate remote git repository to gitea
func Migrate(ctx *context.APIContext) {
	// swagger:operation POST /repos/migrate repository repoMigrate
	// ---
	// summary: Migrate a remote git repository
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/MigrateRepoOptions"
	// responses:
	//   "201":
	//     "$ref": "#/responses/Repository"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "409":
	//     description: The repository with the same name already exists.
	//   "413":
	//     "$ref": "#/responses/quotaExceeded"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.MigrateRepoOptions)

	// get repoOwner
	var (
		repoOwner *user_model.User
		err       error
	)
	if len(form.RepoOwner) != 0 {
		repoOwner, err = user_model.GetUserByName(ctx, form.RepoOwner)
	} else if form.RepoOwnerID != 0 {
		repoOwner, err = user_model.GetUserByID(ctx, form.RepoOwnerID)
	} else {
		repoOwner = ctx.Doer()
	}
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "GetUser", err)
		}
		return
	}

	if ctx.HasAPIError() {
		ctx.Error(http.StatusUnprocessableEntity, "", ctx.GetErrMsg())
		return
	}

	if !ctx.CheckQuota(quota_model.LimitSubjectSizeReposAll, repoOwner.ID, repoOwner.Name) {
		return
	}

	if !ctx.IsUserSiteAdmin() {
		if !repoOwner.IsOrganization() && ctx.Doer().ID != repoOwner.ID {
			ctx.Error(http.StatusForbidden, "", "Given user is not an organization.")
			return
		}

		if repoOwner.IsOrganization() {
			// Check ownership of organization.
			isOwner, err := organization.OrgFromUser(repoOwner).IsActingOwner(ctx, ctx.Doer())
			if err != nil {
				ctx.Error(http.StatusInternalServerError, "IsActingOwner", err)
				return
			} else if !isOwner {
				ctx.Error(http.StatusForbidden, "", "Given user is not owner of organization.")
				return
			}
		}
	}

	// a project is reached only by a token that reaches the whole organization; unknown and foreign ones are one answer
	var groupID int64
	if form.Project != "" {
		if !utils.IsOrgWideToken(ctx) {
			ctx.Error(http.StatusForbidden, "", "This token may not migrate into a project.")
			return
		}
		group, err := repo_model.GetRepoGroupByName(ctx, repoOwner.ID, form.Project)
		if err != nil {
			if errors.Is(err, repo_model.ErrRepoGroupNotExist) {
				ctx.NotFound()
			} else {
				ctx.Error(http.StatusInternalServerError, "GetRepoGroupByName", err)
			}
			return
		}
		groupID = group.ID
	}

	remoteAddr, err := forms.ParseRemoteAddr(form.CloneAddr, form.AuthUsername, form.AuthPassword)
	if err == nil {
		err = migrations_allowlist.IsMigrateURLAllowed(remoteAddr, ctx.Doer())
	}
	if err != nil {
		handleRemoteAddrError(ctx, err)
		return
	}

	gitServiceType := convert.ToGitServiceType(form.Service)

	if form.Mirror && setting.Mirror.DisableNewPull {
		ctx.Error(http.StatusForbidden, "MirrorsGlobalDisabled", errors.New("the site administrator has disabled the creation of new pull mirrors"))
		return
	}

	if setting.Repository.DisableMigrations {
		ctx.Error(http.StatusForbidden, "MigrationsGlobalDisabled", errors.New("the site administrator has disabled migrations"))
		return
	}

	form.LFS = form.LFS && setting.LFS.StartServer

	if form.LFS && len(form.LFSEndpoint) > 0 {
		ep := lfs.DetermineEndpoint("", form.LFSEndpoint)
		if ep == nil {
			ctx.Error(http.StatusInternalServerError, "", ctx.Tr("repo.migrate.invalid_lfs_endpoint"))
			return
		}
		err = migrations_allowlist.IsMigrateURLAllowed(ep.String(), ctx.Doer())
		if err != nil {
			handleRemoteAddrError(ctx, err)
			return
		}
	}

	branchFilter, tagFilter, err := forms.NormalizeMirrorFilters(gitServiceType, form.Mirror, form.MirrorBranchFilter, form.MirrorTagFilter)
	if err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "MirrorFilter", err)
		return
	}

	opts := migrations.MigrateOptions{
		CloneAddr:      remoteAddr,
		RepoName:       form.RepoName,
		Description:    form.Description,
		Private:        form.Private || setting.Repository.ForcePrivate,
		Mirror:         form.Mirror,
		LFS:            form.LFS,
		LFSEndpoint:    form.LFSEndpoint,
		AuthUsername:   form.AuthUsername,
		AuthPassword:   form.AuthPassword,
		AuthToken:      form.AuthToken,
		Wiki:           form.Wiki,
		Issues:         form.Issues,
		Milestones:     form.Milestones,
		Labels:         form.Labels,
		Comments:       form.Issues || form.PullRequests,
		PullRequests:   form.PullRequests,
		Releases:       form.Releases,
		GitServiceType: gitServiceType,
		MirrorInterval: form.MirrorInterval,

		MirrorBranchFilter: branchFilter,
		MirrorTagFilter:    tagFilter,
	}
	if opts.Mirror {
		opts.Issues = false
		opts.Milestones = false
		opts.Labels = false
		opts.Comments = false
		opts.PullRequests = false
		opts.Releases = false
	}

	repo, err := repo_service.CreateRepositoryDirectly(ctx, ctx.Doer(), repoOwner, repo_service.CreateRepoOptions{
		Name:           opts.RepoName,
		Description:    opts.Description,
		OriginalURL:    form.CloneAddr,
		GitServiceType: gitServiceType,
		IsPrivate:      opts.Private || setting.Repository.ForcePrivate,
		IsMirror:       opts.Mirror,
		Status:         repo_model.RepositoryBeingMigrated,
		GroupID:        groupID,
	})
	if err != nil {
		handleMigrateError(ctx, repoOwner, err)
		return
	}

	opts.MigrateToRepoID = repo.ID

	defer func() {
		if e := recover(); e != nil {
			if _, ok := e.(middleware.FormRefused); ok {
				panic(e) // the 400 is written; the request recovery ends the request
			}
			log.Error("PANIC recovered: %v\nStacktrace: %s", e, log.Stack(2))
			err = fmt.Errorf("PANIC recover with error %v", e)
			ctx.Error(http.StatusInternalServerError, "Recovered PANIC with error", err)
		}

		if err == nil {
			notify_service.MigrateRepository(ctx, ctx.Doer(), repoOwner, repo)
			return
		}

		if repo != nil {
			// not cancelled with the request: a dropped client must not leave the being-migrated repository behind
			if errDelete := repo_service.DeleteRepositoryDirectly(gocontext.WithoutCancel(ctx), repo.ID, repo_service.DeleteRepositoryOpts{}); errDelete != nil {
				log.Error("DeleteRepository: %v", errDelete)
			}
		}
	}()

	// not assigned to repo: the failed migration returns nil, and the deferred cleanup needs the created repository
	migrated, err := migrations.MigrateRepository(graceful.GetManager().HammerContext(), ctx.Doer(), repoOwner.Name, opts, nil)
	if err != nil {
		handleMigrateError(ctx, repoOwner, err)
		return
	}
	repo = migrated

	if opts.Releases || opts.Wiki {
		repoOpt := api.EditRepoOption{
			HasReleases: &opts.Releases,
			HasWiki:     &opts.Wiki,
		}

		if unitsErr := updateRepoUnits(ctx, repoOwner.Name, repo, repoOpt); unitsErr != nil { // not err: that would delete the migrated repository
			log.Error("Failed to update units on %s/%s repo. %v", repoOwner.Name, form.RepoName, unitsErr)
		}
	}

	log.Trace("Repository migrated: %s/%s", repoOwner.Name, form.RepoName)
	ctx.JSON(http.StatusCreated, convert.ToRepo(ctx, repo, access_model.Permission{AccessMode: perm.AccessModeAdmin}))
}

func handleMigrateError(ctx *context.APIContext, repoOwner *user_model.User, err error) {
	switch {
	case errors.Is(err, repo_model.ErrRepoGroupNotExist):
		ctx.NotFound()
	case repo_model.IsErrRepoAlreadyExist(err):
		ctx.Error(http.StatusConflict, "", "The repository with the same name already exists.")
	case repo_model.IsErrRepoFilesAlreadyExist(err):
		ctx.Error(http.StatusConflict, "", "Files already exist for this repository. Adopt them or delete them.")
	case migrations.IsRateLimitError(err):
		ctx.Error(http.StatusUnprocessableEntity, "", "Remote visit addressed rate limitation.")
	case migrations.IsTwoFactorAuthError(err):
		ctx.Error(http.StatusUnprocessableEntity, "", "Remote visit required two factors authentication.")
	case errors.As(err, &quota_model.ErrPersonalRepoLimit{}):
		ctx.Error(http.StatusRequestEntityTooLarge, "", err)
	case organization.IsErrOrgArchived(err), errors.As(err, &repo_module.ErrPersonalRepoPolicy{}):
		ctx.Error(http.StatusForbidden, "", err)
	case repo_model.IsErrReachLimitOfRepo(err):
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("You have already reached your limit of %d repositories.", repoOwner.MaxCreationLimit()))
	case db.IsErrNameReserved(err):
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("The username '%s' is reserved.", err.(db.ErrNameReserved).Name))
	case db.IsErrNameCharsNotAllowed(err):
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("The username '%s' contains invalid characters.", err.(db.ErrNameCharsNotAllowed).Name))
	case db.IsErrNamePatternNotAllowed(err):
		ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("The pattern '%s' is not allowed in a username.", err.(db.ErrNamePatternNotAllowed).Pattern))
	case models.IsErrInvalidCloneAddr(err):
		ctx.Error(http.StatusUnprocessableEntity, "", err)
	case base.IsErrNotSupported(err):
		ctx.Error(http.StatusUnprocessableEntity, "", err)
	default:
		err = util.SanitizeErrorCredentialURLs(err)
		if strings.Contains(err.Error(), "Authentication failed") ||
			strings.Contains(err.Error(), "Bad credentials") ||
			strings.Contains(err.Error(), "could not read Username") {
			ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("Authentication failed: %v.", err))
		} else if strings.Contains(err.Error(), "fatal:") {
			ctx.Error(http.StatusUnprocessableEntity, "", fmt.Sprintf("Migration failed: %v.", err))
		} else {
			ctx.Error(http.StatusInternalServerError, "MigrateRepository", err)
		}
	}
}

func handleRemoteAddrError(ctx *context.APIContext, err error) {
	if models.IsErrInvalidCloneAddr(err) {
		addrErr := err.(*models.ErrInvalidCloneAddr)
		switch {
		case addrErr.IsURLError:
			ctx.Error(http.StatusUnprocessableEntity, "", err)
		case addrErr.IsPermissionDenied:
			if addrErr.LocalPath {
				ctx.Error(http.StatusUnprocessableEntity, "", "You are not allowed to import local repositories.")
			} else {
				ctx.Error(http.StatusUnprocessableEntity, "", "You can not import from disallowed hosts.")
			}
		case addrErr.IsInvalidPath:
			ctx.Error(http.StatusUnprocessableEntity, "", "Invalid local path, it does not exist or not a directory.")
		case addrErr.HasCredentials:
			ctx.Error(http.StatusUnprocessableEntity, "", "The URL contains credentials.")
		default:
			ctx.Error(http.StatusInternalServerError, "ParseRemoteAddr", "Unknown error type (ErrInvalidCloneAddr): "+err.Error())
		}
	} else {
		ctx.Error(http.StatusInternalServerError, "ParseRemoteAddr", err)
	}
}
