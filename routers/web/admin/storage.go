// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package admin

import (
	stdCtx "context"
	"encoding/csv"
	"net/http"
	"strconv"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	"forgejo.org/services/cron"

	"xorm.io/builder"
)

const tplStorage base.TplName = "admin/storage"

// Storage shows the storage used per repository owner, or exports it as CSV or JSON
func Storage(ctx *context.Context) {
	totals, err := repo_model.GetStorageTotals(ctx)
	if err != nil {
		ctx.ServerError("GetStorageTotals", err)
		return
	}

	opts := repo_model.FindOwnerStorageOptions{
		Keyword: ctx.FormTrim("q"),
		OrderBy: ctx.FormString("sort"),
	}
	if _, ok := repo_model.OwnerStorageOrderBy[opts.OrderBy]; !ok {
		opts.OrderBy = "reversesize"
	}
	ownerType := ctx.FormString("type")
	switch ownerType {
	case "user":
		opts.OwnerType = optional.Some(user_model.UserTypeIndividual)
	case "org":
		opts.OwnerType = optional.Some(user_model.UserTypeOrganization)
	default:
		ownerType = ""
	}

	if format := ctx.FormString("format"); format == "csv" || format == "json" {
		owners, _, err := repo_model.FindOwnerStorage(ctx, opts)
		if err != nil {
			ctx.ServerError("FindOwnerStorage", err)
			return
		}
		if format == "json" {
			result := make([]*api.OwnerStorage, len(owners))
			for i, o := range owners {
				result[i] = convert.ToOwnerStorage(o, totals)
			}
			ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "application/json", ContentTypeCharset: "utf-8", Filename: "storage.json"})
			if err := json.NewEncoder(ctx.Resp).Encode(result); err != nil {
				log.Error("storage.json: %v", err)
			}
			return
		}
		ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "text/csv", ContentTypeCharset: "utf-8", Filename: "storage.csv"})
		w := csv.NewWriter(ctx.Resp)
		_ = w.Write([]string{
			"owner", "type", "repos", "git_size", "lfs_size", "total_size", "percent",
			"wiki_size", "attachments_size", "packages_size", "artifacts_size", "logs_size", "trash_size",
		})
		for _, o := range owners {
			typ := "user"
			if o.Owner.IsOrganization() {
				typ = "org"
			}
			_ = w.Write([]string{
				util.CSVSafe(o.Owner.Name), typ, strconv.FormatInt(o.NumRepos, 10),
				strconv.FormatInt(o.GitSize, 10), strconv.FormatInt(o.LFSSize, 10), strconv.FormatInt(o.Size(), 10),
				strconv.FormatFloat(o.Percent(totals), 'f', 2, 64),
				strconv.FormatInt(o.WikiSize, 10), strconv.FormatInt(o.AttachmentsSize, 10), strconv.FormatInt(o.PackagesSize, 10),
				strconv.FormatInt(o.ArtifactsSize, 10), strconv.FormatInt(o.LogsSize, 10), strconv.FormatInt(o.TrashSize, 10),
			})
		}
		w.Flush()
		return
	}

	page := max(ctx.FormInt("page"), 1)
	opts.Page = page
	opts.PageSize = setting.UI.Admin.RepoPagingNum
	owners, count, err := repo_model.FindOwnerStorage(ctx, opts)
	if err != nil {
		ctx.ServerError("FindOwnerStorage", err)
		return
	}

	ctx.Data["Title"] = ctx.Tr("admin.storage")
	ctx.Data["PageIsAdminStorage"] = true
	ctx.Data["Totals"] = totals
	ctx.Data["AverageSize"] = totals.AverageRepoSize()
	if ctx.Data["MedianSize"], err = repo_model.GetMedianRepoSize(ctx, totals.NumRepos); err != nil {
		ctx.ServerError("GetMedianRepoSize", err)
		return
	}
	for _, task := range cron.ListTasks() {
		if task.Name == "git_gc_repos" { // its git gc also recalculates the repository sizes
			ctx.Data["SizeCronTask"] = task
		}
	}
	ctx.Data["Total"] = count
	ctx.Data["Owners"] = owners
	ctx.Data["Keyword"] = opts.Keyword
	ctx.Data["SortType"] = opts.OrderBy
	ctx.Data["OwnerType"] = ownerType

	pager := context.NewPagination(int(count), opts.PageSize, page, 5)
	pager.SetDefaultParams(ctx)
	pager.AddParam(ctx, "type", "OwnerType")
	ctx.Data["Page"] = pager

	ctx.HTML(http.StatusOK, tplStorage)
}

// repoStorage is one row of the per-repository storage export
type repoStorage struct {
	RepoID          int64   `json:"repo_id"`
	OwnerName       string  `json:"owner_name"`
	RepoName        string  `json:"repo_name"`
	Private         bool    `json:"private"`
	GitSize         int64   `json:"git_size"`
	LFSSize         int64   `json:"lfs_size"`
	TotalSize       int64   `json:"total_size"`
	Percent         float64 `json:"percent"`
	WikiSize        int64   `json:"wiki_size"`
	AttachmentsSize int64   `json:"attachments_size"`
	ArtifactsSize   int64   `json:"artifacts_size"`
	LogsSize        int64   `json:"logs_size"`
}

// exportRepoStorage streams the storage used per repository as CSV or JSON, filtered by "uid" and sorted by "sort"
func exportRepoStorage(ctx *context.Context, format string) {
	cond := builder.NewCond()
	if uid := ctx.FormString("uid"); uid != "" {
		ownerID, err := strconv.ParseInt(uid, 10, 64)
		if err != nil {
			ctx.Error(http.StatusBadRequest, "invalid uid")
			return
		}
		if ownerID > 0 { // like the list, uid=0 means all owners
			cond = builder.Eq{"owner_id": ownerID}
		}
	}
	sizeFilter, err := repo_model.ParseSizeFilter(ctx.FormString("sizefield"), ctx.FormTrim("minsize"), ctx.FormTrim("maxsize"))
	if err != nil {
		ctx.Error(http.StatusBadRequest, "invalid size filter")
		return
	}
	cond = cond.And(sizeFilter.Cond())
	orderBy, ok := repo_model.OrderByFlatMap[ctx.FormString("sort")]
	if !ok {
		orderBy = repo_model.OrderByFlatMap["reversesize"]
	}
	totals, err := repo_model.GetStorageTotals(ctx)
	if err != nil {
		ctx.ServerError("GetStorageTotals", err)
		return
	}
	assets, err := repo_model.AssetSizesByRepo(ctx)
	if err != nil {
		ctx.ServerError("AssetSizesByRepo", err)
		return
	}

	var write func(r *repoStorage) error
	var finish func() error
	if format == "csv" {
		ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "text/csv", ContentTypeCharset: "utf-8", Filename: "repo-storage.csv"})
		w := csv.NewWriter(ctx.Resp)
		_ = w.Write([]string{
			"repo_id", "owner", "repo", "private", "git_size", "lfs_size", "total_size", "percent",
			"wiki_size", "attachments_size", "artifacts_size", "logs_size",
		})
		write = func(r *repoStorage) error {
			return w.Write([]string{
				strconv.FormatInt(r.RepoID, 10), util.CSVSafe(r.OwnerName), util.CSVSafe(r.RepoName), strconv.FormatBool(r.Private),
				strconv.FormatInt(r.GitSize, 10), strconv.FormatInt(r.LFSSize, 10), strconv.FormatInt(r.TotalSize, 10),
				strconv.FormatFloat(r.Percent, 'f', 2, 64),
				strconv.FormatInt(r.WikiSize, 10), strconv.FormatInt(r.AttachmentsSize, 10),
				strconv.FormatInt(r.ArtifactsSize, 10), strconv.FormatInt(r.LogsSize, 10),
			})
		}
		finish = func() error {
			w.Flush()
			return w.Error()
		}
	} else {
		ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "application/json", ContentTypeCharset: "utf-8", Filename: "repo-storage.json"})
		enc := json.NewEncoder(ctx.Resp)
		sep := "["
		write = func(r *repoStorage) error {
			if _, err := ctx.Resp.Write([]byte(sep)); err != nil {
				return err
			}
			sep = ","
			return enc.Encode(r)
		}
		finish = func() error {
			end := "]\n"
			if sep == "[" {
				end = "[]\n"
			}
			_, err := ctx.Resp.Write([]byte(end))
			return err
		}
	}

	// one query whose rows are streamed; the callback must not use the database
	err = db.GetEngine(ctx).Where(cond).OrderBy(orderBy.String()+", id ASC").Iterate(new(repo_model.Repository), func(_ int, bean any) error {
		repo := bean.(*repo_model.Repository)
		stats := repo_model.StorageStats{GitSize: repo.GitSize, LFSSize: repo.LFSSize, WikiSize: repo.WikiSize}
		if a := assets[repo.ID]; a != nil {
			stats.AttachmentsSize, stats.ArtifactsSize, stats.LogsSize = a.AttachmentsSize, a.ArtifactsSize, a.LogsSize
		}
		return write(&repoStorage{
			RepoID: repo.ID, OwnerName: repo.OwnerName, RepoName: repo.Name, Private: repo.IsPrivate,
			GitSize: repo.GitSize, LFSSize: repo.LFSSize, TotalSize: stats.Size(), Percent: stats.Percent(totals),
			WikiSize: repo.WikiSize, AttachmentsSize: stats.AttachmentsSize, ArtifactsSize: stats.ArtifactsSize, LogsSize: stats.LogsSize,
		})
	})
	if err == nil {
		err = finish()
	}
	if err == nil {
		return
	}
	if ctx.Resp.WrittenStatus() == 0 {
		ctx.Resp.Header().Del("Content-Disposition")
		ctx.ServerError("exportRepoStorage", err)
		return
	}
	// the body has started: the log records why
	log.Error("exportRepoStorage: %v", err)
	panic(http.ErrAbortHandler) // abort so the client sees a failed download, not a short file
}

// StorageRecalculate runs recalculate_repo_sizes in the background, for the repositories of the owner named in
// "owner", or for all repositories
func StorageRecalculate(ctx *context.Context) {
	task := cron.GetTask("recalculate_repo_sizes")
	if task == nil {
		ctx.NotFound("recalculate_repo_sizes", nil)
		return
	}
	config := &cron.RecalculateRepoSizesConfig{}
	if name := ctx.FormTrim("owner"); name != "" {
		owner, err := user_model.GetUserByName(ctx, name)
		if user_model.IsErrUserNotExist(err) {
			ctx.Flash.Error(ctx.Tr("admin.storage.recalculate.unknown_owner"))
			ctx.Redirect(setting.AppSubURL + "/admin/storage")
			return
		} else if err != nil {
			ctx.ServerError("GetUserByName", err)
			return
		}
		config.OwnerID = owner.ID
	}
	go task.RunWithUser(audit_model.WithActor(stdCtx.Background(), audit_model.ActorFromContext(ctx)), ctx.Doer, config) // a run already in progress makes this a no-op
	ctx.Flash.Success(ctx.Tr("admin.storage.recalculate.started"))
	ctx.Redirect(setting.AppSubURL + "/admin/storage")
}
