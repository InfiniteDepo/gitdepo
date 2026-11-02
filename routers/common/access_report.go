// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/services/accessreport"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"

	"xorm.io/builder"
)

// AccessReport is the access report of the repositories of an org, or of every repository if OwnerID is 0, which
// only site admins may see. It is paged by repository.
type AccessReport struct {
	OwnerID int64
	Doer    *user_model.User
	// Admin says whether the doer acts as a site admin, which a restricted token doesn't
	Admin  bool
	Filter accessreport.Filter
	// Repos, if set, limits the repositories, e.g. to those an access token can read
	Repos builder.Cond
}

const accessReportBatch = 100

func (r *AccessReport) cond() builder.Cond {
	cond := builder.NewCond()
	if r.OwnerID > 0 {
		cond = cond.And(builder.Eq{"owner_id": r.OwnerID})
	}
	if r.Repos != nil {
		cond = cond.And(r.Repos)
	}
	return cond
}

func (r *AccessReport) repos(ctx *context.Base, page, size int) ([]int64, error) {
	ids := make([]int64, 0, size)
	return ids, db.GetEngine(ctx).Table("repository").Where(r.cond()).Cols("id").OrderBy("id").Limit(size, (page-1)*size).Find(&ids)
}

// lines returns the lines of the repositories, with the person columns for site admins only.
func (r *AccessReport) lines(ctx *context.Base, repoIDs []int64) ([]*api.AccessReportLine, bool, error) {
	rows, activity, err := accessreport.ForRepos(ctx, repoIDs, r.Admin, r.Doer, r.Filter)
	if err != nil {
		return nil, false, err
	}
	var people map[int64]*accessreport.Person
	if r.Admin {
		if people, err = accessreport.People(ctx, rows, r.cond()); err != nil {
			return nil, false, err
		}
	}
	return convert.ToAccessReportLines(ctx, rows, accessreport.AsAdmin(r.Doer, r.Admin), people), activity, nil
}

// Page returns the lines of a page of repositories, at most 100 per page, and how many repositories there are.
func (r *AccessReport) Page(ctx *context.Base, page, size int) (lines []*api.AccessReportLine, total int64, activity bool, err error) {
	repos, err := r.repos(ctx, page, size)
	if err != nil {
		return nil, 0, false, err
	}
	if lines, activity, err = r.lines(ctx, repos); err != nil {
		return nil, 0, false, err
	}
	total, err = db.GetEngine(ctx).Where(r.cond()).Count(new(repo_model.Repository))
	return lines, total, activity, err
}

func csvTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func csvBool(b *bool) string {
	if b == nil {
		return ""
	}
	return strconv.FormatBool(*b)
}

// Export streams the lines of every repository as CSV or JSON, in batches of repositories. It returns an error
// only if it wrote nothing.
func (r *AccessReport) Export(ctx *context.Base, format string) error {
	var write func(l *api.AccessReportLine) error
	var finish func() error
	if format == "csv" {
		ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "text/csv", ContentTypeCharset: "utf-8", Filename: "access-report.csv"})
		w := csv.NewWriter(ctx.Resp)
		header := []string{"type", "name", "full_name", "repository", "unit", "access", "path", "team", "user_groups", "grant", "applied", "scopes"}
		if r.Admin {
			header = append(header, "last_sign_in", "last_push", "two_factor", "account_source", "suspended")
		}
		if err := w.Write(header); err != nil {
			return err
		}
		write = func(l *api.AccessReportLine) error {
			groups := make([]string, 0, len(l.UserGroups))
			for _, g := range l.UserGroups {
				if g.LoginSource != "" {
					groups = append(groups, g.Name+" ("+g.LoginSource+")")
				} else {
					groups = append(groups, g.Name)
				}
			}
			rec := []string{
				l.Type, l.Name, l.FullName, l.Repository, l.Unit, l.Access, l.Path,
				l.Team, strings.Join(groups, "; "), l.Grant, strconv.FormatBool(l.Applied), strings.Join(l.Scopes, "; "),
			}
			if r.Admin {
				rec = append(rec, csvTime(l.LastLogin), csvTime(l.LastPush), csvBool(l.TwoFactor), l.AccountSource, csvBool(l.Suspended))
			}
			for i := range rec {
				rec[i] = util.CSVSafe(rec[i])
			}
			return w.Write(rec)
		}
		finish = func() error {
			w.Flush()
			return w.Error()
		}
	} else {
		ctx.SetServeHeaders(&context.ServeHeaderOptions{ContentType: "application/json", ContentTypeCharset: "utf-8", Filename: "access-report.json"})
		enc := json.NewEncoder(ctx.Resp)
		sep := "["
		write = func(l *api.AccessReportLine) error {
			if _, err := ctx.Resp.Write([]byte(sep)); err != nil {
				return err
			}
			sep = ","
			return enc.Encode(l)
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

	err := r.export(ctx, write)
	if err == nil {
		err = finish()
	}
	if err == nil {
		return nil
	}
	if ctx.Resp.WrittenStatus() == 0 {
		ctx.Resp.Header().Del("Content-Disposition")
		return err
	}
	// the body has started: the log records why
	log.Error("AccessReport.Export: %v", err)
	panic(http.ErrAbortHandler) // abort so the client sees a failed download, not a short file
}

func (r *AccessReport) export(ctx *context.Base, write func(l *api.AccessReportLine) error) error {
	for page := 1; ; page++ {
		repos, err := r.repos(ctx, page, accessReportBatch)
		if err != nil {
			return err
		}
		lines, _, err := r.lines(ctx, repos)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if err := write(l); err != nil {
				return err
			}
		}
		if len(repos) < accessReportBatch {
			return nil
		}
	}
}
