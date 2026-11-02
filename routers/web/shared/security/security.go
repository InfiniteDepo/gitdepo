// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package security holds what the organization Security tab and the instance pages share: the search form, the
// results and the download, over the same services as the org and instance API.
package security

import (
	"errors"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	vulnerability_model "forgejo.org/models/vulnerability"
	"forgejo.org/modules/dependency"
	"forgejo.org/modules/log"
	"forgejo.org/modules/optional"
	"forgejo.org/modules/setting"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/util"
	"forgejo.org/modules/vulnerability"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	dependency_service "forgejo.org/services/dependency"
	vulnerability_service "forgejo.org/services/vulnerability"
)

// The two searches.
const (
	Vulnerabilities = "vulnerabilities"
	Dependencies    = "dependencies"
)

// Form is what the search form sends. Version of a dependency search holds an exact version or a range.
type Form struct {
	Advisory, Ecosystem, Name, Version, State, Project, Owner string
	Direct                                                    bool
}

func readForm(ctx *context.Context) Form {
	return Form{
		Advisory: ctx.FormTrim("advisory"), Ecosystem: ctx.FormTrim("ecosystem"), Name: ctx.FormTrim("name"), Version: ctx.FormTrim("version"),
		State: ctx.FormTrim("state"), Project: ctx.FormTrim("project"), Owner: ctx.FormTrim("owner"), Direct: ctx.FormBool("direct"),
	}
}

// Query is the form as URL parameters: the links of the pager and of a refused download.
func (f Form) Query() url.Values {
	q := url.Values{}
	for k, v := range map[string]string{"advisory": f.Advisory, "ecosystem": f.Ecosystem, "name": f.Name, "version": f.Version, "state": f.State, "project": f.Project, "owner": f.Owner} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if f.Direct {
		q.Set("direct", "true")
	}
	return q
}

// isRange tells a requirement from an exact version: the one field of the dependency form holds either. It is a range
// when it is operator-shaped; anything else is an exact version, matched as written in the lock file whatever a version
// parser would say of it (so "dev-main", "1!2.0" and "4.17" stay exact).
func isRange(s string) bool {
	return strings.ContainsAny(s[:min(1, len(s))], "^~<>=") || strings.HasPrefix(s, "!=") || strings.ContainsAny(s, " ,|*") ||
		strings.HasSuffix(strings.ToLower(s), ".x")
}

// clip caps a typed value echoed in a message.
func clip(s string) string {
	if len(s) <= 64 {
		return s
	}
	return strings.ToValidUTF8(s[:64], "") + "…"
}

func (f Form) usage() dependency_service.UsageFilter {
	u := dependency_service.UsageFilter{Ecosystem: f.Ecosystem, Name: f.Name}
	if isRange(f.Version) {
		u.Range = f.Version
	} else {
		u.Version = f.Version
	}
	if f.Direct {
		u.Direct = optional.Some(true)
	}
	return u
}

func (f Form) alerts() vulnerability_service.AlertFilter {
	return vulnerability_service.AlertFilter{Advisory: f.Advisory, Ecosystem: f.Ecosystem, Name: f.Name, Version: f.Version, State: f.State}
}

// searched says whether the form asks for anything: an empty form shows the hint and runs no query.
func (f Form) searched(kind string) bool {
	if kind == Vulnerabilities {
		return f.Advisory != "" || f.Name != "" || f.Version != ""
	}
	return f.Name != "" || f.Version != ""
}

// scope fills the project (organization) or owner (instance) filter.
func (f Form) scope(scope dependency_service.SearchScope) dependency_service.SearchScope {
	if scope.Org != nil {
		scope.Project = f.Project
	} else {
		scope.Owner = f.Owner
	}
	return scope
}

type alertRow struct {
	Repo *repo_model.Repository
	*api.VulnerabilityAlert
}

// Page is the data of a search page, as ctx.Data["Search"].
type Page struct {
	Kind, Link           string // Link is the page's own path: the form posts to it and the tabs and pager link to it
	Form                 Form
	Admin                bool // across every owner
	Ecosystems, States   []string
	Projects             []*repo_model.RepoGroup
	Searched             bool
	Error, ErrorField    string // the message of a refused form and the field it names; Error is also set for a too-broad search (TooBroad)
	TooBroad             bool
	Usage                []*dependency_service.UsageRow
	Alerts               []*alertRow
	Advisory             *api.VulnerabilityAdvisory // the card of an advisory search that found alerts
	AdvisoryScore        string                     // the CVSS score as text, "" when the advisory has none
	Total, Repos, Owners int64
}

// validate checks the form the way the user typed it, so a mistake names its field in the user's language. It mirrors
// the checks of dependency_service.SearchUsage / vulnerability_service.SearchAlerts (ecosystem, advisory ID, state,
// a dependency name needs an ecosystem, range syntax); what it lets through is checked again by the services.
func validate(ctx *context.Context, kind string, f Form) (field, msg string) {
	switch {
	case f.Ecosystem != "" && !dependency.IsEcosystem(f.Ecosystem):
		return "ecosystem", ctx.Locale.TrString("security_search.invalid_ecosystem")
	case kind == Vulnerabilities && f.Advisory != "" && !vulnerability.ValidID(f.Advisory):
		return "advisory", ctx.Locale.TrString("security_search.invalid_advisory", clip(f.Advisory))
	case kind == Dependencies && f.Name != "" && f.Ecosystem == "":
		return "ecosystem", ctx.Locale.TrString("security_search.need_ecosystem")
	case f.Name == "" && (f.Version != "" || kind == Dependencies || f.Advisory == ""):
		return "name", ctx.Locale.TrString("security_search.need_package")
	case kind == Dependencies && isRange(f.Version):
		if _, ok := vulnerability.ParseRangeFilter(f.Ecosystem, f.Version); !ok {
			return "version", ctx.Locale.TrString("security_search.invalid_range", clip(f.Version))
		}
	case kind == Vulnerabilities && f.State != "" && f.State != "all" && !slices.Contains(vulnerability_model.States, f.State):
		return "state", ctx.Locale.TrString("security_search.invalid_state")
	}
	return "", ""
}

// Search runs the search the request asks for and sets ctx.Data["Search"]. scope is the visibility rule, link the
// page's path. It answers by itself (and returns false) when the client is rate limited; an empty form runs nothing
// and is not charged.
func Search(ctx *context.Context, scope dependency_service.SearchScope, kind, link string) bool {
	f := readForm(ctx)
	page := &Page{Kind: kind, Link: link, Form: f, Admin: scope.Org == nil, Ecosystems: dependency.Ecosystems, States: append(slices.Clone(vulnerability_model.States), "all"), Searched: f.searched(kind)}
	ctx.Data["Search"] = page
	if scope.Org != nil {
		groups, _, err := repo_model.FindVisibleRepoGroups(ctx, ctx.Doer, scope.Org.ID, "", db.ListOptions{ListAll: true})
		if err != nil {
			ctx.ServerError("FindVisibleRepoGroups", err)
			return false
		}
		page.Projects = groups
	}
	if !page.Searched {
		return true
	}
	if field, msg := validate(ctx, kind, f); msg != "" {
		page.ErrorField, page.Error = field, msg
		return true
	}
	if common.RateLimitHeavy(ctx); ctx.Resp.WrittenStatus() != 0 {
		return false
	}
	scope = f.scope(scope)
	lo := db.ListOptions{Page: max(ctx.FormInt("page"), 1), PageSize: setting.UI.IssuePagingNum}
	var err error
	if kind == Vulnerabilities {
		err = searchAlerts(ctx, scope, page, lo)
	} else {
		err = searchUsage(ctx, scope, page, lo)
	}
	switch {
	case errors.Is(err, dependency_service.ErrTooMany):
		page.TooBroad = true
		page.Error = tooBroad(ctx, page.Admin)
	case errors.Is(err, util.ErrInvalidArgument): // the form passed validate, so this is a mistake only the service knows
		log.Info("security search refused: %v", err)
		page.Error = ctx.Locale.TrString("security_search.invalid_search")
	case err != nil:
		ctx.ServerError("Search", err)
		return false
	}
	if page.Total > int64(lo.PageSize) {
		pager := context.NewPagination(int(page.Total), lo.PageSize, lo.Page, 5)
		q := f.Query()
		for _, k := range slices.Sorted(maps.Keys(q)) {
			pager.AddParamString(k, q.Get(k))
		}
		ctx.Data["Page"] = pager
	}
	return true
}

func tooBroad(ctx *context.Context, admin bool) string {
	limit := ctx.Locale.PrettyNumber(dependency_service.MaxUsageCandidates)
	if admin {
		return ctx.Locale.TrString("security_search.too_broad_admin", limit)
	}
	return ctx.Locale.TrString("security_search.too_broad_org", limit)
}

func searchUsage(ctx *context.Context, scope dependency_service.SearchScope, page *Page, lo db.ListOptions) error {
	f := page.Form.usage()
	res, err := dependency_service.SearchUsageSummary(ctx, scope, f, lo)
	if err != nil {
		return err
	}
	page.Usage, page.Total, page.Repos, page.Owners = res.Rows, res.Total, res.Repos, res.Owners
	common.RecordUsageSearch(ctx.Base, ctx.Doer, scope, f, res.Total)
	return nil
}

func searchAlerts(ctx *context.Context, scope dependency_service.SearchScope, page *Page, lo db.ListOptions) error {
	f := page.Form.alerts()
	res, err := vulnerability_service.SearchAlertsSummary(ctx, scope, f, lo)
	if err != nil {
		return err
	}
	page.Total, page.Repos, page.Owners = res.Total, res.Repos, res.Owners
	common.RecordAlertSearch(ctx.Base, ctx.Doer, scope, f, res.Total)
	if len(res.Hits) == 0 {
		return nil
	}
	converted, err := convert.ToRepoVulnerabilityAlerts(ctx, ctx.Doer, res.Hits)
	if err != nil {
		return err
	}
	for i, a := range converted {
		page.Alerts = append(page.Alerts, &alertRow{Repo: res.Hits[i].Repo, VulnerabilityAlert: &a.VulnerabilityAlert})
	}
	if f.Advisory != "" { // the card comes from a found alert, so an unknown advisory and an unaffected one answer alike
		first := converted[0]
		page.Advisory = &first.Advisory
		if sc := first.Advisory.Score; sc != nil {
			page.AdvisoryScore = strconv.FormatFloat(*sc, 'f', 1, 64)
		}
	}
	return nil
}

// Export sends the download the posted form asks for. A refusal before the first byte (a wrong filter, too many rows,
// no free slot) goes back to the page with a message.
func Export(ctx *context.Context, scope dependency_service.SearchScope, kind, link string) {
	f := readForm(ctx)
	format := ctx.FormString("format")
	scope = f.scope(scope)
	var err error
	switch {
	case format != "csv" && format != "json":
		err = util.NewInvalidArgumentErrorf("unknown format")
	case kind == Vulnerabilities:
		err = common.ExportAlerts(ctx.Base, ctx.Doer, scope, f.alerts(), format)
	default:
		err = common.ExportDependencies(ctx.Base, ctx.Doer, scope, f.usage(), format)
	}
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, common.ErrExportBusy):
		ctx.Flash.Error(ctx.Tr("security_search.export_busy"))
	case errors.Is(err, dependency_service.ErrTooManyCandidates):
		ctx.Flash.Error(tooBroad(ctx, scope.Org == nil))
	case errors.Is(err, dependency_service.ErrTooMany):
		ctx.Flash.Error(ctx.Tr("security_search.export_too_many", ctx.Locale.PrettyNumber(dependency_service.MaxExportRows)))
	case errors.Is(err, common.ErrExportTimeLimit):
		ctx.Flash.Error(ctx.Tr("security_search.export_time_limit"))
	case errors.Is(err, util.ErrInvalidArgument):
		log.Info("security export refused: %v", err)
		ctx.Flash.Error(ctx.Tr("security_search.export_invalid"))
	default:
		ctx.ServerError("Export", err)
		return
	}
	target := link
	if q := f.Query().Encode(); q != "" {
		target += "?" + q
	}
	ctx.Redirect(target)
}
