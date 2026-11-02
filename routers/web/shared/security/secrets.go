// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"errors"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/modules/log"
	"forgejo.org/modules/secretdetection"
	"forgejo.org/modules/setting"
	"forgejo.org/routers/common"
	"forgejo.org/services/context"
	secretscan_service "forgejo.org/services/secretscan"
)

// maxSecretQueryLen is the longest text of the repository search, maxSecretNameLen the longest owner or project.
const (
	maxSecretQueryLen = 128
	maxSecretNameLen  = 255
)

// SecretsForm is what the secret alert list's form sends. State is "" (open, the default), "closed" or "all".
type SecretsForm struct {
	State   string
	Reason  string
	Type    string
	Query   string
	Project string
	Owner   string
}

func readSecretsForm(ctx *context.Context) SecretsForm {
	return SecretsForm{
		State: ctx.FormTrim("state"), Reason: ctx.FormTrim("reason"), Type: ctx.FormTrim("type"),
		Query: ctx.FormTrim("q"), Project: ctx.FormTrim("project"), Owner: ctx.FormTrim("owner"),
	}
}

// Values is the form as URL parameters: the links of the pager and of a refused download.
func (f SecretsForm) Values() url.Values {
	q := url.Values{}
	for k, v := range map[string]string{"state": f.State, "reason": f.Reason, "type": f.Type, "q": f.Query, "project": f.Project, "owner": f.Owner} {
		if v != "" {
			q.Set(k, v)
		}
	}
	return q
}

// SecretType is a choice of the type filter.
type SecretType struct{ ID, Name string }

// SecretsPage is the data of a list page, as ctx.Data["Secrets"].
type SecretsPage struct {
	Link   string // the page's own path: the form posts to it and the pager links to it
	Form   SecretsForm
	Admin  bool // across every owner (the instance list)
	Narrow bool // an organization list of a member: only the repositories where they can write
	// Writable is the number of repositories of a narrowed list; TooMany is MaxNarrowRepos when there were more.
	Writable     int
	TooMany      int
	Ignored      string // the labels of the filters that were not valid and are not applied, joined
	HasFilter    bool
	Types        []SecretType
	TypesCut     bool // the custom patterns offered were cut at maxInstanceTypes
	ClosedStates []string
	Projects     []*repo_model.RepoGroup
	Result       *secretscan_service.Result
}

func secretTypes() []SecretType {
	rules := secretdetection.BuiltinRules()
	out := make([]SecretType, 0, len(rules))
	for _, r := range rules {
		if r.ReportAs != "" { // its findings carry another rule's ID, so no alert has this one
			continue
		}
		out = append(out, SecretType{r.ID, r.Name})
	}
	slices.SortFunc(out, func(a, b SecretType) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// filterLabels are the form labels of the fields ParseFilter reports.
var filterLabels = map[string]string{"state": "security_search.state", "reason": "repo.secrets.reason", "type": "repo.secrets.type"}

// secretsRequest is a list request as parsed: the form as applied, the filter, the scope with the form's project or
// owner, search text and writable repositories, and the labels of what was left out.
type secretsRequest struct {
	form     SecretsForm
	filter   secretscan_service.Filter
	scope    secretscan_service.Scope
	projects []*repo_model.RepoGroup
	ignored  []string
}

// parseSecrets reads the form. A value that is not valid (too long, not an allowed state or reason, an unknown type,
// a project the viewer can't see) is dropped and its label kept, so the page says so and a download refuses.
func parseSecrets(ctx *context.Context, scope secretscan_service.Scope) (*secretsRequest, error) {
	f := readSecretsForm(ctx)
	r := &secretsRequest{}
	if len(f.Query) > maxSecretQueryLen || hasControl(f.Query) {
		f.Query, r.ignored = "", append(r.ignored, "secret_search.search")
	}
	if len(f.Owner) > maxSecretNameLen || hasControl(f.Owner) {
		f.Owner, r.ignored = "", append(r.ignored, "security_search.owner")
	}
	filter, ignored := secretscan_service.ParseFilter(f.State, f.Reason, f.Type)
	for _, field := range ignored {
		r.ignored = append(r.ignored, filterLabels[field])
	}
	f.State, f.Reason, f.Type = filter.State, filter.Reason, filter.Type
	if f.State == secretscan_model.StateOpen {
		f.State = ""
	}
	if scope.Org != nil {
		groups, _, err := repo_model.FindVisibleRepoGroups(ctx, ctx.Doer, scope.Org.ID, "", db.ListOptions{ListAll: true})
		if err != nil {
			return nil, err
		}
		r.projects = groups
		if f.Project != "" && !slices.ContainsFunc(groups, func(g *repo_model.RepoGroup) bool { return strings.EqualFold(g.Name, f.Project) }) {
			f.Project, r.ignored = "", append(r.ignored, "security_search.project")
		}
		scope.Project, f.Owner = f.Project, ""
	} else {
		scope.Owner, f.Project = f.Owner, ""
	}
	scope.Query = f.Query
	r.form, r.filter = f, filter
	if scope.Narrow {
		ids, err := secretscan_service.WritableRepoIDs(ctx, scope.Org, ctx.Doer)
		if err != nil {
			return r, err
		}
		scope.Writable = ids
	}
	r.scope = scope
	return r, nil
}

// hasControl tells whether s holds a control character (a NUL would cut a LIKE pattern short).
func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

// Secrets runs the list the request asks for and sets ctx.Data["Secrets"]. scope is the visibility rule, link the
// page's path.
func Secrets(ctx *context.Context, scope secretscan_service.Scope, link string) bool {
	custom, cut, err := customSecretTypes(ctx, scope)
	if err != nil {
		ctx.ServerError("customSecretTypes", err)
		return false
	}
	page := &SecretsPage{
		Link: link, Admin: scope.Org == nil, Narrow: scope.Narrow, Types: append(secretTypes(), custom...), TypesCut: cut,
		ClosedStates: secretscan_model.ClosedStates, Result: &secretscan_service.Result{},
	}
	ctx.Data["Secrets"] = page
	r, err := parseSecrets(ctx, scope)
	if errors.Is(err, secretscan_service.ErrTooManyRepos) {
		page.Form, page.Projects = r.form, r.projects // the filters stay, for a try with fewer repositories later
		page.TooMany = secretscan_service.MaxNarrowRepos
		return true
	} else if err != nil {
		ctx.ServerError("parseSecrets", err)
		return false
	}
	labels := make([]string, len(r.ignored))
	for i, key := range r.ignored {
		labels[i] = ctx.Locale.TrString(key)
	}
	page.Form, page.Projects, page.Writable = r.form, r.projects, len(r.scope.Writable)
	page.Ignored, page.HasFilter = strings.Join(labels, ", "), r.form != SecretsForm{}
	lo := db.ListOptions{Page: max(ctx.FormInt("page"), 1), PageSize: setting.UI.IssuePagingNum}
	res, err := secretscan_service.Search(ctx, r.scope, r.filter, lo)
	if err != nil {
		ctx.ServerError("secretscan Search", err)
		return false
	}
	page.Result = res
	if res.Total > int64(lo.PageSize) {
		pager := context.NewPagination(int(res.Total), lo.PageSize, lo.Page, 5)
		q := r.form.Values()
		for _, k := range slices.Sorted(maps.Keys(q)) {
			pager.AddParamString(k, q.Get(k))
		}
		ctx.Data["Page"] = pager
	}
	return true
}

// SecretsExport sends the CSV download the posted form asks for. A refusal before the first byte (a wrong filter,
// too many rows or repositories, no free slot) goes back to the page with a message.
func SecretsExport(ctx *context.Context, scope secretscan_service.Scope, link string) {
	r, err := parseSecrets(ctx, scope)
	switch {
	case err != nil:
	case len(r.ignored) > 0:
		err = errInvalidFilter
	default:
		err = common.ExportSecretAlerts(ctx.Base, ctx.Doer, r.scope, r.filter, func(a *secretscan_model.Alert, repo *repo_model.Repository) string {
			return repo.HTMLURL() + "/security/secrets/" + strconv.FormatInt(a.Index, 10)
		})
	}
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, common.ErrExportBusy):
		ctx.Flash.Error(ctx.Tr("security_search.export_busy"))
	case errors.Is(err, secretscan_service.ErrExportTooMany):
		ctx.Flash.Error(ctx.Tr("secret_search.export_too_many"))
	case errors.Is(err, secretscan_service.ErrTooManyRepos):
		ctx.Flash.Error(ctx.Tr("secret_search.narrow_too_many", ctx.Locale.PrettyNumber(secretscan_service.MaxNarrowRepos)))
	case errors.Is(err, common.ErrExportTimeLimit):
		ctx.Flash.Error(ctx.Tr("security_search.export_time_limit"))
	case errors.Is(err, errInvalidFilter):
		ctx.Flash.Error(ctx.Tr("security_search.export_invalid"))
	default:
		log.Error("secret alert export: %v", err)
		ctx.ServerError("SecretsExport", err)
		return
	}
	target := link // back with the filters that were applied: valid and of a bounded length
	if r != nil {
		if q := r.form.Values().Encode(); q != "" {
			target += "?" + q
		}
	}
	ctx.Redirect(target)
}

var errInvalidFilter = errors.New("invalid filter")
