// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/models/db"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	api "forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/context"
	"forgejo.org/services/convert"
	secretscan_service "forgejo.org/services/secretscan"
	vulnerability_service "forgejo.org/services/vulnerability"
	wiki_service "forgejo.org/services/wiki"
)

const (
	tplSecretAlerts base.TplName = "repo/security/secrets"
	tplSecretAlert  base.TplName = "repo/security/secret"

	secretPageSize   = 25
	secretLocPerPage = 10
	maxBulkClose     = 50
)

// MustSeeSecretAlerts is the gate of the secret alert pages: who may see alerts (as for vulnerability alerts), and
// only where the repository has the page: secret scanning is on, or alerts are left from before it was turned off
// (the header worked that out). Everyone else gets the 404 of a missing page. While scanning is off the list only
// shows a banner and the pages of one alert are a 404 (MustScanSecrets).
func MustSeeSecretAlerts(ctx *context.Context) {
	if !vulnerability_service.CanSeeAlerts(&ctx.Repo.Permission, ctx.IsAlertAuditorView()) || ctx.Data["ShowSecretAlerts"] != true {
		ctx.NotFound("MustSeeSecretAlerts", nil)
		return
	}
	enabled := secretscan_service.Enabled(ctx, ctx.Repo.Repository)
	writable := enabled && !ctx.Repo.Repository.IsArchived
	ctx.Data["PageIsSecurity"], ctx.Data["PageIsSecretAlerts"] = true, true
	ctx.Data["SecretScanningOn"] = enabled
	ctx.Data["CanCloseSecretAlerts"] = writable && vulnerability_service.CanDismissAlerts(&ctx.Repo.Permission)
	ctx.Data["CanRescan"] = writable && ctx.IsSigned && ctx.Repo.IsAdmin()
	ctx.Data["CanReadWiki"] = ctx.Repo.CanRead(unit.TypeWiki)
}

// MustScanSecrets 404s the pages of one alert while scanning is off: the alerts are kept but hidden until it is
// turned on again, as in the API.
func MustScanSecrets(ctx *context.Context) {
	if ctx.Data["SecretScanningOn"] != true {
		ctx.NotFound("MustScanSecrets", nil)
	}
}

// mustWriteSecretAlerts is the second check of a POST: closing and reopening are writes.
func mustWriteSecretAlerts(ctx *context.Context) bool {
	if ctx.Data["CanCloseSecretAlerts"] != true {
		ctx.NotFound("mustWriteSecretAlerts", nil)
		return false
	}
	return true
}

// secretAlertRow is an alert as the pages show it.
type secretAlertRow struct {
	*secretscan_model.Alert
	Name      string
	Generic   bool
	First     *secretscan_model.Location
	FirstText *secretscan_model.TextPlace // First, when it is in text
	More      int                         // places beyond the first the viewer can see
	ClosedBy  *user_model.User
}

func buildSecretRows(ctx *context.Context, alerts []*secretscan_model.Alert, canReadWiki bool) ([]*secretAlertRow, error) {
	var ids, userIDs []int64
	for _, a := range alerts {
		ids = append(ids, a.ID)
		if a.ClosedByID != 0 {
			userIDs = append(userIDs, a.ClosedByID)
		}
	}
	first, err := secretscan_model.FirstLocations(ctx, ctx.Repo.Repository.ID, ids, !canReadWiki)
	if err != nil {
		return nil, err
	}
	counts, err := secretscan_model.CountLocations(ctx, ctx.Repo.Repository.ID, ids, !canReadWiki)
	if err != nil {
		return nil, err
	}
	firstLocs := make([]*secretscan_model.Location, 0, len(first))
	for _, l := range first {
		firstLocs = append(firstLocs, l)
	}
	access := secretTextAccess(ctx)
	access.NoPosters = true // the list shows no poster
	texts, err := secretscan_model.LoadTextPlaces(ctx, ctx.Repo.Repository.ID, firstLocs, access)
	if err != nil {
		return nil, err
	}
	users, err := user_model.GetUsersByIDsWithBots(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	ruleIDs := make([]string, len(alerts))
	for i, a := range alerts {
		ruleIDs[i] = a.RuleID
	}
	labels, err := secretscan_model.LoadRuleLabels(ctx, ruleIDs)
	if err != nil {
		return nil, err
	}
	rows := make([]*secretAlertRow, 0, len(alerts))
	for _, a := range alerts {
		l := labels.Label(a.RuleID, ctx.Repo.Repository.OwnerID, nil) // the name of a deleted pattern is for its owners' lists
		r := &secretAlertRow{Alert: a, Name: l.Text(ctx.Locale), Generic: l.Generic, First: first[a.ID], More: max(counts[a.ID]-1, 0)}
		if r.First != nil {
			r.FirstText = texts[r.First.ID]
		}
		if a.ClosedByID != 0 {
			_, r.ClosedBy = user_model.GetUserFromMap(a.ClosedByID, users)
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// secretTextAccess is what the viewer may read of the repository's texts: a place in an issue, a pull request or a
// comment is shown (with its number, link and poster) only to a viewer who reads that issue or pull request.
func secretTextAccess(ctx *context.Context) secretscan_model.TextAccess {
	return secretscan_model.TextAccess{Issues: ctx.Repo.CanRead(unit.TypeIssues), Pulls: ctx.Repo.CanRead(unit.TypePullRequests)}
}

// scanStatus is the status line of the list: the summary of the scan rows the viewer may see.
func scanStatus(ctx *context.Context, canReadWiki bool) (*api.SecretScanningStatus, error) {
	scans, err := secretscan_model.FindScans(ctx, ctx.Repo.Repository.ID)
	if err != nil {
		return nil, err
	}
	canReadText := secretscan_service.TextStatusVisible(ctx, ctx.Repo.Repository, ctx.Repo.CanRead)
	scans = slices.DeleteFunc(scans, func(s *secretscan_model.Scan) bool {
		return s.Kind == secretscan_model.KindWiki && !canReadWiki || s.Kind == secretscan_model.KindIssue && !canReadText
	})
	return convert.ToSecretScanningStatus(scans), nil
}

// SecretAlerts lists the secret alerts of the repository.
func SecretAlerts(ctx *context.Context) {
	repo := ctx.Repo.Repository
	canReadWiki := ctx.Repo.CanRead(unit.TypeWiki)
	ctx.Data["Title"] = ctx.Tr("repo.secrets.title")
	if ctx.Data["SecretScanningOn"] != true { // hidden: only the banner, no alert, no count
		if err := secretOffNotes(ctx); err != nil {
			ctx.ServerError("secretOffNotes", err)
			return
		}
		ctx.HTML(http.StatusOK, tplSecretAlerts)
		return
	}
	state := secretscan_model.StateOpen
	if ctx.FormString("state") == "closed" {
		state = "resolved"
	}
	opts := &secretscan_model.AlertSearchOptions{
		ListOptions: db.ListOptions{Page: max(ctx.FormInt("page"), 1), PageSize: secretPageSize},
		RepoID:      repo.ID, State: state, CodeOnly: !canReadWiki,
		Ascending: ctx.FormString("sort") == "oldest",
	}
	if r := ctx.FormString("reason"); state == "resolved" && slices.Contains(secretscan_model.ClosedStates, r) {
		opts.Resolutions = []string{r}
	}
	ruleIDs, err := secretscan_model.FindRuleIDs(ctx, repo.ID, !canReadWiki)
	if err != nil {
		ctx.ServerError("FindRuleIDs", err)
		return
	}
	ignored := false
	if t := ctx.FormString("type"); slices.Contains(ruleIDs, t) {
		opts.SecretTypes = []string{t}
	} else if t != "" {
		ignored = true
	}
	foundKinds := map[string][]string{"code": {secretscan_model.KindRepo}, "pull": {secretscan_model.KindPull}, "text": secretscan_model.TextKinds}
	foundOptions := []string{"code", "pull", "text"}
	if canReadWiki {
		foundKinds["wiki"], foundOptions = []string{secretscan_model.KindWiki}, []string{"code", "wiki", "pull", "text"}
	}
	found := ctx.FormString("found")
	if kinds, ok := foundKinds[found]; ok {
		opts.Kinds = kinds
	} else if found != "" {
		found, ignored = "", true
	}
	if q := ctx.FormTrim("q"); len(q) <= secretscan_model.MaxFilterLen*4 {
		opts.PathQuery = q
	} else {
		ignored = true
	}
	ctx.Data["FilterIgnored"] = ignored // never show an unfiltered list as if it were the filtered one
	alerts, total, err := db.FindAndCount[secretscan_model.Alert](ctx, opts)
	if err != nil {
		ctx.ServerError("FindAndCount", err)
		return
	}
	rows, err := buildSecretRows(ctx, alerts, canReadWiki)
	if err != nil {
		ctx.ServerError("buildSecretRows", err)
		return
	}
	status, err := scanStatus(ctx, canReadWiki)
	if err != nil {
		ctx.ServerError("scanStatus", err)
		return
	}
	if err := secretOffNotes(ctx); err != nil {
		ctx.ServerError("secretOffNotes", err)
		return
	}
	labels, err := secretscan_model.LoadRuleLabels(ctx, ruleIDs)
	if err != nil {
		ctx.ServerError("LoadRuleLabels", err)
		return
	}
	type ruleOption struct{ ID, Name string }
	var types []ruleOption
	for _, id := range ruleIDs {
		l := labels.Label(id, repo.OwnerID, nil)
		name := l.Text(ctx.Locale)
		if l.Name == "" { // a pattern without a name to show: the rule ID tells such options apart
			name += " (" + id + ")"
		}
		types = append(types, ruleOption{id, name})
	}
	typ, reason, sort := strings.Join(opts.SecretTypes, ""), strings.Join(opts.Resolutions, ""), util.Iif(opts.Ascending, "oldest", "")
	ctx.Data["Alerts"], ctx.Data["Total"] = rows, total
	ctx.Data["State"], ctx.Data["Closed"] = ctx.FormString("state"), state == "resolved"
	ctx.Data["Query"], ctx.Data["Type"], ctx.Data["Reason"], ctx.Data["Sort"] = opts.PathQuery, typ, reason, sort
	ctx.Data["Found"], ctx.Data["FoundOptions"] = found, foundOptions
	ctx.Data["HasFilter"] = opts.PathQuery != "" || typ != "" || reason != "" || found != ""
	ctx.Data["TypeOptions"], ctx.Data["ClosedStates"] = types, secretscan_model.ClosedStates
	ctx.Data["ScanStatus"] = status
	if status.LastScanned != nil {
		ctx.Data["LastScanned"] = timeutil.TimeStamp(status.LastScanned.Unix())
	}
	ctx.Data["TotalSecretAlerts"] = ctx.Data["SecretOpenCount"].(int64) + ctx.Data["SecretClosedCount"].(int64)
	ctx.Data["MaxCommentLen"] = secretscan_model.MaxCommentLen
	pager := context.NewPagination(int(total), secretPageSize, opts.Page, 5)
	for k, v := range map[string]string{"state": ctx.FormString("state"), "q": opts.PathQuery, "type": typ, "found": found, "reason": reason, "sort": sort} {
		if v != "" {
			pager.AddParamString(k, v)
		}
	}
	ctx.Data["Page"] = pager
	ctx.HTML(http.StatusOK, tplSecretAlerts)
}

// secretOffNotes adds what the banner of a list says while scanning is off: which level decides, and for the
// repository's own switch who turned it off and when.
func secretOffNotes(ctx *context.Context) error {
	if ctx.Data["SecretScanningOn"] == true {
		return nil
	}
	sw, err := secretscan_service.GetRepoSwitch(ctx, ctx.Repo.Repository)
	if err != nil {
		return err
	}
	ctx.Data["Switch"] = sw
	if sw.Site && !sw.Own && (sw.Org == nil || sw.CanChange()) {
		change, err := secretscan_service.LastSwitchChange(ctx, ctx.Repo.Repository.ID)
		if err != nil || change == nil || change.On {
			return err
		}
		ctx.Data["OffBy"], ctx.Data["OffAt"] = secretActorName(ctx, change.ActorID, change.ActorName), change.CreatedUnix
	}
	return nil
}

func secretActorName(ctx *context.Context, id int64, fallback string) string {
	if id > 0 {
		if u, err := user_model.GetUserByID(ctx, id); err == nil {
			return u.GetDisplayName()
		}
	}
	return fallback
}

// secretActorNames is secretActorName for the actors of a history, in one query.
func secretActorNames(ctx *context.Context, history []*secretscan_service.Event) ([]*secretHistoryRow, error) {
	ids := make([]int64, 0, len(history))
	for _, e := range history {
		if e.ActorID > 0 {
			ids = append(ids, e.ActorID)
		}
	}
	users, err := user_model.GetUsersByIDsWithBots(ctx, ids)
	if err != nil {
		return nil, err
	}
	rows := make([]*secretHistoryRow, 0, len(history))
	for _, e := range history {
		name := e.ActorName
		if u := users[e.ActorID]; u != nil {
			name = u.GetDisplayName()
		}
		rows = append(rows, &secretHistoryRow{Event: e, Actor: name})
	}
	return rows, nil
}

// loadSecretAlertForPage finds the alert by its number; an alert only in the wiki is missing for someone without Wiki
// read, as in the API.
func loadSecretAlertForPage(ctx *context.Context) *secretscan_model.Alert {
	alert, err := secretscan_model.GetVisibleAlert(ctx, ctx.Repo.Repository.ID, ctx.ParamsInt64(":index"), ctx.Repo.CanRead(unit.TypeWiki))
	switch {
	case errors.Is(err, secretscan_model.ErrAlertNotExist):
		ctx.NotFound("GetAlert", err)
	case err != nil:
		ctx.ServerError("GetAlert", err)
	default:
		return alert
	}
	return nil
}

type secretGuidance struct {
	Key, Provider, URL string
}

// providerDocs are the pages where a provider explains revoking its credentials.
var providerDocs = map[string]secretGuidance{
	"aws":    {URL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
	"slack":  {URL: "https://api.slack.com/authentication/best-practices"},
	"github": {URL: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation"},
	"gitlab": {URL: "https://docs.gitlab.com/user/profile/personal_access_tokens/"},
	"gcp":    {URL: "https://cloud.google.com/iam/docs/keys-create-delete"},
	"azure":  {URL: "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"},
	"stripe": {URL: "https://docs.stripe.com/keys"},
}

// guidanceFor is the help box of a type of secret: what to do first, and where the provider explains revoking it.
func guidanceFor(secretType string) secretGuidance {
	switch secretType {
	case "private-key":
		return secretGuidance{Key: "private_key"}
	case "generic":
		return secretGuidance{Key: "generic"}
	}
	if g, ok := providerDocs[secretType]; ok {
		g.Key, g.Provider = "provider", secretType
		return g
	}
	return secretGuidance{Key: "other"}
}

type secretHistoryRow struct {
	*secretscan_service.Event
	Actor string
}

// SecretAlert shows one alert: its places, and what the audit log recorded about it.
func SecretAlert(ctx *context.Context) {
	alert := loadSecretAlertForPage(ctx)
	if alert == nil {
		return
	}
	repo := ctx.Repo.Repository
	canReadWiki := ctx.Repo.CanRead(unit.TypeWiki)
	rows, err := buildSecretRows(ctx, []*secretscan_model.Alert{alert}, canReadWiki)
	if err != nil {
		ctx.ServerError("buildSecretRows", err)
		return
	}
	row := rows[0]
	locOpts := &secretscan_model.LocationSearchOptions{
		ListOptions: db.ListOptions{Page: max(ctx.FormInt("page"), 1), PageSize: secretLocPerPage},
		RepoID:      repo.ID, AlertID: alert.ID, NoWiki: !canReadWiki,
	}
	locs, total, err := db.FindAndCount[secretscan_model.Location](ctx, locOpts)
	if err != nil {
		ctx.ServerError("FindAndCount", err)
		return
	}
	stored, err := secretscan_model.CountLocations(ctx, repo.ID, []int64{alert.ID}, false)
	if err != nil {
		ctx.ServerError("CountLocations", err)
		return
	}
	history, err := secretscan_service.AlertHistory(ctx, repo.ID, alert.ID)
	if err != nil {
		ctx.ServerError("AlertHistory", err)
		return
	}
	events, err := secretActorNames(ctx, history)
	if err != nil {
		ctx.ServerError("secretActorNames", err)
		return
	}
	ctx.Data["Title"] = row.Name
	ctx.Data["Alert"] = row
	ctx.Data["ShortFingerprint"] = alert.Fingerprint[:min(12, len(alert.Fingerprint))]
	texts, err := secretscan_model.LoadTextPlaces(ctx, repo.ID, locs, secretTextAccess(ctx))
	if err != nil {
		ctx.ServerError("LoadTextPlaces", err)
		return
	}
	kinds, err := secretscan_model.LocationKinds(ctx, repo.ID, alert.ID)
	if err != nil {
		ctx.ServerError("LocationKinds", err)
		return
	}
	hasText := slices.ContainsFunc(kinds, func(k string) bool { return slices.Contains(secretscan_model.TextKinds, k) })
	onlyText := hasText && !slices.ContainsFunc(kinds, func(k string) bool { return !slices.Contains(secretscan_model.TextKinds, k) })
	ctx.Data["TextOnly"], ctx.Data["TextAlso"] = onlyText, hasText && !onlyText
	for _, p := range texts {
		if !p.Readable && !p.Deleted {
			ctx.Data["AnyHidden"] = true // a place the viewer is not told about
		}
	}
	posters := make([]*user_model.User, len(locs)) // the poster of each place, for the profile link
	for i, l := range locs {
		if p := texts[l.ID]; p != nil && p.Readable {
			posters[i] = p.Poster
		}
	}
	ctx.Data["Posters"] = posters
	ctx.Data["RedactedMark"] = secretscan_service.RedactedMark
	ctx.Data["Locations"] = convert.ToSecretScanningLocations(repo, locs, texts, func(path string) string { return wiki_service.PageHTMLURL(repo, path) })
	titles := map[string]string{}
	for _, l := range locs {
		if l.Kind == secretscan_model.KindWiki {
			if wp, err := wiki_service.GitPathToWebPath(l.Path); err == nil {
				_, titles[l.Path] = wiki_service.WebPathToUserTitle(wp)
			}
		}
	}
	ctx.Data["WikiTitles"] = titles
	ctx.Data["NotListed"] = max(alert.LocationCount-stored[alert.ID], 0) // places over the cap, which have no row
	ctx.Data["Guidance"] = guidanceFor(alert.SecretType)
	ctx.Data["History"] = events
	ctx.Data["MaxCommentLen"] = secretscan_model.MaxCommentLen
	ctx.Data["Page"] = context.NewPagination(int(total), secretLocPerPage, locOpts.Page, 5)
	ctx.HTML(http.StatusOK, tplSecretAlert)
}

// secretAlertError flashes the refusal of a close or reopen; it reports whether err was one.
func secretAlertError(ctx *context.Context, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, util.ErrNotExist):
		ctx.NotFound("alert", err)
	case errors.Is(err, secretscan_service.ErrArchived):
		ctx.Flash.Error(ctx.Tr("repo.archive.title"))
	case errors.Is(err, secretscan_service.ErrCommentRequired):
		ctx.Flash.Error(ctx.Tr("repo.secrets.close.wont_fix_comment"))
	case errors.Is(err, secretscan_service.ErrCommentSecret):
		ctx.Flash.Error(ctx.Tr("repo.secrets.close.comment_secret"))
	case errors.Is(err, secretscan_service.ErrCommentTooCostly):
		ctx.Flash.Error(ctx.Tr("repo.secrets.close.comment_costly"))
	case errors.Is(err, util.ErrInvalidArgument):
		ctx.Flash.Error(ctx.Tr("repo.secrets.close.invalid", secretscan_model.MaxCommentLen))
	case errors.Is(err, secretscan_service.ErrConflict):
		ctx.Flash.Error(ctx.Tr("repo.secrets.alert.conflict"))
	default:
		ctx.ServerError("alert", err)
	}
	return true
}

// closeForm reads the reason and the comment of a close: a reason is required (the service wants a comment for won't fix).
func closeForm(ctx *context.Context) (reason, comment string, ok bool) {
	reason, comment = strings.TrimSpace(ctx.FormString("reason")), ctx.FormString("comment")
	switch {
	case !slices.Contains(secretscan_model.ClosedStates, reason):
		ctx.Flash.Error(ctx.Tr("repo.secrets.close.no_reason"))
	default:
		return reason, comment, true
	}
	return "", "", false
}

func secretAlertLink(ctx *context.Context) string {
	return ctx.Repo.RepoLink + "/security/secrets/" + strconv.FormatInt(ctx.ParamsInt64(":index"), 10)
}

// SecretAlertClose closes an alert with a reason and a comment, through the same service as the API.
func SecretAlertClose(ctx *context.Context) {
	if !mustWriteSecretAlerts(ctx) || loadSecretAlertForPage(ctx) == nil {
		return
	}
	if reason, comment, ok := closeForm(ctx); ok {
		_, err := secretscan_service.Close(ctx, ctx.Repo.Repository, ctx.Doer, ctx.ParamsInt64(":index"), reason, comment, ctx.Repo.CanRead(unit.TypeWiki))
		if secretAlertError(ctx, err) {
			if ctx.Written() {
				return
			}
		} else {
			ctx.Flash.Success(ctx.Tr("repo.secrets.alert.closed_done"))
		}
	}
	ctx.Redirect(secretAlertLink(ctx))
}

// SecretAlertReopen reopens a closed alert.
func SecretAlertReopen(ctx *context.Context) {
	if !mustWriteSecretAlerts(ctx) {
		return
	}
	alert := loadSecretAlertForPage(ctx)
	if alert == nil {
		return
	}
	if alert.State == secretscan_model.StateOpen {
		ctx.Flash.Warning(ctx.Tr("repo.secrets.alert.already_open"))
		ctx.Redirect(secretAlertLink(ctx))
		return
	}
	_, err := secretscan_service.Reopen(ctx, ctx.Repo.Repository, ctx.ParamsInt64(":index"))
	if secretAlertError(ctx, err) {
		if ctx.Written() {
			return
		}
	} else {
		ctx.Flash.Success(ctx.Tr("repo.secrets.alert.reopened_done"))
	}
	ctx.Redirect(secretAlertLink(ctx))
}

// SecretAlertRedact removes the secret of the alert from one text of an issue or pull request (see
// secretscan_service.RedactText): someone who may close the alert, and reads that text.
func SecretAlertRedact(ctx *context.Context) {
	if !mustWriteSecretAlerts(ctx) || loadSecretAlertForPage(ctx) == nil {
		return
	}
	target := secretscan_service.RedactTarget{Issue: ctx.FormInt64("issue"), Field: ctx.FormString("field"), Comment: ctx.FormInt64("comment")}
	res, err := secretscan_service.RedactText(ctx, ctx.Repo.Repository, ctx.Doer, ctx.ParamsInt64(":index"), target, secretTextAccess(ctx), ctx.Repo.CanRead(unit.TypeWiki))
	title := target.Field == "title"
	switch {
	case err == nil && res.Replaced > 0 && title:
		ctx.Flash.Success(ctx.Tr("repo.secrets.redact.done_title", secretscan_service.RedactedMark))
	case err == nil && res.Replaced > 0:
		ctx.Flash.Success(ctx.Tr("repo.secrets.redact.done", secretscan_service.RedactedMark))
	case err == nil && res.Cleaned && title:
		ctx.Flash.Success(ctx.Tr("repo.secrets.redact.history_only_title"))
	case err == nil && res.Cleaned:
		ctx.Flash.Success(ctx.Tr("repo.secrets.redact.history_only"))
	case err == nil:
		ctx.Flash.Success(ctx.Tr("repo.secrets.redact.marked_removed"))
	case errors.Is(err, secretscan_service.ErrRedactTarget):
		ctx.NotFound("SecretAlertRedact", err)
		return
	case errors.Is(err, secretscan_service.ErrRedactGone):
		ctx.Flash.Info(ctx.Tr("repo.secrets.redact.gone"))
	case errors.Is(err, secretscan_service.ErrRedactManual):
		ctx.Flash.Error(ctx.Tr("repo.secrets.redact.manual"))
	case errors.Is(err, secretscan_service.ErrRedactPattern):
		ctx.Flash.Error(ctx.Tr("repo.secrets.redact.pattern"))
	case errors.Is(err, secretscan_service.ErrRedactChanged):
		ctx.Flash.Error(ctx.Tr("repo.secrets.redact.changed"))
	case errors.Is(err, util.ErrInvalidArgument): // none other is expected: never the close form's message
		ctx.ServerError("SecretAlertRedact", err)
		return
	case secretAlertError(ctx, err) && ctx.Written():
		return
	}
	ctx.Redirect(secretAlertLink(ctx))
}

// SecretAlertsClose closes the selected alerts of the list with one reason, one alert at a time through the service
// (an audit entry each); the comment is checked once. The ones that can't be closed (gone, closed meanwhile, wiki
// only for this viewer) are counted. It goes back to the list the form was sent from, with its filters.
func SecretAlertsClose(ctx *context.Context) {
	if !mustWriteSecretAlerts(ctx) {
		return
	}
	list := ctx.Repo.RepoLink + "/security/secrets"
	back := list
	if ref, err := url.Parse(ctx.Req.Referer()); err == nil && strings.HasSuffix(ref.Path, "/security/secrets") && ref.RawQuery != "" {
		back += "?" + ref.RawQuery // only the query of the list: never a host or a path of the referer
	}
	reason, comment, ok := closeForm(ctx)
	// the alerts by number, not by text: 4, 04 and 004 are one alert
	var selected []int64
	invalid := 0
	for _, raw := range slices.Compact(slices.Sorted(slices.Values(ctx.Req.PostForm["index"]))) {
		if index, err := strconv.ParseInt(raw, 10, 64); err != nil {
			invalid++
		} else {
			selected = append(selected, index)
		}
	}
	slices.Sort(selected)
	selected = slices.Compact(selected)
	if ok && (len(selected)+invalid == 0 || len(selected)+invalid > maxBulkClose) {
		ctx.Flash.Error(ctx.Tr("repo.secrets.bulk.none", maxBulkClose))
		ok = false
	}
	canReadWiki := ctx.Repo.CanRead(unit.TypeWiki)
	if ok {
		var err error
		if comment, err = secretscan_service.CheckComment(ctx, ctx.Repo.Repository, comment, canReadWiki); err == nil && reason == secretscan_model.StateWontFix && comment == "" {
			err = secretscan_service.ErrCommentRequired
		}
		if ok = !secretAlertError(ctx, err); ctx.Written() {
			return
		}
	}
	if !ok {
		ctx.Redirect(back)
		return
	}
	closed, failed := 0, invalid
	for _, index := range selected {
		alert, err := secretscan_model.GetVisibleAlert(ctx, ctx.Repo.Repository.ID, index, canReadWiki)
		if err == nil {
			_, err = secretscan_service.CloseChecked(ctx, ctx.Repo.Repository, ctx.Doer, alert.Index, reason, comment)
		}
		switch {
		case err == nil:
			closed++
		case errors.Is(err, secretscan_model.ErrAlertNotExist), errors.Is(err, secretscan_service.ErrConflict):
			failed++
		case errors.Is(err, secretscan_service.ErrArchived):
			ctx.Flash.Error(ctx.Tr("repo.archive.title"))
			ctx.Redirect(back)
			return
		default:
			ctx.ServerError("SecretAlertsClose", err)
			return
		}
	}
	if closed > 0 {
		ctx.Flash.Success(ctx.Locale.TrPluralString(closed, "repo.secrets.bulk.closed", closed))
	}
	if failed > 0 {
		ctx.Flash.Warning(ctx.Locale.TrPluralString(failed, "repo.secrets.bulk.failed", failed))
	}
	ctx.Redirect(back)
}

// SecretRescan scans the repository again from the beginning (a repository admin's action).
func SecretRescan(ctx *context.Context) {
	if ctx.Data["CanRescan"] != true {
		ctx.NotFound("SecretRescan", nil)
		return
	}
	switch err := secretscan_service.Rescan(ctx, ctx.Repo.Repository); {
	case errors.Is(err, secretscan_service.ErrNotEnabled):
		ctx.Flash.Error(ctx.Tr("repo.secrets.rescan.off"))
	case err != nil:
		ctx.ServerError("Rescan", err)
		return
	default:
		ctx.Flash.Success(ctx.Tr("repo.secrets.rescan.started"))
	}
	ctx.Redirect(ctx.Repo.RepoLink + "/security/secrets")
}
