// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"html/template"
	"slices"
	"strconv"
	"strings"

	access_model "forgejo.org/models/perm/access"
	repo_model "forgejo.org/models/repo"
	secretscan_model "forgejo.org/models/secretscan"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/log"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/translation"
	"forgejo.org/modules/util"
	vulnerability_service "forgejo.org/services/vulnerability"
)

const tplSecretDigest base.TplName = "secret/digest"

// maxDigestRecipients is the most administrators one digest is mailed to, counted after the permission and
// opt-out checks: a repository with more is logged, and the rest read the alerts on the page.
const maxDigestRecipients = 100

// SecretDigestInput is what the scan hands over after a push: the alerts above AfterAlertID are the new ones, in the
// repository's push to Ref (a short name, "" for the wiki) at Commit; PusherID is the person who pushed, 0 when nobody
// did or when the digest holds pushes of more than one person (a text has no pusher). Kinds are the secretscan_model.DigestKind* bits of what
// the pushes touched.
type SecretDigestInput struct {
	Ref, Commit  string
	PusherID     int64
	AfterAlertID int64
	UpToAlertID  int64 // the newest alert the digest may hold (0: no bound): the next digest starts after it
	Kinds        int
}

// digestKinds are the kinds of places a recipient is told about. An administrator hears of every new alert (the wiki's
// only when the wiki had been scanned before the push, and the recipient can read it); the pusher only of what they
// pushed: code for a branch or tag, the wiki for the wiki, so a fork pull request or a wiki edit is never "your push".
func digestKinds(in SecretDigestInput, isPusher, wikiRead bool) []string {
	var kinds []string
	if isPusher {
		if in.Kinds&secretscan_model.DigestKindCode != 0 {
			kinds = append(kinds, secretscan_model.KindRepo)
		}
		if in.Kinds&secretscan_model.DigestKindWiki != 0 && wikiRead {
			kinds = append(kinds, secretscan_model.KindWiki)
		}
		return kinds
	}
	kinds = []string{secretscan_model.KindRepo, secretscan_model.KindPull}
	if in.Kinds&secretscan_model.DigestKindText != 0 {
		kinds = append(kinds, secretscan_model.TextKinds...) // counted only: the mail names no issue or comment
	}
	if in.Kinds&secretscan_model.DigestWikiScanned != 0 && wikiRead {
		kinds = append(kinds, secretscan_model.KindWiki)
	}
	return kinds
}

// SendSecretDigest mails the repository's administrators one digest of the new secret alerts, and the pusher their own
// mail. Everyone is checked as they are now: an active individual with an address, who can see alerts (CanSeeAlerts)
// (the pusher too) and whose notification settings allow the event; wiki alerts need wiki read. A pusher who is an
// administrator gets the digest only. The mail never holds a secret or a fingerprint: only types, counts and places.
// It runs after the scan's transaction is committed.
func SendSecretDigest(ctx context.Context, repo *repo_model.Repository, in SecretDigestInput) error {
	if setting.MailService == nil {
		return nil
	}
	admins, err := repoAdminRecipients(ctx, repo.ID)
	if err != nil {
		return err
	}
	adminUsers := admins.users
	adminIDs := map[int64]bool{}
	for _, u := range adminUsers {
		adminIDs[u.ID] = true
	}
	users := adminUsers
	var pusher *user_model.User
	if in.PusherID > 0 && !adminIDs[in.PusherID] {
		if u, err := user_model.GetUserByID(ctx, in.PusherID); err == nil && mailable(u) {
			pusher = u
			users = append(slices.Clip(users), u)
		}
	}
	ids := make([]int64, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	filter, err := newEmailFilter(ctx, repo.ID, ids...)
	if err != nil {
		log.Error("newEmailFilter: %v", err) // fall back to the preset and defaults
	}
	labels := map[string]secretscan_model.RuleLabel{} // of the rules of the digests, read once per digest
	digests := map[string]*secretscan_model.Digest{}  // by kinds
	digestFor := func(kinds []string) (*secretscan_model.Digest, error) {
		key := strings.Join(kinds, ",")
		if d, ok := digests[key]; ok {
			return d, nil
		}
		d, err := secretscan_model.BuildDigest(ctx, repo.ID, in.AfterAlertID, in.UpToAlertID, kinds)
		digests[key] = d
		if err != nil {
			return d, err
		}
		var ruleIDs []string
		for _, t := range d.Types {
			if _, ok := labels[t.RuleID]; !ok {
				ruleIDs = append(ruleIDs, t.RuleID)
			}
		}
		rl, err := secretscan_model.LoadRuleLabels(ctx, ruleIDs)
		if err != nil {
			return d, err
		}
		for _, id := range ruleIDs {
			labels[id] = rl.Label(id, repo.OwnerID, nil) // a deleted pattern's name is for its owners' lists
		}
		return d, nil
	}
	// who gets a mail: permission and opt-out first, then the cap
	type recipient struct {
		user     *user_model.User
		wikiRead bool
		digest   *secretscan_model.Digest
	}
	eligible := func(u *user_model.User, isPusher bool) (r recipient, ok bool, err error) {
		perm, err := access_model.GetUserRepoPermission(ctx, repo, u)
		if err != nil {
			return recipient{}, false, err
		}
		if !vulnerability_service.CanSeeAlerts(&perm, false) || !filter.ShouldEmail(u, user_model.NotifyEventSecretAlert) {
			return recipient{}, false, nil // the pusher too: the mail names alerts and links to them
		}
		wikiRead := perm.CanRead(unit.TypeWiki)
		kinds := digestKinds(in, isPusher, wikiRead)
		if len(kinds) == 0 {
			return recipient{}, false, nil
		}
		d, err := digestFor(kinds)
		if err != nil || d.Alerts == 0 {
			return recipient{}, false, err
		}
		return recipient{u, wikiRead, d}, true, nil
	}
	var recipients []recipient
	for _, u := range adminUsers {
		r, ok, err := eligible(u, false)
		if err != nil {
			return err
		}
		if ok {
			recipients = append(recipients, r)
		}
	}
	if len(recipients) > maxDigestRecipients {
		log.Warn("secret digest of repository %d: %d administrators to mail, mailed to the first %d", repo.ID, len(recipients), maxDigestRecipients)
		recipients = recipients[:maxDigestRecipients]
	}
	adminsNotified := false
	for _, r := range recipients { // the administrators first: the pusher's mail says whether they were told
		if err := sendSecretDigestMail(repo, r.user, r.digest, in, labels, false, r.wikiRead, false); err != nil {
			log.Error("secret digest to %d: %v", r.user.ID, err)
			continue
		}
		adminsNotified = true
	}
	if pusher == nil {
		return nil
	}
	r, ok, err := eligible(pusher, true)
	if err != nil || !ok {
		return err
	}
	if err := sendSecretDigestMail(repo, pusher, r.digest, in, labels, true, r.wikiRead, adminsNotified); err != nil {
		log.Error("secret digest to %d: %v", pusher.ID, err)
	}
	return nil
}

func sendSecretDigestMail(repo *repo_model.Repository, u *user_model.User, d *secretscan_model.Digest, in SecretDigestInput, labels map[string]secretscan_model.RuleLabel, isPusher, wikiRead, adminsNotified bool) error {
	locale := translation.NewLocale(u.Language)
	name := repo.FullName()
	textOnly := in.Kinds&(secretscan_model.DigestKindCode|secretscan_model.DigestKindWiki) == 0 && in.Kinds&secretscan_model.DigestKindText != 0
	// the push as the mail names it: the branch as code, the commit linked (the arguments are HTML, built escaped); a
	// wiki push is named only to someone who can read the wiki; pushes of several refs are not named after the last
	where := locale.Tr("mail.secret_digest.where_push")
	switch {
	case in.Kinds&secretscan_model.DigestSeveral != 0:
		if isPusher {
			where = locale.Tr("mail.secret_digest.where_several_pusher")
		} else {
			where = locale.Tr("mail.secret_digest.where_several")
		}
	case textOnly:
		where = locale.Tr("mail.secret_digest.where_text")
	case in.Ref != "":
		where = template.HTML("<code>" + template.HTMLEscapeString(cleanDigestText(in.Ref)) + "</code>")
		if in.Commit != "" {
			short := in.Commit[:min(7, len(in.Commit))]
			link := template.HTML(`<a href="` + template.HTMLEscapeString(repo.HTMLURL()+"/commit/"+in.Commit) + `">` + template.HTMLEscapeString(short) + "</a>")
			where = locale.Tr("mail.secret_digest.where_commit", where, link)
		}
	case wikiRead:
		where = locale.Tr("mail.secret_digest.where_wiki")
	}
	type typeRow struct {
		Name  string
		Count int
	}
	types := make([]typeRow, len(d.Types))
	for i, t := range d.Types {
		types[i] = typeRow{Name: labels[t.RuleID].Text(locale), Count: t.Count}
	}
	places := make([]string, len(d.Locations))
	for i, l := range d.Locations {
		places[i] = cleanDigestText(l.Path)
		if l.StartLine > 0 {
			places[i] += ":" + strconv.Itoa(l.StartLine)
		}
		if l.Kind == secretscan_model.KindWiki {
			places[i] = locale.TrString("mail.secret_digest.wiki_place", places[i])
		}
	}
	// literal keys, so that lint-locale-usage finds them; the plural phrases escape their arguments for HTML
	var subjectHTML, intro, advice, foot, notified template.HTML
	if isPusher {
		subjectHTML = locale.TrPluralString(d.Alerts, "mail.secret_digest.subject_pusher", name)
		intro = locale.TrPluralString(d.Alerts, "mail.secret_digest.intro_pusher", where, d.Alerts)
		advice, foot = locale.TrPluralString(d.Alerts, "mail.secret_digest.advice_pusher"), locale.Tr("mail.secret_digest.foot_pusher", name)
		if adminsNotified {
			notified = locale.Tr("mail.secret_digest.admins_notified")
		}
	} else {
		subjectHTML = locale.TrPluralString(d.Alerts, "mail.secret_digest.subject", name)
		intro = locale.TrPluralString(d.Alerts, "mail.secret_digest.intro", where, d.Alerts)
		advice, foot = locale.Tr("mail.secret_digest.advice_admin"), locale.Tr("mail.secret_digest.foot_admin", name)
		if textOnly {
			advice = locale.Tr("mail.secret_digest.advice_admin_text")
		}
	}
	subject := html.UnescapeString(string(subjectHTML))
	link := repo.HTMLURL() + "/security/secrets"
	if d.FirstIndex > 0 {
		link += "/" + strconv.FormatInt(d.FirstIndex, 10) // one alert: straight to it
	}
	data := map[string]any{
		"locale":     locale,
		"Language":   locale.Language(),
		"Title":      subject,
		"Intro":      intro,
		"Types":      types,
		"Places":     places,
		"PlacesHead": locale.TrPluralString(len(places), "mail.secret_digest.places"),
		"Advice":     advice,
		"Notified":   notified,
		"Footer":     foot,
		"Settings":   setting.AppURL + "user/settings/notifications",
		"Link":       link,
		"LinkText":   locale.TrPluralString(d.Alerts, "mail.secret_digest.open"),
	}
	if d.TextAlerts > 0 && textOnly {
		data["TextNote"] = locale.Tr("mail.secret_digest.text_where") // the intro says it is in text already
	} else if d.TextAlerts > 0 {
		data["TextNote"] = locale.TrPluralString(d.TextAlerts, "mail.secret_digest.text_note", d.TextAlerts)
	}
	if d.TotalLocations > len(places) {
		data["PlacesHead"] = locale.Tr("mail.secret_digest.places_capped", len(places), d.TotalLocations)
		data["More"] = locale.TrPluralString(d.TotalLocations-len(places), "mail.secret_digest.more", d.TotalLocations-len(places))
	}
	var content bytes.Buffer
	if err := bodyTemplates.ExecuteTemplate(&content, string(tplSecretDigest), data); err != nil {
		return fmt.Errorf("ExecuteTemplate: %w", err)
	}
	msg := NewMessage(u.EmailTo(), subject, content.String())
	msg.Info = fmt.Sprintf("Secret digest: repository %d", repo.ID)
	SendAsync(msg)
	return nil
}

// cleanDigestText removes control, bidirectional and zero-width characters from a branch name or path of git: it can't
// reorder or hide the text around it in the mail.
func cleanDigestText(s string) string {
	return util.StripFormatting(util.StripControl(s))
}
