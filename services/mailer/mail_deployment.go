// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mailer

import (
	"bytes"
	"context"
	"fmt"
	"time"

	actions_model "forgejo.org/models/actions"
	access_model "forgejo.org/models/perm/access"
	"forgejo.org/models/unit"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/base"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/translation"
)

const (
	tplDeploymentReview  base.TplName = "actions/deployment_review"
	tplDeploymentDecided base.TplName = "actions/deployment_decided"
)

// DeploymentMail is what a mail about one deployment shows: no secret and no log line.
type DeploymentMail struct {
	Run         *actions_model.ActionRun // its Repo loaded
	JobName     string
	Environment string
	Deployment  *actions_model.ActionDeployment
	TriggerUser *user_model.User // who started the attempt
	Reviewer    *user_model.User // who rejected it, nil if it expired
	Expires     time.Time        // when a review that nobody gives expires
}

// MailDeploymentReview mails the reviewers that the deployment waits for one of them. The caller decides who may
// review it (each can read the repository's Actions); each recipient's notification settings apply.
func MailDeploymentReview(ctx context.Context, reviewers []*user_model.User, m *DeploymentMail) error {
	return mailDeployment(ctx, reviewers, m, tplDeploymentReview, false)
}

// MailDeploymentDecided mails the user who started the attempt that its deployment was rejected or expired, unless
// they can no longer read the repository's Actions.
func MailDeploymentDecided(ctx context.Context, u *user_model.User, m *DeploymentMail) error {
	return mailDeployment(ctx, []*user_model.User{u}, m, tplDeploymentDecided, true)
}

func mailDeployment(ctx context.Context, users []*user_model.User, m *DeploymentMail, tpl base.TplName, checkAccess bool) error {
	if setting.MailService == nil || len(users) == 0 {
		return nil
	}
	repo := m.Run.Repo
	ids := make([]int64, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	filter, err := newEmailFilter(ctx, repo.ID, ids...)
	if err != nil {
		return err
	}
	for _, u := range users {
		if !u.IsActive || u.ProhibitLogin || u.Email == "" || !filter.ShouldEmail(u, user_model.NotifyEventDeployments) {
			continue
		}
		if checkAccess && !access_model.CheckRepoUnitUser(ctx, repo, u, unit.TypeActions) {
			continue
		}
		locale := translation.NewLocale(u.Language)
		data := map[string]any{
			"locale":      locale,
			"Language":    locale.Language(),
			"Link":        m.Run.HTMLURL(),
			"Repo":        repo.FullName(),
			"Run":         m.Run,
			"Job":         m.JobName,
			"Environment": m.Environment,
			"Deployment":  m.Deployment,
			"Ref":         git.RefName(m.Deployment.Ref).ShortName(),
			"Commit":      base.ShortSha(m.Deployment.CommitSHA),
			"TriggerUser": visibleName(ctx, m.TriggerUser, u),
			"Reviewer":    visibleName(ctx, m.Reviewer, u),
			"Expires":     m.Expires.Format("2006-01-02 15:04 -07:00"),
		}
		var content bytes.Buffer
		if err := bodyTemplates.ExecuteTemplate(&content, string(tpl), data); err != nil {
			return err
		}
		subject := locale.TrString("mail.actions.deployment_expired_subject", m.Environment)
		switch {
		case tpl == tplDeploymentReview:
			subject = locale.TrString("mail.actions.deployment_review_subject", m.Environment)
		case m.Deployment.Status == actions_model.DeploymentRejected:
			subject = locale.TrString("mail.actions.deployment_rejected_subject", m.Environment)
		}
		subject = fmt.Sprintf("[%s] %s", repo.FullName(), subject)
		msg := NewMessage(u.EmailTo(), subject, content.String())
		msg.Info = subject
		SendAsync(msg)
	}
	return nil
}

// visibleName is the display name of u for the recipient, the ghost's for a user the recipient can't see.
func visibleName(ctx context.Context, u, recipient *user_model.User) string {
	if u == nil {
		return ""
	}
	if !user_model.IsUserVisibleToViewer(ctx, u, recipient) {
		u = user_model.NewGhostUser()
	}
	return u.GetDisplayName()
}
