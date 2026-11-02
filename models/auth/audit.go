// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"bytes"
	"context"
	"maps"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/modules/json"
)

// appFields are the audited fields of the app: its name and where it redirects to, never its secret.
func appFields(app *OAuth2Application) map[string]any {
	uris := make([]string, 0, len(app.RedirectURIs))
	for _, u := range app.RedirectURIs {
		if u = audit_model.URL(u); u != "" {
			uris = append(uris, u)
		}
	}
	return map[string]any{"name": app.Name, "redirect_uris": uris, "confidential": app.ConfidentialClient}
}

// recordOAuth2App records a change of the app. A user's app has the user as its subject; an organization's app and
// an instance app (uid 0) have none.
func recordOAuth2App(ctx context.Context, action string, app *OAuth2Application, extra map[string]any) error {
	var subject int64
	if app.UID != 0 {
		var typ int
		// models/user can't be imported here: 0 is an individual (user_model.UserTypeIndividual)
		if _, err := db.GetEngine(ctx).Table("user").Where("id = ?", app.UID).Cols("type").Get(&typ); err != nil {
			return err
		}
		if typ == 0 {
			subject = app.UID
		}
	}
	data := appFields(app)
	maps.Copy(data, extra)
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: app.UID, SubjectUserID: subject,
		TargetType: "oauth2_app", TargetID: app.ID, TargetName: app.Name, Data: data,
	})
}

func recordGrant(ctx context.Context, action string, grant *OAuth2Grant) error {
	var appName string
	if _, err := db.GetEngine(ctx).Table("oauth2_application").Where("id = ?", grant.ApplicationID).Cols("name").Get(&appName); err != nil {
		return err
	}
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: grant.UserID, SubjectUserID: grant.UserID,
		TargetType: "oauth2_grant", TargetID: grant.ID, TargetName: appName,
		Data: map[string]any{"app_id": grant.ApplicationID, "app_name": appName, "scopes": grant.Scope},
	})
}

// IntegrationFields are the audited fields of the integration and its repositories; never its claim rules.
func IntegrationFields(ai *AuthorizedIntegration, repoIDs []int64) map[string]any {
	return map[string]any{
		"name": ai.Name, "issuer": audit_model.URL(ai.Issuer), "scopes": string(ai.Scope),
		"resource_all_repos": ai.ResourceAllRepos, "repo_ids": repoIDs, "ui": string(ai.UI),
	}
}

// RecordAuthorizedIntegration records a change of the user's authorized integration.
func RecordAuthorizedIntegration(ctx context.Context, action string, ai *AuthorizedIntegration, data map[string]any) error {
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: ai.UserID, SubjectUserID: ai.UserID,
		TargetType: "authorized_integration", TargetID: ai.ID, TargetName: ai.Name, Data: data,
	})
}

// sourceFields are the audited fields of a login source. Its configuration holds bind passwords and client secrets,
// so only whether it changed is recorded.
func sourceFields(s *Source) map[string]any {
	return map[string]any{"name": s.Name, "type": s.Type.String(), "is_active": s.IsActive, "is_sync_enabled": s.IsSyncEnabled}
}

// configChanged compares the configurations as they are in memory, before they are stored: storing one encrypts its
// secrets with a new nonce each time (and clears them from the struct), so the stored forms always differ.
func configChanged(before, after *Source) (bool, error) {
	b, err := json.Marshal(before.Cfg)
	if err != nil {
		return false, err
	}
	a, err := json.Marshal(after.Cfg)
	if err != nil {
		return false, err
	}
	return !bytes.Equal(b, a), nil
}

// RecordSource records a change of the login source s; data is merged over its audited fields.
func RecordSource(ctx context.Context, action string, s *Source, data map[string]any) error {
	fields := sourceFields(s)
	maps.Copy(fields, data)
	return audit_model.Record(ctx, audit_model.Event{
		Action: action, Result: audit_model.ResultSuccess, TargetType: "login_source", TargetID: s.ID, TargetName: s.Name,
		Data: fields,
	})
}

// recordSourceChange records admin.login_source.updated when an audited field or the configuration of the source
// differs from before.
func recordSourceChange(ctx context.Context, before, source *Source, changed bool, reason string) error {
	data := audit_model.Changes(sourceFields(before), sourceFields(source))
	if data == nil && !changed {
		return nil
	}
	if data == nil {
		data = map[string]any{}
	}
	data["config_changed"] = changed
	if reason != "" {
		data["reason"] = reason
	}
	return RecordSource(ctx, "admin.login_source.updated", source, data)
}
