// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package asymkey

import (
	"context"
	"maps"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
)

// RecordPublicKey records a change of the user's SSH key or principal in the audit log, never its content.
func RecordPublicKey(ctx context.Context, action string, key *PublicKey, extra map[string]any) error {
	keyType := "user"
	if key.Type == KeyTypePrincipal {
		keyType = "principal"
	}
	data := map[string]any{
		"name": key.Name, "fingerprint": key.Fingerprint, "key_type": keyType, "expires": int64(key.ExpiresUnix),
		"login_source_id": key.LoginSourceID,
	}
	maps.Copy(data, extra)
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: key.OwnerID, SubjectUserID: key.OwnerID,
		TargetType: "ssh_key", TargetID: key.ID, TargetName: key.Name, Data: data,
	})
}

func recordGPGKey(ctx context.Context, action string, key *GPGKey) error {
	subkeyIDs := make([]string, 0, len(key.SubsKey))
	for _, sub := range key.SubsKey {
		subkeyIDs = append(subkeyIDs, sub.KeyID)
	}
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: key.OwnerID, SubjectUserID: key.OwnerID,
		TargetType: "gpg_key", TargetID: key.ID, TargetName: key.KeyID,
		Data: map[string]any{"key_id": key.KeyID, "subkey_ids": subkeyIDs, "verified": key.Verified, "expires": int64(key.ExpiredUnix)},
	})
}

// RecordDeployKey records a change of the repository's deploy key. The scope comes from the repository row, which
// may already be in the trash or being deleted.
func RecordDeployKey(ctx context.Context, action string, key *DeployKey) error {
	var ownerID, groupID int64
	if _, err := db.GetEngine(ctx).Table("repository").Where("id = ?", key.RepoID).Cols("owner_id", "group_id").Get(&ownerID, &groupID); err != nil {
		return err
	}
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: ownerID, GroupID: groupID, RepoID: key.RepoID,
		TargetType: "deploy_key", TargetID: key.ID, TargetName: key.Name,
		Data: map[string]any{"name": key.Name, "fingerprint": key.Fingerprint, "mode": int(key.Mode), "expires": int64(key.ExpiresUnix)},
	})
}

// recordOrgDeployKey records a change of the organization's deploy key (orgAction) or of a project's (projectAction).
func recordOrgDeployKey(ctx context.Context, orgAction, projectAction string, key *OrgDeployKey, extra map[string]any) error {
	action, targetType := orgAction, "org_deploy_key"
	if key.GroupID != 0 {
		action, targetType = projectAction, "project_deploy_key"
	}
	data := map[string]any{"name": key.Name, "fingerprint": key.Fingerprint, "mode": int(key.Mode), "expires": int64(key.ExpiresUnix)}
	maps.Copy(data, extra)
	return audit_model.RecordCredential(ctx, audit_model.Event{
		Action: action, OwnerID: key.OrgID, GroupID: key.GroupID,
		TargetType: targetType, TargetID: key.ID, TargetName: key.Name, Data: data,
	})
}
