// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secrets

import (
	"context"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	secret_model "forgejo.org/models/secret"
)

// CreateOrUpdateSecret creates or updates a secret of an owner, a project, a repository, or (environmentID not 0) an
// environment of the repository; the secret of an environment only by the doer's own act (audit_model.CheckOwnAct).
func CreateOrUpdateSecret(ctx context.Context, ownerID, groupID, repoID, environmentID int64, name, data string) (*secret_model.Secret, bool, error) {
	if environmentID != 0 { // an environment's secrets are part of its deployment protection, like its rules
		if err := audit_model.CheckOwnAct(ctx); err != nil {
			return nil, false, err
		}
	}
	if err := secret_model.ValidateName(name); err != nil {
		return nil, false, err
	}

	s, exists, err := db.Get[secret_model.Secret](ctx, secret_model.FindSecretsOptions{
		OwnerID:       ownerID,
		GroupID:       groupID,
		RepoID:        repoID,
		EnvironmentID: environmentID,
		Name:          name,
	}.ToConds())
	if err != nil {
		return nil, false, err
	}

	if !exists {
		insert := func() (*secret_model.Secret, error) {
			if environmentID != 0 {
				return secret_model.InsertEncryptedEnvironmentSecret(ctx, repoID, environmentID, name, data)
			}
			return secret_model.InsertEncryptedSecret(ctx, ownerID, groupID, repoID, name, data)
		}
		s, err := insert()
		if err != nil {
			return nil, false, err
		}
		return s, true, nil
	}

	s.SetData(data)
	if err := secret_model.UpdateSecret(ctx, s, true, "data"); err != nil {
		return nil, false, err
	}
	return s, false, nil
}

func DeleteSecretByID(ctx context.Context, ownerID, groupID, repoID, secretID int64) error {
	s, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{
		OwnerID:  ownerID,
		GroupID:  groupID,
		RepoID:   repoID,
		SecretID: secretID,
	})
	if err != nil {
		return err
	}
	if len(s) != 1 {
		return secret_model.ErrSecretNotFound{}
	}

	return deleteSecret(ctx, s[0])
}

func DeleteSecretByName(ctx context.Context, ownerID, groupID, repoID, environmentID int64, name string) error {
	if environmentID != 0 {
		if err := audit_model.CheckOwnAct(ctx); err != nil {
			return err
		}
	}
	s, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{
		OwnerID:       ownerID,
		GroupID:       groupID,
		RepoID:        repoID,
		EnvironmentID: environmentID,
		Name:          name,
	})
	if err != nil {
		return err
	}
	if len(s) != 1 {
		return secret_model.ErrSecretNotFound{}
	}

	return deleteSecret(ctx, s[0])
}

func deleteSecret(ctx context.Context, s *secret_model.Secret) error {
	return secret_model.DeleteSecret(ctx, s)
}
