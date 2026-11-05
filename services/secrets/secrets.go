// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secrets

import (
	"context"

	"forgejo.org/models/db"
	secret_model "forgejo.org/models/secret"
)

// CreateOrUpdateSecret creates or updates a secret of an owner, a project, a repository, or (environmentID not 0) an
// environment of the repository; the secret of an environment only by the doer's own act (checked by secret_model.LockLevel).
func CreateOrUpdateSecret(ctx context.Context, ownerID, groupID, repoID, environmentID int64, name, data string) (*secret_model.Secret, bool, error) {
	if err := secret_model.ValidateName(name); err != nil {
		return nil, false, err
	}
	if err := secret_model.ValidateValue(data); err != nil {
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

// CreateSecret inserts a new secret of a level as CreateOrUpdateSecret names it (an existing name is an error).
func CreateSecret(ctx context.Context, ownerID, groupID, repoID, environmentID int64, name, data string) (*secret_model.Secret, error) {
	if environmentID != 0 {
		return secret_model.InsertEncryptedEnvironmentSecret(ctx, repoID, environmentID, name, data)
	}
	return secret_model.InsertEncryptedSecret(ctx, ownerID, groupID, repoID, name, data)
}

// EditSecret renames the secret with that ID of a level, and sets its value unless data is empty (checked as
// CreateSecret checks it: after the caller normalized its line breaks); a secret of another level is util.ErrNotExist.
func EditSecret(ctx context.Context, ownerID, groupID, repoID, environmentID, id int64, name, data string) (*secret_model.Secret, error) {
	var s *secret_model.Secret
	var err error
	if environmentID != 0 {
		s, err = secret_model.GetEnvironmentSecretByID(ctx, repoID, environmentID, id)
	} else {
		s, err = secret_model.GetSecretByID(ctx, ownerID, groupID, repoID, id)
	}
	if err != nil {
		return nil, err
	}
	s.Name = name
	if data != "" {
		if err := secret_model.ValidateValue(data); err != nil {
			return nil, err
		}
		s.SetData(data)
	}
	return s, secret_model.UpdateSecret(ctx, s, data != "")
}

func DeleteSecretByID(ctx context.Context, ownerID, groupID, repoID, environmentID, secretID int64) error {
	s, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{
		OwnerID:       ownerID,
		GroupID:       groupID,
		RepoID:        repoID,
		EnvironmentID: environmentID,
		SecretID:      secretID,
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
