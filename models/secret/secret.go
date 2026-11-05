// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secret

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/keying"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"xorm.io/builder"
)

var (
	namePattern            = regexp.MustCompile("(?i)^[A-Z_][A-Z0-9_]*$")
	forbiddenPrefixPattern = regexp.MustCompile("(?i)^(FORGEJO_|GITEA_|GITHUB_|[0-9])")

	ErrInvalidName = util.NewInvalidArgumentErrorf("invalid secret name")
)

// Secret represents a secret
//
// It can be:
//  1. org/user level secret, OwnerID is org/user ID, GroupID and RepoID are 0
//  2. repo level secret, OwnerID is 0 and RepoID is repo ID
//  3. project level secret, OwnerID is the org ID, GroupID the project (repo_group) ID and RepoID is 0
//  4. environment secret, OwnerID and GroupID are 0, RepoID is the repo ID and EnvironmentID the environment
//
// Please note that it's not acceptable to have both OwnerID and RepoID to be non-zero,
// or it will be complicated to find secrets belonging to a specific owner.
// For example, conditions like `OwnerID = 1` will also return secret {OwnerID: 1, RepoID: 1},
// but it's a repo level secret, not an org/user level secret.
// To avoid this, make it clear with {OwnerID: 0, RepoID: 1} for repo level secrets.
//
// Please note that it's not acceptable to have both OwnerID and RepoID to zero, global secrets are not supported.
// It's for security reasons, admin may be not aware of that the secrets could be stolen by any user when setting them as global.
type Secret struct {
	ID            int64
	OwnerID       int64              `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL"`
	GroupID       int64              `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	RepoID        int64              `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	EnvironmentID int64              `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	Name          string             `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
	Data          []byte             `xorm:"BLOB"` // encrypted data
	CreatedUnix   timeutil.TimeStamp `xorm:"created NOT NULL"`
}

// ErrSecretNotFound represents a "secret not found" error.
type ErrSecretNotFound struct {
	Name string
}

func (err ErrSecretNotFound) Error() string {
	return fmt.Sprintf("secret was not found [name: %s]", err.Name)
}

func (err ErrSecretNotFound) Unwrap() error {
	return util.ErrNotExist
}

// InsertEncryptedSecret Creates, encrypts, and validates a new secret with yet unencrypted data and insert into database
func InsertEncryptedSecret(ctx context.Context, ownerID, groupID, repoID int64, name, data string) (*Secret, error) {
	return insertEncryptedSecret(ctx, ownerID, groupID, repoID, 0, name, data)
}

// InsertEncryptedEnvironmentSecret is InsertEncryptedSecret for a secret of an environment of the repository.
func InsertEncryptedEnvironmentSecret(ctx context.Context, repoID, environmentID int64, name, data string) (*Secret, error) {
	return insertEncryptedSecret(ctx, 0, 0, repoID, environmentID, name, data)
}

func insertEncryptedSecret(ctx context.Context, ownerID, groupID, repoID, environmentID int64, name, data string) (*Secret, error) {
	if ownerID != 0 && repoID != 0 {
		// It's trying to create a secret that belongs to a repository, but OwnerID has been set accidentally.
		// Remove OwnerID to avoid confusion; it's not worth returning an error here.
		ownerID = 0
	}
	if repoID != 0 || ownerID == 0 {
		groupID = 0
	}
	if ownerID == 0 && repoID == 0 {
		return nil, fmt.Errorf("%w: ownerID and repoID cannot be both zero, global secrets are not supported", util.ErrInvalidArgument)
	}
	if err := ValidateName(name); err != nil {
		return nil, err
	}

	secret := &Secret{
		OwnerID:       ownerID,
		GroupID:       groupID,
		RepoID:        repoID,
		EnvironmentID: environmentID,
		Name:          strings.ToUpper(name),
	}

	return secret, db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockGroup(ctx, ownerID, groupID); err != nil {
			return err
		}
		if environmentID != 0 {
			if err := LockEnvironment(ctx, repoID, environmentID); err != nil {
				return err
			}
		}
		if err := db.Insert(ctx, secret); err != nil {
			return err
		}

		secret.SetData(data)
		if _, err := db.GetEngine(ctx).ID(secret.ID).Cols("data").Update(secret); err != nil {
			return err
		}
		if environmentID != 0 {
			return recordSecret(ctx, audit_model.LevelActions{Repo: "repo.actions_env_secret.created"}, secret, nil)
		}
		return recordSecret(ctx, audit_model.LevelActions{Repo: "repo.actions_secret.created", Org: "org.actions_secret.created", Account: "account.actions_secret.created"}, secret, nil)
	})
}

// LockEnvironment takes the row lock of the environment (a no-op UPDATE: a write lock on SQLite, a row lock elsewhere)
// and returns an error wrapping util.ErrNotExist if it is gone. It is the one lock of an environment: every write of
// its secrets, variables, reviewers and rules and its delete take it first, so none can leave rows behind or merge
// with another. Call it inside a transaction.
func LockEnvironment(ctx context.Context, repoID, id int64) error {
	if _, err := db.Exec(ctx, "UPDATE `action_environment` SET repo_id = repo_id WHERE repo_id = ? AND id = ?", repoID, id); err != nil {
		return err
	}
	if ok, err := db.GetEngine(ctx).Table("action_environment").Where("repo_id = ? AND id = ?", repoID, id).Exist(); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: environment %d", util.ErrNotExist, id)
	}
	return nil
}

// recordSecret records the action of actions for the secret's level, with its name only, never its value.
func recordSecret(ctx context.Context, actions audit_model.LevelActions, s *Secret, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	data["name"] = s.Name
	if s.EnvironmentID != 0 {
		data["environment_id"] = s.EnvironmentID
	}
	return repo_model.RecordScoped(ctx, actions, s.OwnerID, s.GroupID, s.RepoID, audit_model.Event{
		TargetType: "actions_secret", TargetID: s.ID, TargetName: s.Name, Data: data,
	})
}

// DeleteSecret deletes s and records actions_secret.deleted.
func DeleteSecret(ctx context.Context, s *Secret) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockGroup(ctx, s.OwnerID, s.GroupID); err != nil {
			return err
		}
		actions := audit_model.LevelActions{Repo: "repo.actions_secret.deleted", Org: "org.actions_secret.deleted", Account: "account.actions_secret.deleted"}
		if s.EnvironmentID != 0 {
			actions = audit_model.LevelActions{Repo: "repo.actions_env_secret.deleted"}
		}
		if err := recordSecret(ctx, actions, s, nil); err != nil {
			return err
		}
		_, err := db.DeleteByID[Secret](ctx, s.ID)
		return err
	})
}

// LockGroup locks the project row (nothing for groupID 0), so that deleting the project (which deletes its secrets)
// and adding, changing or deleting one run one after the other and a secret never outlives its project.
func LockGroup(ctx context.Context, ownerID, groupID int64) error {
	if groupID == 0 {
		return nil
	}
	_, err := repo_model.LockRepoGroup(ctx, ownerID, groupID)
	return err
}

func init() {
	db.RegisterModel(new(Secret))
}

type FindSecretsOptions struct {
	db.ListOptions
	RepoID  int64
	OwnerID int64 // it will be ignored if RepoID is set
	GroupID int64 // the project of OwnerID; 0 is the organization/user level itself. Ignored if RepoID is set
	// EnvironmentID is always bound: 0 finds no secret of an environment
	EnvironmentID int64
	SecretID      int64
	Name          string
}

func (opts FindSecretsOptions) ToConds() builder.Cond {
	cond := builder.NewCond()

	cond = cond.And(builder.Eq{"repo_id": opts.RepoID})
	if opts.RepoID != 0 { // if RepoID is set
		// ignore OwnerID and treat it as 0
		cond = cond.And(builder.Eq{"owner_id": 0, "group_id": 0})
	} else {
		cond = cond.And(builder.Eq{"owner_id": opts.OwnerID, "group_id": opts.GroupID})
	}
	cond = cond.And(builder.Eq{"environment_id": opts.EnvironmentID})

	if opts.SecretID != 0 {
		cond = cond.And(builder.Eq{"id": opts.SecretID})
	}
	if opts.Name != "" {
		cond = cond.And(builder.Eq{"name": strings.ToUpper(opts.Name)})
	}

	return cond
}

var _ db.FindOptionsOrder = FindSecretsOptions{}

// ToOrders implements db.FindOptionsOrder to have a stable sort order
func (opts FindSecretsOptions) ToOrders() string {
	// Sort by name. ID serves as a tie-breaker.
	return "name, id"
}

func (s *Secret) SetData(data string) {
	normalizedData := util.ReserveLineBreakForTextarea(data)
	s.Data = keying.ActionSecret.Encrypt([]byte(normalizedData), keying.ColumnAndID("data", s.ID))
}

func (s *Secret) GetDecryptedData() (string, error) {
	key := keying.ActionSecret
	v, err := key.Decrypt(s.Data, keying.ColumnAndID("data", s.ID))
	if err != nil {
		return "", fmt.Errorf("unable to decrypt secret[id=%d,name=%q]: %w", s.ID, s.Name, err)
	}

	return string(v), nil
}

func GetSecretByID(ctx context.Context, ownerID, groupID, repoID, id int64) (*Secret, error) {
	return getSecretByID(ctx, ownerID, groupID, repoID, 0, id)
}

// GetEnvironmentSecretByID returns the secret with that ID of an environment of the repository.
func GetEnvironmentSecretByID(ctx context.Context, repoID, environmentID, id int64) (*Secret, error) {
	return getSecretByID(ctx, 0, 0, repoID, environmentID, id)
}

func getSecretByID(ctx context.Context, ownerID, groupID, repoID, environmentID, id int64) (*Secret, error) {
	query := db.GetEngine(ctx).Where("id=?", id)

	if repoID > 0 {
		query = query.And(builder.Eq{"repo_id": repoID, "owner_id": 0, "group_id": 0})
	} else if ownerID > 0 {
		query = query.And(builder.Eq{"repo_id": 0, "owner_id": ownerID, "group_id": groupID})
	} else {
		return nil, fmt.Errorf("ownerID and repoID cannot be simultaneously 0")
	}
	query = query.And(builder.Eq{"environment_id": environmentID})

	var secret Secret
	has, err := query.Get(&secret)

	if err != nil {
		return nil, err
	} else if !has {
		return nil, fmt.Errorf("secret with ID %d: %w", id, util.ErrNotExist)
	}
	return &secret, nil
}

// UpdateSecret writes secret and records actions_secret.updated when its name changed or valueChanged (the request
// set a new value); the value itself is never compared or recorded.
func UpdateSecret(ctx context.Context, secret *Secret, valueChanged bool, columns ...string) error {
	if err := ValidateName(secret.Name); err != nil {
		return err
	}
	secret.Name = strings.ToUpper(secret.Name)

	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockGroup(ctx, secret.OwnerID, secret.GroupID); err != nil {
			return err
		}
		e := db.GetEngine(ctx)
		stored := new(Secret)
		if has, err := e.ID(secret.ID).Cols("name").Get(stored); err != nil {
			return err
		} else if has && (stored.Name != secret.Name || valueChanged) {
			data := audit_model.Changes(map[string]any{"name": stored.Name}, map[string]any{"name": secret.Name})
			if data == nil {
				data = map[string]any{}
			}
			data["value_changed"] = valueChanged
			actions := audit_model.LevelActions{Repo: "repo.actions_secret.updated", Org: "org.actions_secret.updated", Account: "account.actions_secret.updated"}
			if secret.EnvironmentID != 0 {
				actions = audit_model.LevelActions{Repo: "repo.actions_env_secret.updated"}
			}
			if err := recordSecret(ctx, actions, secret, data); err != nil {
				return err
			}
		}
		var err error
		if len(columns) == 0 {
			_, err = e.ID(secret.ID).AllCols().Update(secret)
		} else {
			_, err = e.ID(secret.ID).Cols(columns...).Update(secret)
		}
		return err
	})
}

// FetchActionSecrets returns the secrets of a repository; groupID is the project it is in (0 at the root of its owner).
// The closest level wins: repository, then project, then organization/user.
func FetchActionSecrets(ctx context.Context, ownerID, groupID, repoID int64) (map[string]string, error) {
	secrets := map[string]string{}

	ownerSecrets, err := db.Find[Secret](ctx, FindSecretsOptions{OwnerID: ownerID})
	if err != nil {
		log.Error("find secrets of owner %v: %v", ownerID, err)
		return nil, err
	}
	var groupSecrets []*Secret
	if groupID != 0 {
		groupSecrets, err = db.Find[Secret](ctx, FindSecretsOptions{OwnerID: ownerID, GroupID: groupID})
		if err != nil {
			log.Error("find secrets of project %v: %v", groupID, err)
			return nil, err
		}
	}
	repoSecrets, err := db.Find[Secret](ctx, FindSecretsOptions{RepoID: repoID})
	if err != nil {
		log.Error("find secrets of repo %v: %v", repoID, err)
		return nil, err
	}

	for _, secret := range slices.Concat(ownerSecrets, groupSecrets, repoSecrets) {
		decryptedData, err := secret.GetDecryptedData()
		if err != nil {
			log.Error("%v", err)
			return nil, err
		}
		secrets[secret.Name] = decryptedData
	}

	return secrets, nil
}

// FetchEnvironmentSecrets returns the secrets of an environment of the repository. The caller has checked that the
// job it is for passed the environment's gate.
func FetchEnvironmentSecrets(ctx context.Context, repoID, environmentID int64) (map[string]string, error) {
	rows, err := db.Find[Secret](ctx, FindSecretsOptions{RepoID: repoID, EnvironmentID: environmentID})
	if err != nil {
		log.Error("find secrets of environment %v: %v", environmentID, err)
		return nil, err
	}
	secrets := make(map[string]string, len(rows))
	for _, secret := range rows {
		decryptedData, err := secret.GetDecryptedData()
		if err != nil {
			log.Error("%v", err)
			return nil, err
		}
		secrets[secret.Name] = decryptedData
	}
	return secrets, nil
}

func ValidateName(name string) error {
	if !namePattern.MatchString(name) || forbiddenPrefixPattern.MatchString(name) {
		return ErrInvalidName
	}
	return nil
}
