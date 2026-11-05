// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package asymkey

import (
	"context"
	"fmt"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// ________                .__                 ____  __.
// \______ \   ____ ______ |  |   ____ ___.__.|    |/ _|____ ___.__.
//  |    |  \_/ __ \\____ \|  |  /  _ <   |  ||      <_/ __ <   |  |
//  |    `   \  ___/|  |_> >  |_(  <_> )___  ||    |  \  ___/\___  |
// /_______  /\___  >   __/|____/\____// ____||____|__ \___  > ____|
//         \/     \/|__|               \/             \/   \/\/
//
// This file contains functions specific to DeployKeys

// DeployKey represents deploy key information and its relation with repository.
type DeployKey struct {
	ID          int64 `xorm:"pk autoincr"`
	KeyID       int64 `xorm:"UNIQUE(s) INDEX"`
	RepoID      int64 `xorm:"UNIQUE(s) INDEX"`
	Name        string
	Fingerprint string
	Content     string `xorm:"-"`

	Mode        perm.AccessMode    `xorm:"NOT NULL DEFAULT 1"`
	ExpiresUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"` // 0 = never; per repo, the shared PublicKey row has none
	CreatorID   int64              `xorm:"NOT NULL DEFAULT 0"` // the user who added the key, 0 = not recorded

	CreatedUnix       timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix       timeutil.TimeStamp `xorm:"updated"`
	HasRecentActivity bool               `xorm:"-"`
	HasUsed           bool               `xorm:"-"`
}

// AfterLoad is invoked from XORM after setting the values of all fields of this object.
func (key *DeployKey) AfterLoad() {
	key.HasUsed = key.UpdatedUnix > key.CreatedUnix
	key.HasRecentActivity = key.UpdatedUnix.AddDuration(7*24*time.Hour) > timeutil.TimeStampNow()
}

// IsExpired reports whether the deploy key has an expiry date that has passed.
func (key *DeployKey) IsExpired() bool {
	return key.ExpiresUnix != 0 && timeutil.TimeStampNow() >= key.ExpiresUnix
}

// GetContent gets associated public key content.
func (key *DeployKey) GetContent(ctx context.Context) error {
	pkey, err := GetPublicKeyByID(ctx, key.KeyID)
	if err != nil {
		return err
	}
	key.Content = pkey.Content
	return nil
}

// IsReadOnly checks if the key can only be used for read operations, used by template
func (key *DeployKey) IsReadOnly() bool {
	return key.Mode == perm.AccessModeRead
}

func init() {
	db.RegisterModel(new(DeployKey))
}

func checkDeployKey(ctx context.Context, keyID, repoID int64, name string) error {
	// Note: We want error detail, not just true or false here.
	has, err := db.GetEngine(ctx).
		Where("key_id = ? AND repo_id = ?", keyID, repoID).
		Get(new(DeployKey))
	if err != nil {
		return err
	} else if has {
		return ErrDeployKeyAlreadyExist{keyID, repoID}
	}

	has, err = db.GetEngine(ctx).
		Where("repo_id = ? AND name = ?", repoID, name).
		Get(new(DeployKey))
	if err != nil {
		return err
	} else if has {
		return ErrDeployKeyNameAlreadyUsed{repoID, name}
	}

	return nil
}

// addDeployKey adds new key-repo relation.
func addDeployKey(ctx context.Context, keyID, repoID int64, name, fingerprint string, mode perm.AccessMode, expires timeutil.TimeStamp) (*DeployKey, error) {
	if err := checkDeployKey(ctx, keyID, repoID, name); err != nil {
		return nil, err
	}

	key := &DeployKey{
		KeyID:       keyID,
		RepoID:      repoID,
		Name:        name,
		Fingerprint: fingerprint,
		Mode:        mode,
		ExpiresUnix: expires,
		CreatorID:   keyCreatorID(ctx),
	}
	return key, db.Insert(ctx, key)
}

// AddDeployKey add new deploy key to database and authorized_keys file.
func AddDeployKey(ctx context.Context, repoID int64, name, content string, readOnly bool, expires timeutil.TimeStamp) (*DeployKey, error) {
	fingerprint, err := CalcFingerprint(content)
	if err != nil {
		return nil, err
	}

	accessMode := perm.AccessModeRead
	if !readOnly {
		accessMode = perm.AccessModeWrite
	}

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return nil, err
	}
	defer committer.Close()

	pkey, added, err := getOrAddDeployPublicKey(ctx, name, content, fingerprint, accessMode)
	if err != nil {
		return nil, err
	}

	key, err := addDeployKey(ctx, pkey.ID, repoID, name, pkey.Fingerprint, accessMode, expires)
	if err != nil {
		return nil, err
	}
	if err := RecordDeployKey(ctx, "credential.deploy_key.created", key); err != nil {
		return nil, err
	}
	if err := committer.Commit(); err != nil {
		return nil, err
	}
	if added {
		return key, appendKeyAfterCommit(pkey)
	}
	return key, nil
}

// getOrAddDeployPublicKey returns the deploy public key with the fingerprint, shared by repository and organization
// deploy keys, and adds it if it doesn't exist, which it reports so that the caller appends it to the authorized_keys
// file after its commit. A key of another type (a user's) is refused.
func getOrAddDeployPublicKey(ctx context.Context, name, content, fingerprint string, mode perm.AccessMode) (*PublicKey, bool, error) {
	pkey, exist, err := db.Get[PublicKey](ctx, builder.Eq{"fingerprint": fingerprint})
	if err != nil {
		return nil, false, err
	} else if exist {
		if pkey.Type != KeyTypeDeploy {
			return nil, false, ErrKeyAlreadyExist{0, fingerprint, ""}
		}
		return pkey, false, nil
	}
	// First time use this deploy key.
	pkey = &PublicKey{
		Fingerprint: fingerprint,
		Mode:        mode,
		Type:        KeyTypeDeploy,
		Content:     content,
		Name:        name,
	}
	if err = addKey(ctx, pkey); err != nil {
		return nil, false, fmt.Errorf("addKey: %w", err)
	}
	return pkey, true, nil
}

// GetDeployKeyByID returns deploy key by given ID.
func GetDeployKeyByID(ctx context.Context, id int64) (*DeployKey, error) {
	key, exist, err := db.GetByID[DeployKey](ctx, id)
	if err != nil {
		return nil, err
	} else if !exist {
		return nil, ErrDeployKeyNotExist{id, 0, 0}
	}
	return key, nil
}

// IsDeployKeyExistByKeyID return true if there is at least one repository or organization deploy key with the key id
func IsDeployKeyExistByKeyID(ctx context.Context, keyID int64) (bool, error) {
	has, err := db.GetEngine(ctx).Where("key_id = ?", keyID).Exist(new(DeployKey))
	if err != nil || has {
		return has, err
	}
	return db.GetEngine(ctx).Where("key_id = ?", keyID).Exist(new(OrgDeployKey))
}

// UpdateDeployKeyCols updates deploy key information in the specified columns.
func UpdateDeployKeyCols(ctx context.Context, key *DeployKey, cols ...string) error {
	_, err := db.GetEngine(ctx).ID(key.ID).Cols(cols...).Update(key)
	return err
}

// ListDeployKeysOptions are options for ListDeployKeys
type ListDeployKeysOptions struct {
	db.ListOptions
	RepoID      int64
	KeyID       int64
	Fingerprint string
}

func (opt ListDeployKeysOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	if opt.RepoID != 0 {
		cond = cond.And(builder.Eq{"repo_id": opt.RepoID})
	}
	if opt.KeyID != 0 {
		cond = cond.And(builder.Eq{"key_id": opt.KeyID})
	}
	if opt.Fingerprint != "" {
		cond = cond.And(builder.Eq{"fingerprint": opt.Fingerprint})
	}
	return cond
}

type keyCreatorKey struct{}

// WithKeyCreator names the user a deploy key added with ctx is recorded for, when the request actor is not that user
// (the Bitbucket import runs as the importing admin on the command line).
func WithKeyCreator(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, keyCreatorKey{}, userID)
}

// keyCreatorID is the user who adds a deploy key: the one named by WithKeyCreator, else the user acting in the
// request; 0 when there is none (a push with such a key can't be attributed, see PullPushers).
func keyCreatorID(ctx context.Context) int64 {
	if id, ok := ctx.Value(keyCreatorKey{}).(int64); ok {
		return id
	}
	if a := audit_model.ActorFromContext(ctx); a != nil && a.Type == audit_model.ActorUser && a.ID > 0 {
		return a.ID
	}
	return 0
}
