// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	lru "github.com/hashicorp/golang-lru/v2"
	"xorm.io/builder"
)

// ErrAccessTokenNotExist represents a "AccessTokenNotExist" kind of error.
type ErrAccessTokenNotExist struct {
	Token string
}

// IsErrAccessTokenNotExist checks if an error is a ErrAccessTokenNotExist.
func IsErrAccessTokenNotExist(err error) bool {
	_, ok := err.(ErrAccessTokenNotExist)
	return ok
}

func (err ErrAccessTokenNotExist) Error() string {
	return "access token does not exist"
}

func (err ErrAccessTokenNotExist) Unwrap() error {
	return util.ErrNotExist
}

// ErrAccessTokenEmpty represents a "AccessTokenEmpty" kind of error.
type ErrAccessTokenEmpty struct{}

// IsErrAccessTokenEmpty checks if an error is a ErrAccessTokenEmpty.
func IsErrAccessTokenEmpty(err error) bool {
	_, ok := err.(ErrAccessTokenEmpty)
	return ok
}

func (err ErrAccessTokenEmpty) Error() string {
	return "access token is empty"
}

func (err ErrAccessTokenEmpty) Unwrap() error {
	return util.ErrInvalidArgument
}

// ErrAccessTokenExpired represents an access token whose expiry date has passed.
type ErrAccessTokenExpired struct {
	ID, UID int64
	Name    string
	Expires timeutil.TimeStamp
}

// IsErrAccessTokenExpired checks if an error is a ErrAccessTokenExpired.
func IsErrAccessTokenExpired(err error) bool {
	_, ok := err.(ErrAccessTokenExpired)
	return ok
}

func (err ErrAccessTokenExpired) Error() string {
	return fmt.Sprintf("access token %q expired on %s", err.Name, err.Expires.FormatDate())
}

func (err ErrAccessTokenExpired) Unwrap() error {
	return util.ErrPermissionDenied
}

var successfulAccessTokenCache *lru.Cache[string, any]

// AccessToken represents a personal access token, or a token of an organization, a project or a repository (see
// AccessTokenOwnerType), which has no user (UID 0) and acts with its own permission (Mode).
type AccessToken struct {
	ID             int64                `xorm:"pk autoincr"`
	UID            int64                `xorm:"INDEX"`
	OwnerType      AccessTokenOwnerType `xorm:"NOT NULL DEFAULT 0 INDEX(owner)"`
	OwnerID        int64                `xorm:"NOT NULL DEFAULT 0 INDEX(owner)"`
	GroupID        int64                `xorm:"NOT NULL DEFAULT 0 INDEX(owner)"`
	Mode           perm.AccessMode      `xorm:"NOT NULL DEFAULT 0"`
	CreatorID      int64                `xorm:"NOT NULL DEFAULT 0"` // who created a token that isn't a personal one
	Name           string
	Description    string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	Token          string `xorm:"-"`
	TokenHash      string `xorm:"UNIQUE"` // sha256 of token
	TokenSalt      string
	TokenLastEight string `xorm:"INDEX token_last_eight"`
	Scope          AccessTokenScope

	CreatedUnix       timeutil.TimeStamp `xorm:"INDEX created"`
	UpdatedUnix       timeutil.TimeStamp `xorm:"INDEX updated"`
	HasRecentActivity bool               `xorm:"-"`
	HasUsed           bool               `xorm:"-"`

	ExpiresUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"` // 0 = never
	LastUsedIP  string             `xorm:"VARCHAR(45) NOT NULL DEFAULT ''"`

	// A token that isn't a personal one may rotate itself (POST /tokens/self/rotate). RotatedByID is the user who
	// rotated it last, or the token's own identity (AccessTokenBotID) when it rotated itself.
	SelfRotate  bool               `xorm:"NOT NULL DEFAULT false"`
	RotatedUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
	RotatedByID int64              `xorm:"NOT NULL DEFAULT 0"`

	// A revoked token that isn't a personal one keeps its row without a secret, so its name stays in history.
	RevokedUnix timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0 INDEX"`
	RevokedByID int64              `xorm:"NOT NULL DEFAULT 0"`

	ResourceAllRepos bool `xorm:"NOT NULL DEFAULT TRUE"` // flag for whether AccessTokenResourceRepo instances will limit the resources this access token can access (false) or won't limit them (true).
}

// AfterLoad is invoked from XORM after setting the values of all fields of this object.
func (t *AccessToken) AfterLoad() {
	t.HasUsed = t.UpdatedUnix > t.CreatedUnix
	t.HasRecentActivity = t.HasUsed && t.UpdatedUnix.AddDuration(7*24*time.Hour) > timeutil.TimeStampNow()
}

func init() {
	db.RegisterModel(new(AccessToken), func() error {
		if setting.SuccessfulTokensCacheSize > 0 {
			var err error
			successfulAccessTokenCache, err = lru.New[string, any](setting.SuccessfulTokensCacheSize)
			if err != nil {
				return fmt.Errorf("unable to allocate AccessToken cache: %w", err)
			}
		} else {
			successfulAccessTokenCache = nil
		}
		return nil
	})
}

// NewAccessToken creates a new access token limited to the given repositories, and records it in the audit log. A
// token acts as its owner, so creating one for someone else (an admin for a user, or an organization, project or
// repository token) is only a person's own act.
func NewAccessToken(ctx context.Context, t *AccessToken, resources []*AccessTokenResourceRepo) error {
	if err := checkMintIsOwnAct(ctx, t); err != nil {
		return err
	}
	generateAccessToken(t)
	return db.WithTx(ctx, func(ctx context.Context) error {
		if _, err := db.GetEngine(ctx).Insert(t); err != nil {
			return err
		}
		if err := InsertAccessTokenResourceRepos(ctx, t.ID, resources); err != nil {
			return err
		}
		repoIDs := make([]int64, 0, len(resources))
		for _, resourceRepo := range resources {
			repoIDs = append(repoIDs, resourceRepo.RepoID)
		}
		return recordAccessToken(ctx, "created", t, map[string]any{"after": accessTokenFields(t, repoIDs)})
	})
}

func accessTokenFields(t *AccessToken, repoIDs []int64) map[string]any {
	fields := map[string]any{
		"name":               t.Name,
		"scopes":             string(t.Scope),
		"expires":            int64(t.ExpiresUnix),
		"resource_all_repos": t.ResourceAllRepos,
		"repo_ids":           repoIDs,
	}
	if !t.IsOwnedByUser() {
		fields["mode"] = t.Mode.String()
		fields["description"] = t.Description
		fields["self_rotate"] = t.SelfRotate
	}
	return fields
}

// recordAccessToken records a change of the token in the audit log. The token's owner is read from the row, never
// from the doer, who may be an admin acting for the owner.
func recordAccessToken(ctx context.Context, verb string, t *AccessToken, data map[string]any) error {
	e := audit_model.Event{
		Action:        "credential.access_token." + verb,
		OwnerID:       t.UID,
		SubjectUserID: t.UID,
		TargetType:    "access_token",
		TargetID:      t.ID,
		TargetName:    t.Name,
		Data:          data,
	}
	switch t.OwnerType {
	case AccessTokenOwnerOrg, AccessTokenOwnerProject:
		e.OwnerID, e.GroupID = t.OwnerID, t.GroupID
	case AccessTokenOwnerRepo:
		e.OwnerID, e.RepoID = 0, t.OwnerID
	}
	return audit_model.RecordCredential(ctx, e)
}

func generateAccessToken(t *AccessToken) {
	salt := util.CryptoRandomString(util.RandomStringMedium)
	t.TokenSalt = salt
	t.Token = hex.EncodeToString(util.CryptoRandomBytes(20))
	t.TokenHash = HashToken(t.Token, t.TokenSalt)
	t.TokenLastEight = t.Token[len(t.Token)-8:]
}

// IsExpired reports whether the token has an expiry date that has passed.
func (t *AccessToken) IsExpired() bool {
	return t.ExpiresUnix != 0 && timeutil.TimeStampNow() >= t.ExpiresUnix
}

// DisplayPublicOnly whether to display this as a public-only token.
func (t *AccessToken) DisplayPublicOnly() bool {
	publicOnly, err := t.Scope.PublicOnly()
	if err != nil {
		return false
	}
	return publicOnly
}

// UpdateLastUsed records that this token was used now, from the client address ip ("" when unknown).
func (t *AccessToken) UpdateLastUsed(ctx context.Context, ip string) error {
	t.UpdatedUnix = timeutil.TimeStampNow()
	t.LastUsedIP = ip
	_, err := db.GetEngine(ctx).ID(t.ID).Cols("updated_unix", "last_used_ip").NoAutoTime().Update(t)
	return err
}

// CachedToken is what the successful token caches hold: the row and the hash that matched, so a token
// regenerated in place (same row, new hash) is not accepted from the cache.
type CachedToken struct {
	ID   int64
	Hash string
}

// TokenCacheKey is the key of a token in the successful token caches, so they don't hold the tokens themselves.
func TokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func getAccessTokenFromCache(key string) CachedToken {
	if successfulAccessTokenCache == nil {
		return CachedToken{}
	}
	tInterface, ok := successfulAccessTokenCache.Get(key)
	if !ok {
		return CachedToken{}
	}
	t, _ := tInterface.(CachedToken)
	return t
}

// GetAccessTokenBySHA returns access token by given token value
func GetAccessTokenBySHA(ctx context.Context, token string) (*AccessToken, error) {
	if token == "" {
		return nil, ErrAccessTokenEmpty{}
	}
	// A token is defined as being SHA1 sum these are 40 hexadecimal bytes long
	if len(token) != 40 {
		return nil, ErrAccessTokenNotExist{token}
	}
	for _, x := range []byte(token) {
		if x < '0' || (x > '9' && x < 'a') || x > 'f' {
			return nil, ErrAccessTokenNotExist{token}
		}
	}

	lastEight := token[len(token)-8:]
	cacheKey := TokenCacheKey(token)

	if cached := getAccessTokenFromCache(cacheKey); cached.ID > 0 {
		accessToken := &AccessToken{
			TokenLastEight: lastEight,
		}
		// Re-get the token from the db in case it has been deleted or regenerated in the intervening period
		has, err := db.GetEngine(ctx).ID(cached.ID).Get(accessToken)
		if err != nil {
			return nil, err
		}
		if has && accessToken.TokenHash == cached.Hash {
			return checkAccessTokenExpiry(accessToken)
		}
		successfulAccessTokenCache.Remove(cacheKey)
	}

	var tokens []AccessToken
	err := db.GetEngine(ctx).Table(&AccessToken{}).Where("token_last_eight = ?", lastEight).Find(&tokens)
	if err != nil {
		return nil, err
	} else if len(tokens) == 0 {
		return nil, ErrAccessTokenNotExist{token}
	}

	for _, t := range tokens {
		tempHash := HashToken(token, t.TokenSalt)
		if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(tempHash)) == 1 {
			if successfulAccessTokenCache != nil {
				successfulAccessTokenCache.Add(cacheKey, CachedToken{ID: t.ID, Hash: t.TokenHash})
			}
			return checkAccessTokenExpiry(&t)
		}
	}
	return nil, ErrAccessTokenNotExist{token}
}

func checkAccessTokenExpiry(t *AccessToken) (*AccessToken, error) {
	if t.IsRevoked() {
		return nil, ErrAccessTokenNotExist{}
	}
	if t.IsExpired() {
		return nil, ErrAccessTokenExpired{ID: t.ID, UID: t.UID, Name: t.Name, Expires: t.ExpiresUnix}
	}
	return t, nil
}

// AccessTokenByNameExists checks if a token name has been used already by a user.
func AccessTokenByNameExists(ctx context.Context, token *AccessToken) (bool, error) {
	return db.GetEngine(ctx).Table("access_token").Where("name = ?", token.Name).And("uid = ?", token.UID).Exist()
}

// ListAccessTokensOptions contain filter options
type ListAccessTokensOptions struct {
	db.ListOptions
	Name   string
	UserID int64
}

func (opts ListAccessTokensOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	// user id is required, otherwise it will return all result which maybe a possible bug
	cond = cond.And(builder.Eq{"uid": opts.UserID})
	if len(opts.Name) > 0 {
		cond = cond.And(builder.Eq{"name": opts.Name})
	}
	return cond
}

func (opts ListAccessTokensOptions) ToOrders() string {
	return "created_unix DESC"
}

// DeleteAccessTokenByID deletes access token by given ID.
func DeleteAccessTokenByID(ctx context.Context, id, userID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		t := &AccessToken{}
		if has, err := db.GetEngine(ctx).Where("id = ? AND uid = ?", id, userID).Get(t); err != nil {
			return err
		} else if !has {
			return ErrAccessTokenNotExist{}
		}
		var repoIDs []int64
		if err := db.GetEngine(ctx).Table("access_token_resource_repo").Where("token_id = ?", id).Cols("repo_id").Find(&repoIDs); err != nil {
			return err
		}
		if err := db.DeleteBeans(ctx,
			&AccessTokenResourceRepo{TokenID: id},
		); err != nil {
			return fmt.Errorf("DeleteBeans: %w", err)
		}

		cnt, err := db.GetEngine(ctx).ID(id).Delete(&AccessToken{
			UID: userID,
		})
		if err != nil {
			return err
		} else if cnt != 1 {
			return ErrAccessTokenNotExist{}
		}
		return recordAccessToken(ctx, "deleted", t, map[string]any{"before": accessTokenFields(t, repoIDs)})
	})
}

// checkMintIsOwnAct refuses a new secret of t (see NewAccessToken) unless it is the owner's request for themselves or
// a person's own act.
func checkMintIsOwnAct(ctx context.Context, t *AccessToken) error {
	if t.IsOwnedByUser() {
		return audit_model.CheckOwnActFor(ctx, t.UID)
	}
	return audit_model.CheckOwnAct(ctx)
}

// RegenerateAccessTokenByID regenerates access token by given ID.
// It regenerates token and salt, as well as updates the creation time. Like NewAccessToken, doing it for someone
// else is only a person's own act.
func RegenerateAccessTokenByID(ctx context.Context, id, userID int64) (*AccessToken, error) {
	if err := audit_model.CheckOwnActFor(ctx, userID); err != nil {
		return nil, err
	}
	t := &AccessToken{}
	return t, db.WithTx(ctx, func(ctx context.Context) error {
		found, err := db.GetEngine(ctx).Where("id = ? AND uid = ?", id, userID).Get(t)
		if err != nil {
			return err
		} else if !found {
			return ErrAccessTokenNotExist{}
		}

		generateAccessToken(t)

		// Reset the creation time, token is unused
		t.UpdatedUnix = timeutil.TimeStampNow()

		if _, err := db.GetEngine(ctx).ID(t.ID).Cols("token_salt", "token", "token_hash", "token_last_eight", "updated_unix").NoAutoTime().Update(t); err != nil {
			return err
		}
		return recordAccessToken(ctx, "regenerated", t, map[string]any{"name": t.Name})
	})
}
