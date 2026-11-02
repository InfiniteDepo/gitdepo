// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add expires_unix to access_token, public_key and deploy_key",
		Upgrade:     addCredentialExpiry,
	})
}

func addCredentialExpiry(x *xorm.Engine) error {
	type AccessToken struct {
		ExpiresUnix int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	type PublicKey struct {
		ExpiresUnix int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	type DeployKey struct {
		ExpiresUnix int64 `xorm:"NOT NULL DEFAULT 0"`
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(AccessToken), new(PublicKey), new(DeployKey))
	return err
}
