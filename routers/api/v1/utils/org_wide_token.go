// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package utils

import (
	"forgejo.org/services/authz"
	"forgejo.org/services/context"
)

// IsOrgWideToken reports whether the request is limited neither to public resources nor to specific repositories.
func IsOrgWideToken(ctx *context.APIContext) bool {
	_, all := ctx.Reducer().(*authz.AllAccessAuthorizationReducer)
	return all && !ctx.PublicOnly()
}
