// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package utils

import (
	"errors"
	"net/http"
	"time"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/services/authz"
	"forgejo.org/services/context"
)

// ValidateExpiry converts an optional API expiry time and checks it against the policy. It writes a 422 response
// and returns false when the expiry is not allowed.
func ValidateExpiry(ctx *context.APIContext, p setting.CredentialExpiryPolicy, t *time.Time) (timeutil.TimeStamp, bool) {
	expires := ExpiryTimeStamp(t)
	if err := authz.ValidateExpiry(p, expires); err != nil {
		ctx.Error(http.StatusUnprocessableEntity, "ValidateExpiry", err)
		return 0, false
	}
	return expires, true
}

// ExpiryTimeStamp converts an optional API expiry time, nil or zero meaning never.
func ExpiryTimeStamp(t *time.Time) timeutil.TimeStamp {
	if t == nil || t.IsZero() {
		return 0
	}
	return timeutil.TimeStamp(t.Unix())
}

// IsExpiryError reports whether err is an expiry policy error, which the API reports as 422.
func IsExpiryError(err error) bool {
	return errors.Is(err, authz.ErrExpiryPolicy)
}
