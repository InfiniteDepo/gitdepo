// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"errors"
	"fmt"
	"time"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
)

// ErrExpiryPolicy is wrapped by every error returned by ValidateExpiry and ParseExpiryDate.
var ErrExpiryPolicy = errors.New("expiry date")

var (
	ErrExpiryInvalid  = fmt.Errorf("%w: invalid date", ErrExpiryPolicy)
	ErrExpiryRequired = fmt.Errorf("%w: required", ErrExpiryPolicy)
	ErrExpiryInPast   = fmt.Errorf("%w: must be in the future", ErrExpiryPolicy)
	ErrExpiryTooLate  = fmt.Errorf("%w: too late", ErrExpiryPolicy)
)

func endOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, t.Location())
}

// MaxExpiry is the latest expiry the policy allows for a credential created now, or 0 when there is no maximum.
func MaxExpiry(p setting.CredentialExpiryPolicy) timeutil.TimeStamp {
	if p.MaxLifetimeDays <= 0 {
		return 0
	}
	now := timeutil.TimeStampNow().AsTimeInLocation(setting.DefaultUILocation)
	return timeutil.TimeStamp(endOfDay(now.AddDate(0, 0, p.MaxLifetimeDays)).Unix())
}

// MaxExpiryDate is the latest expiry date (YYYY-MM-DD) the policy allows, or "" when there is no maximum.
func MaxExpiryDate(p setting.CredentialExpiryPolicy) string {
	if m := MaxExpiry(p); m != 0 {
		return m.FormatDate()
	}
	return ""
}

// DefaultExpiryDate is the expiry date (YYYY-MM-DD) a create form suggests: 30 days from today, capped at the maximum,
// or "" when the policy doesn't require an expiry.
func DefaultExpiryDate(p setting.CredentialExpiryPolicy) string {
	if !p.Required && p.MaxLifetimeDays <= 0 {
		return ""
	}
	days := 30
	if p.MaxLifetimeDays > 0 {
		days = min(days, p.MaxLifetimeDays)
	}
	return MaxExpiry(setting.CredentialExpiryPolicy{MaxLifetimeDays: days}).FormatDate()
}

// ParseExpiryDate parses a YYYY-MM-DD form value into the end of that day; "" means no expiry.
func ParseExpiryDate(s string) (timeutil.TimeStamp, error) {
	if s == "" {
		return 0, nil
	}
	t, err := time.ParseInLocation("2006-01-02", s, setting.DefaultUILocation)
	if err != nil {
		return 0, ErrExpiryInvalid
	}
	return timeutil.TimeStamp(endOfDay(t).Unix()), nil
}

// ValidateExpiry checks the expiry of a new credential (0 = never) against the policy.
func ValidateExpiry(p setting.CredentialExpiryPolicy, expires timeutil.TimeStamp) error {
	if expires == 0 {
		if p.MaxLifetimeDays > 0 {
			return fmt.Errorf("%w: the maximum lifetime is %d days", ErrExpiryRequired, p.MaxLifetimeDays)
		}
		if p.Required {
			return ErrExpiryRequired
		}
		return nil
	}
	if expires <= timeutil.TimeStampNow() {
		return ErrExpiryInPast
	}
	if m := MaxExpiry(p); m != 0 && expires > m {
		return fmt.Errorf("%w: the maximum lifetime is %d days", ErrExpiryTooLate, p.MaxLifetimeDays)
	}
	return nil
}

// RotationExpiry is the expiry a rotated credential gets: the date the create forms suggest, or, where the policy
// suggests none, 30 days for a credential that had an expiry and none for one that had none.
func RotationExpiry(p setting.CredentialExpiryPolicy, hadExpiry bool) timeutil.TimeStamp {
	if p.Required || p.MaxLifetimeDays > 0 || hadExpiry {
		p.Required = true
		expires, _ := ParseExpiryDate(DefaultExpiryDate(p))
		return expires
	}
	return 0
}
