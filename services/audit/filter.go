// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package audit reads the audit log: the filters of the site audit page, its API and the exports.
package audit

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

// Params are the filter parameters, in the order the manifest lists them. The page, the API and the CLI take the
// same names.
var Params = []string{
	"category", "org", "project", "repo", "user", "credential_type", "credential", "credential_owner", "action", "result",
	"ip", "request_id", "since", "before", "target_type", "target_id", "before_id", "after_id",
}

// Tabs are the category values of the page tabs; "changes" is the default.
var Tabs = map[string][]string{
	"changes":  {"credential", "account", "admin", "org", "repo", "audit"},
	"signins":  {"auth"},
	"activity": {"activity"},
	"all":      nil,
}

// FilterError is a filter value that is invalid, or a name that names nothing.
type FilterError struct {
	Param, Value string
	Unknown      bool
}

func (e *FilterError) Error() string {
	if e.Unknown {
		return fmt.Sprintf("no %s named %q", strings.ReplaceAll(e.Param, "_", " "), e.Value)
	}
	return fmt.Sprintf("invalid %s: %q", e.Param, e.Value)
}

func (e *FilterError) Unwrap() error { return util.ErrInvalidArgument }

// Filter is a parsed filter.
type Filter struct {
	Opts   audit_model.SearchOptions
	Values url.Values // the given parameters, with the effective category
	OrgID  int64
}

// List returns the filter as key=value strings in Params order.
func (f *Filter) List() []string {
	var list []string
	for _, k := range Params {
		if v := f.Values.Get(k); v != "" {
			list = append(list, k+"="+v)
		}
	}
	return list
}

var (
	actionRe    = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*(\.\*)?$`)
	requestIDRe = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
	typeRe      = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
)

// ParseFilter reads the filter parameters with get. Names are looked up as they are now (nothing in the trash); a
// value of digits is an ID and is used as it is, so entries of deleted and trashed objects stay reachable.
func ParseFilter(ctx context.Context, get func(string) string) (*Filter, error) {
	f := &Filter{Values: url.Values{}}
	o := &f.Opts
	val := func(k string) string {
		v := strings.TrimSpace(get(k))
		if v != "" {
			f.Values.Set(k, v)
		}
		return v
	}
	bad := func(k, v string) error { return &FilterError{Param: k, Value: v} }
	unknown := func(k, v string) error { return &FilterError{Param: k, Value: v, Unknown: true} }
	id := func(v string) int64 {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return 0
		}
		return n
	}
	lookupUser := func(k, v string) (int64, error) {
		if n := id(v); n != 0 {
			return n, nil
		}
		u, err := user_model.GetUserByName(ctx, v)
		if user_model.IsErrUserNotExist(err) {
			return 0, unknown(k, v)
		}
		if err != nil {
			return 0, err
		}
		return u.ID, nil
	}

	category := val("category")
	if category == "" {
		category = "changes"
		f.Values.Set("category", category)
	}
	if tab, ok := Tabs[category]; ok {
		o.Categories = tab
	} else {
		for c := range strings.SplitSeq(category, ",") {
			if !slices.Contains(audit_model.Categories, c) {
				return nil, bad("category", category)
			}
			o.Categories = append(o.Categories, c)
		}
	}

	if v := val("org"); v != "" {
		if f.OrgID = id(v); f.OrgID == 0 {
			org, err := organization.GetOrgByName(ctx, v)
			if organization.IsErrOrgNotExist(err) {
				return nil, unknown("organization", v)
			} else if err != nil {
				return nil, err
			}
			f.OrgID = org.ID
		}
		o.OwnerID = f.OrgID
	}
	if v := val("project"); v != "" {
		if o.GroupID = id(v); o.GroupID == 0 {
			return nil, bad("project", v)
		}
		if f.OrgID != 0 {
			if _, err := repo_model.GetRepoGroupByID(ctx, f.OrgID, o.GroupID); err != nil {
				if err == repo_model.ErrRepoGroupNotExist {
					return nil, unknown("project", v)
				}
				return nil, err
			}
		}
	}
	if v := val("repo"); v != "" {
		if o.RepoID = id(v); o.RepoID == 0 {
			repo, err := repo_model.GetRepositoryByFullName(ctx, v)
			if repo_model.IsErrRepoNotExist(err) {
				return nil, unknown("repository", v)
			} else if err != nil {
				return nil, err
			}
			o.RepoID = repo.ID
		}
	}
	var err error
	if v := val("user"); v != "" {
		if o.UserID, err = lookupUser("user", v); err != nil {
			return nil, err
		}
	}
	if v := val("credential_owner"); v != "" {
		if o.CredentialOwnerID, err = lookupUser("credential_owner", v); err != nil {
			return nil, err
		}
	}
	if v := val("credential_type"); v != "" {
		for t := range strings.SplitSeq(v, ",") {
			if !slices.Contains(audit_model.CredentialTypes, t) {
				return nil, bad("credential_type", v)
			}
			o.CredentialTypes = append(o.CredentialTypes, t)
		}
	}
	if v := val("credential"); v != "" {
		t, n, _ := strings.Cut(v, ":")
		if o.CredentialType, o.CredentialID = t, id(n); !slices.Contains(audit_model.CredentialTypes, t) || o.CredentialID == 0 {
			return nil, bad("credential", v)
		}
	}
	if v := val("action"); v != "" {
		if len(v) > 64 || !actionRe.MatchString(v) {
			return nil, bad("action", v)
		}
		o.Action, o.ActionPrefix = strings.CutSuffix(v, ".*")
	}
	if v := val("result"); v != "" {
		if !slices.Contains(audit_model.Results, v) {
			return nil, bad("result", v)
		}
		o.Result = v
	}
	if v := val("ip"); v != "" {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return nil, bad("ip", v)
		}
		o.IP = addr.String()
	}
	if v := val("request_id"); v != "" {
		if !requestIDRe.MatchString(v) {
			return nil, bad("request_id", v)
		}
		o.RequestID = v
	}
	for k, ts := range map[string]*timeutil.TimeStamp{"since": &o.Since, "before": &o.Before} {
		if v := val(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, bad(k, v)
			}
			*ts = timeutil.TimeStamp(t.Unix())
		}
	}
	if v := val("target_type"); v != "" {
		if !typeRe.MatchString(v) {
			return nil, bad("target_type", v)
		}
		o.TargetType = v
	}
	for k, n := range map[string]*int64{"target_id": &o.TargetID, "before_id": &o.BeforeID, "after_id": &o.AfterID} {
		if v := val(k); v != "" {
			if *n = id(v); *n == 0 {
				return nil, bad(k, v)
			}
		}
	}
	return f, nil
}
