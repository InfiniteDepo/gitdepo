// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package repo

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/modules/timeutil"

	"xorm.io/builder"
)

// BitbucketOrigin records where an imported repository (RepoID) or project (GroupID) came from in Bitbucket Data
// Center. A repository row has RepoID set and OwnerID 0, because a transfer changes the repository's owner; it is
// removed when the repository is purged. A project row has OwnerID and GroupID set and Slug empty; it is removed with
// the project or its organization.
type BitbucketOrigin struct {
	ID          int64              `xorm:"pk autoincr"`
	ProjectKey  string             `xorm:"UNIQUE(s) NOT NULL"` // upper case
	Slug        string             `xorm:"UNIQUE(s) NOT NULL"` // lower case
	Server      string             `xorm:"UNIQUE(s) NOT NULL"` // base URL with a lower-case scheme and host
	OwnerID     int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	RepoID      int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	GroupID     int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
}

func init() {
	db.RegisterModel(new(BitbucketOrigin))
}

// GetBitbucketOrigin returns the origin of the repository, or nil if it has none.
func GetBitbucketOrigin(ctx context.Context, repoID int64) (*BitbucketOrigin, error) {
	o := new(BitbucketOrigin)
	if has, err := db.GetEngine(ctx).Where("repo_id = ?", repoID).Get(o); err != nil || !has {
		return nil, err
	}
	return o, nil
}

// GetBitbucketProjectOrigin returns the origin of the owner's project, or nil if it has none.
func GetBitbucketProjectOrigin(ctx context.Context, ownerID, groupID int64) (*BitbucketOrigin, error) {
	o := new(BitbucketOrigin)
	if has, err := db.GetEngine(ctx).Where("owner_id = ? AND group_id = ? AND repo_id = 0", ownerID, groupID).Get(o); err != nil || !has {
		return nil, err
	}
	return o, nil
}

// Path returns "KEY/slug".
func (o *BitbucketOrigin) Path() string {
	return o.ProjectKey + "/" + o.Slug
}

// BrowseURL returns the repository's page on the Bitbucket server, or "" if the stored server isn't a plain http(s)
// URL.
func (o *BitbucketOrigin) BrowseURL() string {
	u, err := url.Parse(o.Server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return u.JoinPath("projects", o.ProjectKey, "repos", o.Slug, "browse").String()
}

var (
	bitbucketNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.~-]+$`)
	bitbucketHostPattern = regexp.MustCompile(`^[a-z0-9.-]+$`)
)

// maxBitbucketOriginKeyword caps the keywords parsed as a Bitbucket repository.
const maxBitbucketOriginKeyword = 512

// parseBitbucketOriginKeyword reads a search keyword naming a Bitbucket repository: "KEY/slug",
// "http(s)://host[/context]/scm/key/slug[.git]", "http(s)://host[/context]/projects/KEY/repos/slug[/...]" or
// "ssh://[user@]host[:port]/key/slug[.git]". host is "" for "KEY/slug".
func parseBitbucketOriginKeyword(keyword string) (host, key, slug string, ok bool) {
	if len(keyword) > maxBitbucketOriginKeyword {
		return "", "", "", false
	}
	var segs []string
	if !strings.Contains(keyword, "://") {
		segs = strings.Split(keyword, "/")
		if len(segs) != 2 {
			return "", "", "", false
		}
	} else {
		u, err := url.Parse(keyword)
		if err != nil {
			return "", "", "", false
		}
		host = strings.ToLower(u.Hostname())
		if !bitbucketHostPattern.MatchString(host) {
			return "", "", "", false
		}
		path := strings.Split(strings.Trim(u.Path, "/"), "/")
		switch u.Scheme {
		case "ssh":
			if len(path) == 2 {
				segs = path
			}
		case "http", "https":
			for i, s := range path {
				if s == "scm" && len(path) == i+3 {
					segs = path[i+1:]
					break
				}
				if s == "projects" && len(path) >= i+4 && path[i+2] == "repos" {
					segs = []string{path[i+1], path[i+3]}
					break
				}
			}
		}
		if segs == nil {
			return "", "", "", false
		}
	}
	key, slug = strings.ToUpper(segs[0]), strings.ToLower(strings.TrimSuffix(segs[1], ".git"))
	if !bitbucketNamePattern.MatchString(key) || !bitbucketNamePattern.MatchString(slug) {
		return "", "", "", false
	}
	return host, key, slug, true
}

// bitbucketOriginKeywordCond matches the repositories whose origin the keyword names, or is nil if it names none.
// It is only a keyword alternative: the caller's visibility conditions still apply.
func bitbucketOriginKeywordCond(keyword string) builder.Cond {
	host, key, slug, ok := parseBitbucketOriginKeyword(keyword)
	if !ok {
		return nil
	}
	cond := builder.Eq{"project_key": key, "slug": slug}.And(builder.Neq{"repo_id": 0})
	if host != "" {
		// the host has no LIKE wildcards (bitbucketHostPattern)
		cond = cond.And(builder.Or(
			builder.Like{"server", "%://" + host},
			builder.Like{"server", "%://" + host + ":%"},
			builder.Like{"server", "%://" + host + "/%"},
		))
	}
	return builder.In("`repository`.id", builder.Select("repo_id").From("bitbucket_origin").Where(cond))
}

// IsValidBitbucketName reports whether s is a plain Bitbucket project key or repository slug. "." and ".." are not:
// url.JoinPath would resolve them and send a request to another path.
func IsValidBitbucketName(s string) bool {
	return s != "." && s != ".." && bitbucketNamePattern.MatchString(s)
}

// GetBitbucketOriginByPath returns the origin row of a Bitbucket repository (or of a project, with an empty slug),
// or nil.
func GetBitbucketOriginByPath(ctx context.Context, server, key, slug string) (*BitbucketOrigin, error) {
	o := new(BitbucketOrigin)
	if has, err := db.GetEngine(ctx).Where("project_key = ? AND slug = ? AND server = ?", key, slug, server).Get(o); err != nil || !has {
		return nil, err
	}
	return o, nil
}

// InsertBitbucketOrigin records an origin; a second row for the same Bitbucket repository or project fails on the
// unique key.
func InsertBitbucketOrigin(ctx context.Context, o *BitbucketOrigin) error {
	return db.Insert(ctx, o)
}
