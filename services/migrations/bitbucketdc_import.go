// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package migrations

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	audit_model "forgejo.org/models/audit"
	"forgejo.org/models/organization"
	repo_model "forgejo.org/models/repo"
	user_model "forgejo.org/models/user"
	"forgejo.org/modules/log"
	base "forgejo.org/modules/migration"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/structs"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
	"forgejo.org/services/authz"
	"forgejo.org/services/migrations/allowlist"
	repo_service "forgejo.org/services/repository"
)

// BitbucketImportOptions are the options of an import of Bitbucket Data Center projects into an organization.
type BitbucketImportOptions struct {
	Server       string
	Username     string // the account of a user token; empty for a project or repository token
	Token        string
	Projects     []string // project keys; empty imports every project the token can read
	DryRun       bool
	PullRequests bool
	KeyExpiry    string // YYYY-MM-DD: the latest expiry of an imported deploy key; empty for none
	SkipUnmapped bool   // import the rest when a branch permission can't be mapped, instead of stopping
}

// String never prints the token.
func (o BitbucketImportOptions) String() string {
	return fmt.Sprintf("{server: %s, projects: %v, dry run: %t, key expiry: %s}", o.Server, o.Projects, o.DryRun, o.KeyExpiry)
}

// GoString never prints the token.
func (o BitbucketImportOptions) GoString() string {
	return o.String()
}

// The statuses of a BitbucketImportItem.
const (
	BitbucketPlanned  = "planned"
	BitbucketReused   = "reused"
	BitbucketCreated  = "created"
	BitbucketConflict = "conflict"
	BitbucketFailed   = "failed"
	BitbucketSkipped  = "skipped"
)

// BitbucketImportItem is a project, repository, permission or key of an import. Text from the Bitbucket server is
// stripped of control characters.
type BitbucketImportItem struct {
	Kind      string `json:"kind"`             // "project", "repository", "team", "member", "group", "collaborator", "key", "rule", "hook", "branching_model" or "permission"
	Bitbucket string `json:"bitbucket"`        // KEY, KEY/slug, a user or group name, "KEY key 1", ...
	Name      string `json:"name"`             // the path, team, login, user group or key name in gitdepo
	Target    string `json:"target,omitempty"` // the team, repository or project a grant or key lands on
	Access    string `json:"access,omitempty"`
	Expires   string `json:"expires,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	OldHTTP   string `json:"old_http,omitempty"`
	OldSSH    string `json:"old_ssh,omitempty"` // display only: never fetched
	OldWeb    string `json:"old_web,omitempty"`
	NewHTTP   string `json:"new_http,omitempty"`
	NewSSH    string `json:"new_ssh,omitempty"`
	NewWeb    string `json:"new_web,omitempty"`

	key, slug, groupName, description string
	group                             *repo_model.RepoGroup
	repo                              *repo_model.Repository
	repos                             []*BitbucketImportItem
	public                            bool
	bitbucketPermission
}

func (item *BitbucketImportItem) set(status, reason string) {
	item.Status, item.Reason = status, util.StripControl(reason)
}

// BitbucketImportReport is the plan of an import, and once it ran, its outcome.
type BitbucketImportReport struct {
	Items   []*BitbucketImportItem `json:"items"`
	Blocked bool                   `json:"blocked"` // a conflict: nothing was written
}

// bitbucketImports holds the organizations an import runs into in this process. It never waits, so it can't be held
// across a transaction someone else waits on; on another pod, a concurrent import fails closed on the name claims and
// the unique key of the origin rows.
var bitbucketImports sync.Map

// ImportBitbucket plans the import of Bitbucket Data Center projects into the organization orgName as doerName, a site
// admin or an acting owner of the organization, and unless it is a dry run or the plan has a conflict, runs it. Every
// write goes through the normal services as the doer, and the first one happens only after the whole plan was checked.
func ImportBitbucket(ctx context.Context, doerName, orgName string, opts BitbucketImportOptions) (*BitbucketImportReport, error) {
	doer, err := user_model.GetUserByName(ctx, doerName)
	if err != nil {
		return nil, err
	}
	if !doer.IsActive || doer.ProhibitLogin {
		return nil, util.NewPermissionDeniedErrorf("%s can't sign in", doer.Name)
	}
	org, err := organization.GetOrgByName(ctx, orgName)
	if err != nil {
		return nil, err
	}
	if org.IsArchived {
		return nil, organization.ErrOrgArchived{Name: org.Name}
	}
	if !doer.IsAdmin {
		if owner, err := org.IsActingOwner(ctx, doer); err != nil {
			return nil, err
		} else if !owner {
			return nil, util.NewPermissionDeniedErrorf("%s is not an owner of %s", doer.Name, org.Name)
		}
	}
	// a command line run: every entry it causes names the account it runs as (data.task)
	ctx = audit_model.WithActor(ctx, &audit_model.Actor{
		Type: audit_model.ActorCLI, Credential: audit_model.Credential{Type: audit_model.CredentialCLI},
		Task: fmt.Sprintf("bitbucket_import:%s(%d)", doer.Name, doer.ID),
	})
	if !opts.DryRun && setting.GetMaintenance(ctx).ReadOnly() {
		return nil, util.NewPermissionDeniedErrorf("the instance is in maintenance mode")
	}
	server, err := parseBitbucketServer(opts.Server)
	if err != nil {
		return nil, err
	}
	if err := allowlist.IsMigrateURLAllowed(server.String(), doer); err != nil {
		return nil, err
	}
	keyExpiry, err := authz.ParseExpiryDate(opts.KeyExpiry)
	if err == nil && keyExpiry != 0 {
		err = authz.ValidateExpiry(setting.DeployKeyExpiry, keyExpiry)
	}
	if err != nil {
		return nil, util.NewInvalidArgumentErrorf("--key-expiry: %v", err)
	}

	if _, busy := bitbucketImports.LoadOrStore(org.ID, true); busy {
		return nil, fmt.Errorf("%w: an import into %s is already running", util.ErrAlreadyExist, org.Name)
	}
	defer bitbucketImports.Delete(org.ID)
	log.Info("Bitbucket import into %s by %s: %s", org.Name, doer.Name, opts) // String leaves the token out

	d := newBitbucketDataCenterDownloader(ctx, server, "", "", opts.Token)
	report, err := planBitbucketImport(ctx, d, org, opts.Projects, keyExpiry, opts.SkipUnmapped)
	if err != nil || report.Blocked || opts.DryRun {
		return report, err
	}
	applyBitbucketImport(ctx, doer, org, d, report, opts)
	return report, nil
}

// parseBitbucketServer accepts a plain http(s) base URL and returns it with a lower-case scheme and host.
func parseBitbucketServer(server string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil {
		return nil, util.NewInvalidArgumentErrorf("invalid server URL")
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, util.NewInvalidArgumentErrorf("the server must be a plain http(s) URL")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}, nil
}

type bitbucketProject struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Public      bool   `json:"public"`
}

type bitbucketRepository struct {
	Slug   string              `json:"slug"`
	Links  bitbucketCloneLinks `json:"links"`
	Public bool                `json:"public"`
}

// bitbucketProjectName turns a Bitbucket project name into a project name: lower case, every run of other characters
// than letters, digits, "_" and "." one "-"; the lower-case key if nothing usable is left.
func bitbucketProjectName(name, key string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.') {
			b.WriteRune(r)
		} else if s := b.String(); s != "" && !strings.HasSuffix(s, "-") {
			b.WriteByte('-')
		}
	}
	if s := strings.Trim(b.String(), "-."); s != "" && repo_model.IsUsableGroupName(s) == nil {
		return s
	}
	return strings.ToLower(key)
}

// planBitbucketImport lists the projects and repositories to import and decides, without writing, what happens to
// each: created, reused (imported before into the same place) or a conflict, which blocks the whole import.
func planBitbucketImport(ctx context.Context, d *BitbucketDataCenterDownloader, org *organization.Organization, keys []string, keyExpiry timeutil.TimeStamp, skipUnmapped bool) (*BitbucketImportReport, error) {
	server := d.baseURL.String()
	projects, err := callAPIPaged[bitbucketProject](d, "api/1.0/projects")
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, key := range keys {
		wanted[strings.ToUpper(key)] = false
	}
	slices.SortFunc(projects, func(a, b bitbucketProject) int { return strings.Compare(a.Key, b.Key) })

	report := &BitbucketImportReport{}
	conflict := func(item *BitbucketImportItem, reason string) {
		item.set(BitbucketConflict, reason)
		report.Blocked = true
	}
	names, filter := map[string]bool{}, len(wanted) > 0
	teams := map[string]*BitbucketImportItem{}
	for _, p := range projects {
		if _, ok := wanted[strings.ToUpper(p.Key)]; filter && !ok {
			continue
		}
		wanted[strings.ToUpper(p.Key)] = true
		item := &BitbucketImportItem{Kind: "project", Bitbucket: util.StripControl(p.Key), key: p.Key, description: util.StripControl(p.Description), public: p.Public, Status: BitbucketPlanned}
		report.Items = append(report.Items, item)
		if !repo_model.IsValidBitbucketName(p.Key) {
			conflict(item, "the project key isn't a plain name")
			continue
		}
		item.OldWeb = d.baseURL.JoinPath("projects", p.Key).String()

		origin, err := repo_model.GetBitbucketOriginByPath(ctx, server, strings.ToUpper(p.Key), "")
		if err != nil {
			return nil, err
		}
		if origin != nil {
			// imported before: reuse the project only where it was created
			group, err := repo_model.GetRepoGroupByID(ctx, org.ID, origin.GroupID)
			if origin.OwnerID != org.ID || errors.Is(err, repo_model.ErrRepoGroupNotExist) {
				conflict(item, "imported before into another organization or a deleted project")
				continue
			} else if err != nil {
				return nil, err
			}
			item.group, item.groupName = group, group.Name
			item.set(BitbucketReused, "")
		} else {
			item.groupName = bitbucketProjectName(p.Name, p.Key)
			if repo_model.IsUsableGroupName(item.groupName) != nil {
				conflict(item, "the project name isn't usable")
			} else if taken, err := repo_model.IsNameTaken(ctx, org.ID, 0, item.groupName); err != nil {
				return nil, err
			} else if onDisk, err := util.IsExist(repo_model.GroupPath(org.Name, item.groupName)); err != nil {
				return nil, err
			} else if taken || onDisk || names[item.groupName] {
				conflict(item, "the name is taken in the organization")
			}
		}
		names[item.groupName] = true
		item.Name = org.Name + "/" + item.groupName

		repos, err := callAPIPaged[bitbucketRepository](d, "api/1.0/projects/"+p.Key+"/repos")
		if err != nil {
			return nil, err
		}
		slices.SortFunc(repos, func(a, b bitbucketRepository) int { return strings.Compare(a.Slug, b.Slug) })
		for _, r := range repos {
			ritem := &BitbucketImportItem{Kind: "repository", Bitbucket: util.StripControl(p.Key + "/" + r.Slug), key: p.Key, slug: r.Slug, public: r.Public, Status: BitbucketPlanned}
			item.repos = append(item.repos, ritem)
			report.Items = append(report.Items, ritem)
			if !repo_model.IsValidBitbucketName(r.Slug) || repo_model.IsUsableRepoName(r.Slug) != nil {
				conflict(ritem, "the repository slug isn't a usable name")
				continue
			}
			ritem.Name = item.Name + "/" + r.Slug
			ritem.OldHTTP = d.cloneURL(p.Key, r.Slug)
			ritem.OldWeb = d.baseURL.JoinPath("projects", p.Key, "repos", r.Slug, "browse").String()
			ritem.OldSSH = fmt.Sprintf("ssh://git@%s:7999/%s/%s.git", d.baseURL.Hostname(), strings.ToLower(p.Key), r.Slug)
			for _, c := range r.Links.Clone {
				if c.Name == "ssh" {
					ritem.OldSSH = util.StripControl(c.Href) // display only
				}
			}

			origin, err := repo_model.GetBitbucketOriginByPath(ctx, server, strings.ToUpper(p.Key), strings.ToLower(r.Slug))
			if err != nil {
				return nil, err
			}
			if origin != nil {
				// imported before: reuse the repository only if it is still live where it was created
				repo, err := repo_model.GetRepositoryByIDIncludingTrashed(ctx, origin.RepoID)
				if err != nil && !repo_model.IsErrRepoNotExist(err) {
					return nil, err
				}
				if repo == nil || repo.IsTrashed() || repo.OwnerID != org.ID || item.group == nil || repo.GroupID != item.group.ID {
					conflict(ritem, "imported before, but since trashed, moved or transferred")
					continue
				}
				ritem.set(BitbucketReused, "")
				ritem.repo = repo
				ritem.NewHTTP, ritem.NewSSH, ritem.NewWeb = repo.CloneLink().HTTPS, repo.CloneLink().SSH, repo.HTMLURL()
			} else if item.group != nil {
				if taken, err := repo_model.IsNameTaken(ctx, org.ID, item.group.ID, r.Slug); err != nil {
					return nil, err
				} else if onDisk, err := util.IsExist(repo_model.GroupRepoPath(org.Name, item.group.Name, r.Slug)); err != nil {
					return nil, err
				} else if taken || onDisk {
					conflict(ritem, "the name is taken in the project")
				}
			}
		}
		if item.Status != BitbucketConflict {
			if err := planBitbucketPermissions(ctx, d, org, report, item, keyExpiry, teams, skipUnmapped); err != nil {
				return nil, err
			}
		}
	}
	for _, key := range keys {
		if !wanted[strings.ToUpper(key)] {
			wanted[strings.ToUpper(key)] = true // listed once
			report.Items = append(report.Items, &BitbucketImportItem{Kind: "project", Bitbucket: util.StripControl(key), Status: BitbucketConflict, Reason: "not found on the server"})
			report.Blocked = true
		}
	}
	return report, nil
}

// applyBitbucketImport creates the planned projects and repositories. A repository that fails is reported and the
// others go on; a later run resumes, because only an imported repository has an origin row.
func applyBitbucketImport(ctx context.Context, doer *user_model.User, org *organization.Organization, d *BitbucketDataCenterDownloader, report *BitbucketImportReport, opts BitbucketImportOptions) {
	server := d.baseURL.String()
	failure := func(item *BitbucketImportItem, err error) {
		msg := util.SanitizeCredentialURLs(err.Error())
		if opts.Token != "" {
			msg = strings.ReplaceAll(msg, opts.Token, "***")
		}
		item.set(BitbucketFailed, msg)
	}
	// purge deletes a repository whose import failed, so a rerun imports it. It runs even when ctx was cancelled (a
	// Ctrl-C or a dropped CLI connection), which also kills the clone.
	purge := func(item *BitbucketImportItem, repo *repo_model.Repository, err error) {
		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		if derr := repo_service.DeleteRepositoryPermanently(pctx, doer, repo, false); derr != nil {
			err = fmt.Errorf("%w; deleting the half-imported repository failed too: delete %s and rerun", err, repo.FullName())
		}
		failure(item, err)
	}
	for _, item := range report.Items {
		if item.Kind != "project" || item.Status == BitbucketConflict {
			continue
		}
		if item.Status == BitbucketPlanned {
			group, err := repo_model.CreateRepoGroup(ctx, org.AsUser(), item.groupName, item.description)
			if err != nil {
				failure(item, err)
			} else if err := repo_model.InsertBitbucketOrigin(context.WithoutCancel(ctx), &repo_model.BitbucketOrigin{OwnerID: org.ID, GroupID: group.ID, ProjectKey: strings.ToUpper(item.key), Server: server}); err != nil {
				failure(item, fmt.Errorf("the project was created, but recording its origin failed: delete it and rerun: %w", err))
			} else {
				item.group = group
				item.set(BitbucketCreated, "")
			}
		}
		for _, ritem := range item.repos {
			if ritem.Status != BitbucketPlanned {
				continue
			}
			if ctx.Err() != nil {
				ritem.set(BitbucketFailed, "the import was cancelled")
				continue
			}
			if item.Status == BitbucketFailed {
				ritem.set(BitbucketFailed, "its project was not created")
				continue
			}
			// create the repository first, as the migration task does, so a failed one can be deleted by its ID
			repo, err := repo_service.CreateRepositoryDirectly(ctx, doer, org.AsUser(), repo_service.CreateRepoOptions{
				Name:           ritem.slug,
				GroupID:        item.group.ID,
				OriginalURL:    ritem.OldWeb,
				GitServiceType: structs.BitbucketDataCenterService,
				IsPrivate:      true,
				Status:         repo_model.RepositoryBeingMigrated,
			})
			if err != nil {
				failure(ritem, err)
				continue
			}
			if _, err := MigrateRepository(ctx, doer, org.Name, base.MigrateOptions{
				CloneAddr:       ritem.OldHTTP,
				OriginalURL:     ritem.OldWeb,
				AuthUsername:    opts.Username,
				AuthToken:       opts.Token,
				RepoName:        ritem.slug,
				MigrateToRepoID: repo.ID,
				Private:         true,
				GitServiceType:  structs.BitbucketDataCenterService,
				PullRequests:    opts.PullRequests,
				Comments:        opts.PullRequests,
			}, nil); err != nil {
				purge(ritem, repo, err)
				continue
			}
			migrated, err := repo_model.GetRepositoryByID(ctx, repo.ID)
			if err == nil {
				err = repo_model.InsertBitbucketOrigin(ctx, &repo_model.BitbucketOrigin{RepoID: repo.ID, ProjectKey: strings.ToUpper(ritem.key), Slug: strings.ToLower(ritem.slug), Server: server})
			}
			if err != nil {
				purge(ritem, repo, fmt.Errorf("recording the origin failed: %w", err))
				continue
			}
			ritem.repo = migrated
			ritem.NewHTTP, ritem.NewSSH, ritem.NewWeb = migrated.CloneLink().HTTPS, migrated.CloneLink().SSH, migrated.HTMLURL()
			ritem.set(BitbucketCreated, "")
		}
		applyBitbucketPermissions(ctx, doer, org, item, failure)
	}
}
