// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package audit stores the audit log. Record is the one way to write an entry.
package audit

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/modules/json"
	"forgejo.org/modules/log"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"
)

// Entry is one row of the audit log. The table has no foreign keys and nothing that deletes a user, organization or
// repository touches it: entries outlive what they name until retention removes them.
type Entry struct {
	CreatedUnix       timeutil.TimeStamp `xorm:"INDEX NOT NULL"`
	Action            string             `xorm:"VARCHAR(64) NOT NULL index(action_id)"`
	Category          string             `xorm:"VARCHAR(16) NOT NULL index(category_id)"`
	Result            string             `xorm:"VARCHAR(16) NOT NULL"`
	ActorType         string             `xorm:"VARCHAR(16) NOT NULL"`
	ActorID           int64              `xorm:"NOT NULL DEFAULT 0 index(actor_id)"`
	ActorName         string             `xorm:"VARCHAR(255)"`
	SudoByID          int64              `xorm:"NOT NULL DEFAULT 0 index(sudo_by_id)"`
	CredentialType    string             `xorm:"VARCHAR(32) index(credential_id)"`
	CredentialID      int64              `xorm:"NOT NULL DEFAULT 0 index(credential_id)"`
	CredentialName    string             `xorm:"VARCHAR(255)"`
	CredentialOwnerID int64              `xorm:"NOT NULL DEFAULT 0 index(credential_owner_id)"`
	IP                string             `xorm:"VARCHAR(64) index(ip_id)"`
	UserAgent         string             `xorm:"VARCHAR(256)"`
	RequestID         string             `xorm:"VARCHAR(32) INDEX"`
	OwnerID           int64              `xorm:"NOT NULL DEFAULT 0 index(owner_id)"`
	GroupID           int64              `xorm:"NOT NULL DEFAULT 0 index(group_id)"`
	RepoID            int64              `xorm:"NOT NULL DEFAULT 0 index(repo_id)"`
	SubjectUserID     int64              `xorm:"NOT NULL DEFAULT 0 index(subject_user_id)"`
	TargetType        string             `xorm:"VARCHAR(32) index(target)"`
	TargetID          int64              `xorm:"NOT NULL DEFAULT 0 index(target)"`
	TargetName        string             `xorm:"VARCHAR(255)"`
	Data              string             `xorm:"LONGTEXT"`
	Seq               *int64             `xorm:"UNIQUE NULL"`
	PrevHash          *string            `xorm:"CHAR(64) NULL"`
	Hash              *string            `xorm:"CHAR(64) NULL"`
	// ID is last so that it is the last column of the (x, id) indexes above.
	ID int64 `xorm:"pk autoincr index(action_id) index(category_id) index(actor_id) index(sudo_by_id) index(credential_id) index(credential_owner_id) index(ip_id) index(owner_id) index(group_id) index(repo_id) index(subject_user_id)"`
}

func (Entry) TableName() string { return "audit_event" }

// ChainHead is the single row that the sealer moves forward.
type ChainHead struct {
	ID             int64  `xorm:"pk autoincr"`
	Seq            int64  `xorm:"NOT NULL DEFAULT 0"`
	Hash           string `xorm:"CHAR(64) NOT NULL"`
	AnchorSeq      int64  `xorm:"NOT NULL DEFAULT 0"`
	AnchorPrevHash string `xorm:"CHAR(64) NOT NULL"`
}

func (ChainHead) TableName() string { return "audit_chain_head" }

func init() {
	db.RegisterModel(new(Entry))
	db.RegisterModel(new(ChainHead))
}

// MaxUserAgent is the most bytes of a user agent kept; MaxIPCandidates the most candidate IPs of an ambiguous one.
const (
	MaxUserAgent    = 256
	MaxIPCandidates = 8
)

const (
	CategoryAccount    = "account"
	CategoryAuth       = "auth"
	CategoryCredential = "credential"
	CategoryAudit      = "audit"
	CategoryAdmin      = "admin"
	CategoryOrg        = "org"
	CategoryRepo       = "repo"
	CategoryActivity   = "activity"

	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultRefused = "refused"

	maxText     = 255
	maxData     = 32 * 1024
	maxUA       = MaxUserAgent
	maxIP       = 64
	maxListText = 255
)

// Event is what a caller records. Its category comes from Actions. Data holds only keys listed in Fields[TargetType] (and inside "before"/"after");
// everything else is dropped.
type Event struct {
	Action, Result           string
	OwnerID, GroupID, RepoID int64
	SubjectUserID            int64
	TargetType               string
	TargetID                 int64
	TargetName               string
	Data                     map[string]any
}

// Fields lists the data keys kept per target type. Secrets (token values, hashes, salts, last eight) are never listed.
var Fields = map[string][]string{
	"access_token": {"name", "scopes", "expires", "resource_all_repos", "repo_ids", "mode", "description", "self_rotate", "self"},
	"authorized_integration": {
		"name", "issuer", "scopes", "resource_all_repos", "repo_ids", "ui", "claim_rules_changed",
	},
	"audit_export":   {"format", "filter", "capped", "through_id"},
	"audit_chain":    {"unsealed_before", "first_unsealed_id", "deleted", "through_seq", "through_hash", "cutoff_unix", "retention_days"},
	"credential_use": {"method"},
	// activity: what a request or a push did, never its body, query or content
	"api_request":       {"method", "route", "status", "target", "bytes"},
	"upload":            {"kind", "op", "bytes", "object"},
	"dependency_search": {"kind", "ecosystem", "name", "advisory", "owner", "state", "total"},
	"secret_pattern":    {"name", "pattern_sha256", "keyword_count", "previous_name", "previous_pattern_sha256"},
	"dependency_export": {"kind", "format", "ecosystem", "name", "version", "range", "direct", "advisory", "owner", "project", "state", "severity", "count"},
	"secret_export":     {"kind", "format", "state", "reason", "type", "owner", "project", "q", "count"},
	"download":          {"kind", "bytes", "object"},
	"git_read":          {"service", "protocol", "bytes", "wiki"},
	"git_push":          {"refs", "more", "forced_count", "forced_unknown", "deleted_count", "wiki", "trigger"},
	"git_push_refused":  {"ref"},
	"deploy_key":        {"expires", "name", "fingerprint", "mode"},
	"email":             {"address", "primary", "activated"},
	"gpg_key":           {"key_id", "subkey_ids", "verified", "expires"},
	"external_login":    {"login_source_id", "external_id"},
	"openid":            {"uri"},
	"two_factor":        {"type", "name"},
	"user": {
		"name", "email", "is_admin", "is_restricted", "is_active", "prohibit_login", "visibility", "login_source",
		"login_type", "must_change_password", "require_two_factor", "is_auditor", "allow_create_organization",
		"counts", "purge", "tombstone", "tombstone_removed", "role", "group_id", "user_ids", "count", "login_source_id",
		"allow_git_hook", "allow_import_local", "max_repo_creation", "personal_repo_size_limit", "category_id",
	},
	"instance":     {"version", "config_sha256"},
	"login_source": {"name", "type", "is_active", "is_sync_enabled", "config_changed", "counts"},
	"user_group": {
		"name", "grants_site_admin", "grants_create_organization", "grants_auditor", "grants_org_admin", "user_id",
		"team_id", "team_name", "org_id", "login_source_id", "org_ids", "counts",
	},
	// setting: the non-secret dynamic settings, whose values are recorded; any other key is recorded as a hash
	"setting": {
		"keys", "hashed", "picture.disable_gravatar", "picture.enable_federated_avatar", "repository.open-with.editor-apps",
		"maintenance.state", "ip_allowlist.state", "oauth2.app_policy", "webhook.types", "repository.unit_policy",
		"repository.personal_repos", "org_category.owners_can_assign", "audit.retention_days", "dependency_graph.enabled",
		"secret_scanning.enabled", "secret_scanning.config",
	},
	"log_shipping": {
		"id", "name", "type", "endpoint", "log_types", "enabled", "level", "ndjson", "key_changed", "headers_changed",
		"header_names", "filter_changed",
	},
	"org": {
		"name", "visibility", "require_two_factor", "restrict_repo_visibility_change", "private_fork_policy",
		"repo_admin_change_team_access", "max_repo_creation", "category_id", "is_active", "prohibit_login", "user_id",
		"counts", "purge", "domain", "verified_by_admin", "required", "units", "mode", "locked", "development_branch",
		"release_prefixes", "production_branch", "merge_forward", "merge_forward_never_bypass", "merge_forward_anyone_may_skip", "types", "default_pr_target", "model_locked",
		"dependency_graph", "dependency_graph_locked", "secret_scanning", "secret_scanning_locked",
	},
	"team": {
		"name", "access_mode", "units", "includes_all_repositories", "can_create_org_repo", "user_id", "inviter_id", "reason",
		"repo_id", "repo_name", "group_id", "counts", "email",
	},
	"repo": {
		"name", "owner_id", "owner_name", "group_id", "group_name", "is_private", "is_template", "default_branch",
		"is_mirror", "fork_id", "template_id", "units", "counts", "purge", "to_owner_id", "to_owner_name", "team_ids",
		"interval", "enable_prune", "branch_filter", "tag_filter", "lfs", "lfs_endpoint", "address", "url_changed",
		"credentials_changed", "development_branch", "release_prefixes", "production_branch", "merge_forward", "merge_forward_never_bypass", "merge_forward_anyone_may_skip", "types", "default_pr_target", "inherit", "mode",
		"dependency_graph", "secret_scanning",
	},
	"collaborator":       {"user_id", "mode"},
	"branch":             {"name", "from", "to", "commit", "default", "pull", "reason", "conflict_pull", "pull_failed"},
	"tag":                {"name", "commit"},
	"project":            {"name", "counts"},
	"queue":              {"name"},
	"quota_rule":         {"name", "limit", "subjects", "counts"},
	"quota_group":        {"name", "rule_name", "user_id", "groups", "counts"},
	"cron_task":          {"name"},
	"logger":             {"op", "logger", "writer", "mode", "on"},
	"oauth2_app":         {"name", "redirect_uris", "confidential", "secret_expires", "counts"},
	"oauth2_grant":       {"app_id", "app_name", "scopes"},
	"org_deploy_key":     {"expires", "name", "fingerprint", "mode", "all_repos", "repo_ids", "repos_added", "repos_removed"},
	"project_deploy_key": {"expires", "name", "fingerprint", "mode", "all_repos", "repo_ids", "repos_added", "repos_removed"},
	"refusal":            {"reason", "class", "method"},
	"runner":             {"name", "labels", "level", "ephemeral", "token_reset"},
	"runner_token":       {"level"},
	"signin":             {"method", "reason"},
	"ssh_key":            {"expires", "name", "fingerprint", "key_type", "login_source_id"},
	"webhook": {
		"origin", "type", "http_method", "content_type", "is_active", "events", "branch_filter", "kind", "secret_set",
		"authorization_set", "secret_changed", "authorization_changed", "url_changed",
	},
	"push_mirror": {"remote_name", "address", "interval", "sync_on_commit", "branch_filter", "use_ssh", "credentials_set"},
	"git_hook":    {"name", "active"},
	"branch_protection": {
		"rule_name", "can_push", "enable_whitelist", "whitelist_user_ids", "whitelist_team_ids", "enable_merge_whitelist",
		"whitelist_deploy_keys", "whitelist_deploy_key_ids", "merge_whitelist_user_ids", "merge_whitelist_team_ids",
		"enable_status_check", "status_check_contexts", "enable_approvals_whitelist", "approvals_whitelist_user_ids",
		"approvals_whitelist_team_ids", "required_approvals", "block_on_rejected_reviews", "block_on_official_review_requests",
		"block_on_outdated_branch", "dismiss_stale_approvals", "ignore_stale_approvals", "ignore_pusher_approvals", "require_signed_commits",
		"protected_file_patterns", "unprotected_file_patterns", "apply_to_admins", "block_on_unresolved_conversations",
		"ignore_outdated_conversations", "block_on_incomplete_tasks", "require_merge_queue", "merge_queue_merge_style",
		"merge_queue_build_concurrency", "merge_queue_min_group_size", "merge_queue_max_group_size", "merge_queue_wait_minutes",
		"merge_queue_check_timeout_minutes", "delete_allowlist_user_ids", "delete_allowlist_team_ids",
		"delete_allowlist_deploy_key_ids", "force_push_allowlist_user_ids", "force_push_allowlist_team_ids",
		"force_push_allowlist_deploy_key_ids", "apply_to_selected_repos", "approval_rules", "repo_ids",
	},
	"vulnerability_alert": {
		"alert_id", "advisory_id", "ecosystem", "package", "manifest", "reason", "comment", "previous_state", "previous_reason",
	},
	"secret_scanning_alert": {"index", "rule", "fingerprint", "path", "previous_state", "state", "comment", "issue", "field", "comment_id", "replaced", "history_only", "cleaned"},
	"vulnerability_mirror":  {"ecosystems"},
	// dependency_graph: the settings saved in Site administration; the mirror token only as token_changed
	"dependency_graph": {
		"source", "mirror_url", "sign_in", "user", "allowed_hosts", "token_changed", "max_concurrent_scans", "scan_timeout",
		"max_manifest_size", "max_manifests", "max_dependencies", "max_tree_entries", "update_interval", "osv_max_download",
		"osv_max_entries", "osv_max_entry_size", "osv_max_uncompressed", "osv_ecosystem_timeout", "class", "host",
	},
	"tag_protection": {"name_pattern", "allowlist_user_ids", "allowlist_team_ids", "allowlist_deploy_key_ids"},
	"push_rule": {
		"commit_message_regex", "commit_message_banned_regex", "branch_name_regex", "require_verified_author_email",
		"max_file_size_mb", "banned_file_patterns", "pr_title_regex", "pr_title_banned_regex", "pr_title_message",
		"pr_title_branches", "pr_title_block_merge",
	},
	"actions_secret":   {"name", "value_changed", "environment_id"},
	"actions_variable": {"name", "value_changed", "environment_id"},
	// actions_environment: the rules of an environment (no secret); actions_deployment: why a job was refused
	"actions_environment": {"name", "ref_policy", "ref_patterns", "wait_timer_minutes", "prevent_self_review", "runner_labels", "allowed_workflows", "reviewers", "reviews_required", "reviewers_removed", "auto", "counts"},
	"actions_deployment":  {"environment_id", "ref", "run_id", "job_id", "attempt", "comment_length", "revoked_reviewer_id"},
	"actions_run":         {"index", "workflow", "counts"},
	"actions_runs":        {"older_than_days", "run_ids"},
	"actions_artifact":    {"name", "run_id"},
	"actions_cleanup":     {},
}

// sharedKeys are the top-level data keys every target type may carry.
var sharedKeys = []string{
	"before", "after", "on_behalf", "reason", "truncated", "ip_ambiguous", "ip_candidates",
	"count", "first", "last", "overflow", // aggregated entries
}

// RecordAccount records a change of the account uid, its subject. The actor is whoever makes it: the user, an admin,
// the CLI or a cron task.
func RecordAccount(ctx context.Context, action string, uid int64, targetType string, targetID int64, targetName string, data map[string]any) error {
	return Record(ctx, Event{
		Action: action, Result: ResultSuccess, OwnerID: uid, SubjectUserID: uid,
		TargetType: targetType, TargetID: targetID, TargetName: targetName, Data: data,
	})
}

// RecordCredential records a change of a credential. Its SubjectUserID is the user who owns it (0 for a key of a
// repository or an organization); when another user makes the change, such as an admin, data.on_behalf is set.
func RecordCredential(ctx context.Context, ev Event) error {
	ev.Result = ResultSuccess
	if a := ActorFromContext(ctx); a != nil && a.Type == ActorUser && ev.SubjectUserID != 0 && a.ID != ev.SubjectUserID {
		if ev.Data == nil {
			ev.Data = map[string]any{}
		}
		ev.Data["on_behalf"] = true
	}
	return Record(ctx, ev)
}

// InsertEntry writes the row. It is a variable so that tests can make the insert fail.
var InsertEntry = func(ctx context.Context, e *Entry) error {
	return db.Insert(ctx, e)
}

// Record writes one entry with the actor of ctx, in ctx's transaction if it has one. An error means the entry was not
// written: callers inside a transaction return it, so the change fails with it.
func Record(ctx context.Context, ev Event) error {
	category, ok := Actions[ev.Action]
	if !ok {
		return fmt.Errorf("audit: unknown action %q", ev.Action)
	}
	a := ActorFromContext(ctx)
	if a == nil {
		log.Error("audit: no actor in context for %s", ev.Action)
		a = &Actor{Type: ActorUnknown}
	}
	data := filterData(ev.TargetType, ev.Data)
	if a.IPAmbiguous {
		data["ip_ambiguous"] = true
		if len(a.IPCandidates) > 0 {
			data["ip_candidates"] = a.IPCandidates
		}
	}
	if a.Task != "" {
		data["task"] = Text(a.Task, maxText)
	}
	cred := a.Credential
	if namer := credentialNamers[cred.Type]; cred.Name == "" && namer != nil {
		name, err := namer(ctx, cred)
		if err != nil {
			return err
		}
		cred.Name = name
	}
	encoded, err := encodeData(data)
	if err != nil {
		return err
	}
	e := &Entry{
		CreatedUnix:       timeutil.TimeStampNow(),
		Action:            ev.Action,
		Category:          category,
		Result:            ev.Result,
		ActorType:         a.Type,
		ActorID:           a.ID,
		ActorName:         Text(a.Name, maxText),
		SudoByID:          a.SudoByID,
		CredentialType:    cred.Type,
		CredentialID:      cred.ID,
		CredentialName:    Text(cred.Name, maxText),
		CredentialOwnerID: cred.OwnerID,
		IP:                Text(a.IP, maxIP),
		UserAgent:         Text(a.UserAgent, maxUA),
		RequestID:         Text(a.RequestID, 32),
		OwnerID:           ev.OwnerID,
		GroupID:           ev.GroupID,
		RepoID:            ev.RepoID,
		SubjectUserID:     ev.SubjectUserID,
		TargetType:        ev.TargetType,
		TargetID:          ev.TargetID,
		TargetName:        Text(ev.TargetName, maxText),
		Data:              encoded,
	}
	if err := InsertEntry(ctx, e); err != nil {
		return err
	}
	db.AfterTx(ctx, func() { Written[category].Add(1) }) // a rolled-back entry isn't counted
	return nil
}

// Changes returns the fields of after whose value differs from before, as data's "before" and "after"; nil when none
// differs.
func Changes(before, after map[string]any) map[string]any {
	b, a := map[string]any{}, map[string]any{}
	for k, v := range after {
		if !reflect.DeepEqual(before[k], v) {
			b[k], a[k] = before[k], v
		}
	}
	if len(a) == 0 {
		return nil
	}
	return map[string]any{"before": b, "after": a}
}

// URL is raw without its user info, query and fragment, so that no value they carry is recorded; "" when raw doesn't
// parse. Of an opaque URI (scheme:anything) only the scheme is kept.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Opaque != "" {
		return u.Scheme + ":"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// Origin is the scheme and host (with port) of raw, so that no path, query or user info is recorded; "" when raw
// doesn't parse or has no host.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Text strips control characters and cuts s to at most n bytes at a rune boundary.
func Text(s string, n int) string {
	s, _ = util.SplitStringAtByteN(strings.ToValidUTF8(util.StripControl(s), "?"), n)
	return s
}

func filterData(targetType string, in map[string]any) map[string]any {
	allowed := Fields[targetType]
	out := filterKeys(in, append(allowed, sharedKeys...))
	for _, k := range []string{"before", "after"} {
		if m, ok := in[k].(map[string]any); ok {
			out[k] = filterKeys(m, allowed)
		} else {
			delete(out, k)
		}
	}
	return out
}

func filterKeys(in map[string]any, allowed []string) map[string]any {
	out := map[string]any{}
	for _, k := range allowed {
		v, ok := in[k]
		if !ok {
			continue
		}
		switch v := v.(type) {
		case string:
			out[k] = Text(v, maxText)
		case []string:
			list := make([]string, len(v))
			for i, s := range v {
				list[i] = Text(s, maxListText)
			}
			out[k] = list
		default:
			out[k] = v
		}
	}
	return out
}

// encodeData returns the JSON of data (keys sorted) cut to maxData: it halves the longest list of objects first, then
// the longest name list, then the longest ID list, and sets "truncated".
func encodeData(data map[string]any) (string, error) {
	for {
		b, err := json.Marshal(data)
		if err != nil || len(b) <= maxData {
			return string(b), err
		}
		if !halveLongest[map[string]any](data) && !halveLongest[string](data) && !halveLongest[int64](data) {
			return "", util.NewInvalidArgumentErrorf("audit data too large")
		}
		data["truncated"] = true
	}
}

func halveLongest[T any](data map[string]any) bool {
	var longest []T
	var set func([]T)
	visit := func(m map[string]any) {
		for k, v := range m {
			if l, ok := v.([]T); ok && len(l) > len(longest) {
				longest, set = l, func(n []T) { m[k] = n }
			}
		}
	}
	visit(data)
	for _, k := range []string{"before", "after"} {
		if m, ok := data[k].(map[string]any); ok {
			visit(m)
		}
	}
	if len(longest) == 0 {
		return false
	}
	set(longest[:len(longest)/2])
	return true
}

// LevelActions are the action keys of one change of a setting that exists at several levels (a webhook, an Actions
// secret or variable), so that each key is a literal at its call site.
type LevelActions struct{ Repo, Org, Account, Admin string }
