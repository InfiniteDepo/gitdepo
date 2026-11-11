// Copyright 2017 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"forgejo.org/models/db"
	"forgejo.org/models/perm"
	"forgejo.org/models/unit"
	"forgejo.org/modules/json"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/timeutil"
	"forgejo.org/modules/util"

	"code.forgejo.org/xorm/xorm"
	"code.forgejo.org/xorm/xorm/convert"
	"xorm.io/builder"
)

// ErrUnitTypeNotExist represents a "UnitTypeNotExist" kind of error.
type ErrUnitTypeNotExist struct {
	UT unit.Type
}

// IsErrUnitTypeNotExist checks if an error is a ErrUnitNotExist.
func IsErrUnitTypeNotExist(err error) bool {
	_, ok := err.(ErrUnitTypeNotExist)
	return ok
}

func (err ErrUnitTypeNotExist) Error() string {
	return fmt.Sprintf("Unit type does not exist: %s", err.UT.String())
}

func (err ErrUnitTypeNotExist) Unwrap() error {
	return util.ErrNotExist
}

// RepoUnitAccessMode specifies the users access mode to a repo unit
// Only UnitAccessModeWrite is used by the wiki, to mark it as instance-writable
type UnitAccessMode int

const (
	// UnitAccessModeUnset - no unit mode set
	UnitAccessModeUnset UnitAccessMode = iota // 0

	// UnitAccessModeNone no access
	// UnitAccessModeNone UnitAccessMode = 1
	// UnitAccessModeRead read access
	// UnitAccessModeRead UnitAccessMode = 2

	// UnitAccessModeWrite write access
	UnitAccessModeWrite UnitAccessMode = 3
)

func (mode UnitAccessMode) ToAccessMode(modeIfUnset perm.AccessMode) perm.AccessMode {
	switch mode {
	case UnitAccessModeUnset:
		return modeIfUnset
	// case UnitAccessModeNone:
	//	return perm.AccessModeNone
	// case UnitAccessModeRead:
	//	return perm.AccessModeRead
	case UnitAccessModeWrite:
		return perm.AccessModeWrite
	default:
		return perm.AccessModeNone
	}
}

// RepoUnit describes all units of a repository
type RepoUnit struct { //revive:disable-line:exported
	ID                 int64
	RepoID             int64              `xorm:"INDEX(s)"`
	Type               unit.Type          `xorm:"INDEX(s)"`
	Config             convert.Conversion `xorm:"TEXT"`
	CreatedUnix        timeutil.TimeStamp `xorm:"INDEX CREATED"`
	DefaultPermissions UnitAccessMode     `xorm:"NOT NULL DEFAULT 0"`
}

func init() {
	db.RegisterModel(new(RepoUnit))
}

// UnitConfig describes common unit config
type UnitConfig struct{}

// FromDB fills up a UnitConfig from serialized format.
func (cfg *UnitConfig) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a UnitConfig to a serialized format.
func (cfg *UnitConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// CodeConfig describes code config
type CodeConfig struct {
	// IndexedBranches are names or glob patterns of branches, besides the default one, that code search indexes
	IndexedBranches []string
}

// FromDB fills up a CodeConfig from serialized format.
func (cfg *CodeConfig) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a CodeConfig to a serialized format.
func (cfg *CodeConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// ExternalWikiConfig describes external wiki config
type ExternalWikiConfig struct {
	ExternalWikiURL string
}

// FromDB fills up a ExternalWikiConfig from serialized format.
func (cfg *ExternalWikiConfig) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a ExternalWikiConfig to a serialized format.
func (cfg *ExternalWikiConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// WikiSourceFolder publishes a folder of the code repository as the wiki
const WikiSourceFolder = "folder"

// WikiConfig describes wiki config; the zero value is the separate wiki repository
type WikiConfig struct {
	Source string // "" or WikiSourceFolder
	Folder string // folder of the code repository, see CleanWikiFolder
	Branch string // "" means the default branch
}

// FromFolder reports whether the wiki is a folder of the code repository
func (cfg *WikiConfig) FromFolder() bool {
	return cfg.Source == WikiSourceFolder
}

// FromDB fills up a WikiConfig from serialized format.
func (cfg *WikiConfig) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a WikiConfig to a serialized format.
func (cfg *WikiConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// CleanWikiFolder returns the cleaned folder, or "" when it is not a folder inside the repository below its root.
func CleanWikiFolder(folder string) string {
	if len(folder) > 255 || strings.HasPrefix(folder, "/") || strings.ContainsAny(folder, "\\\x00") ||
		slices.Contains(strings.Split(folder, "/"), "..") {
		return ""
	}
	if folder = path.Clean(folder); folder == "." {
		return ""
	}
	return folder
}

// ExternalTrackerConfig describes external tracker config
type ExternalTrackerConfig struct {
	ExternalTrackerURL           string
	ExternalTrackerFormat        string
	ExternalTrackerStyle         string
	ExternalTrackerRegexpPattern string
}

// FromDB fills up a ExternalTrackerConfig from serialized format.
func (cfg *ExternalTrackerConfig) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a ExternalTrackerConfig to a serialized format.
func (cfg *ExternalTrackerConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// IssuesConfig describes issues config
type IssuesConfig struct {
	EnableTimetracker                bool
	AllowOnlyContributorsToTrackTime bool
	EnableDependencies               bool
}

// FromDB fills up a IssuesConfig from serialized format.
func (cfg *IssuesConfig) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a IssuesConfig to a serialized format.
func (cfg *IssuesConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// DeleteBranchMode tells if the head branch is deleted after a merge. The zero value inherits from the organization or the instance.
type DeleteBranchMode int

const (
	DeleteBranchInherit DeleteBranchMode = iota
	DeleteBranchOff
	DeleteBranchDefaultOn
	DeleteBranchAlways
)

var deleteBranchModeNames = [...]string{"inherit", "off", "default-on", "always"}

func (m DeleteBranchMode) String() string {
	if m < 0 || int(m) >= len(deleteBranchModeNames) {
		return deleteBranchModeNames[DeleteBranchInherit]
	}
	return deleteBranchModeNames[m]
}

// ParseDeleteBranchMode parses the names returned by String.
func ParseDeleteBranchMode(s string) (DeleteBranchMode, bool) {
	for i, name := range deleteBranchModeNames {
		if name == s {
			return DeleteBranchMode(i), true
		}
	}
	return DeleteBranchInherit, false
}

// PullRequestsConfig describes pull requests config
type PullRequestsConfig struct {
	IgnoreWhitespaceConflicts     bool
	AllowMerge                    bool
	AllowRebase                   bool
	AllowRebaseMerge              bool
	AllowSquash                   bool
	AllowFastForwardOnly          bool
	AllowManualMerge              bool
	AutodetectManualMerge         bool
	AllowRebaseUpdate             bool
	DefaultDeleteBranchAfterMerge bool // legacy, read through GetDeleteBranchAfterMerge
	DeleteBranchAfterMerge        DeleteBranchMode
	DefaultMergeStyle             MergeStyle
	DefaultUpdateStyle            UpdateStyle
	DefaultAllowMaintainerEdit    bool
	CancelAutoMergeOnPush         bool            // a push to the head cancels the pull request's auto merge
	BranchingModel                *BranchingModel // nil inherits from the organization
}

// BranchingModel names the development branch and the release branches whose names end in a version.
type BranchingModel struct {
	DevelopmentBranch string   `json:",omitempty"` // "" is the repository's default branch
	ReleasePrefixes   []string `json:",omitempty"`
	ProductionBranch  string   `json:",omitempty"` // "" is none; merges into it are merged forward into the development branch
	MergeForward      bool     `json:",omitempty"` // a merge into a release or the production branch is merged forward
	// MergeForwardNeverBypass makes a step that branch protection refuses open a pull request; otherwise a step is an
	// extension of the approved pull request, allowed to whoever may merge into the target without its approvals
	// and status checks
	MergeForwardNeverBypass bool `json:",omitempty"`
	// MergeForwardAnyoneMaySkip lets everyone who merges choose "Don't merge forward"; otherwise only those who may
	// change the branching model
	MergeForwardAnyoneMaySkip bool `json:",omitempty"`
	// Types are the branch types besides Release, whose prefixes are ReleasePrefixes
	Types []BranchType `json:",omitempty"`
	// DefaultPRTarget is the branch new pull requests target when their branch has no type; "" is the default branch
	DefaultPRTarget string `json:",omitempty"`
}

// The branch a branch type is created from and its pull requests target.
const (
	BranchTypeBaseDevelopment = "development"
	BranchTypeBaseProduction  = "production"
	BranchTypeBaseBranch      = "branch" // the branch named in BaseBranch
)

// BranchType is a kind of branch told by the start of its name.
type BranchType struct {
	Name       string
	Prefix     string
	Base       string // one of the BranchTypeBase constants
	BaseBranch string `json:",omitempty"` // only for BranchTypeBaseBranch
	Off        bool   `json:",omitempty"` // a type that is turned off doesn't match branches
}

// FromDB fills up a PullRequestsConfig from serialized format.
func (cfg *PullRequestsConfig) FromDB(bs []byte) error {
	// AllowRebaseUpdate = true as default for existing PullRequestConfig in DB
	cfg.AllowRebaseUpdate = true
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a PullRequestsConfig to a serialized format.
func (cfg *PullRequestsConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// GetDeleteBranchAfterMerge returns the repository's own mode. Repositories that only have the legacy bool count as "Default on".
func (cfg *PullRequestsConfig) GetDeleteBranchAfterMerge() DeleteBranchMode {
	if cfg.DeleteBranchAfterMerge == DeleteBranchInherit && cfg.DefaultDeleteBranchAfterMerge {
		return DeleteBranchDefaultOn
	}
	return cfg.DeleteBranchAfterMerge
}

// IsMergeStyleAllowed returns if merge style is allowed
func (cfg *PullRequestsConfig) IsMergeStyleAllowed(mergeStyle MergeStyle) bool {
	return mergeStyle == MergeStyleMerge && cfg.AllowMerge ||
		mergeStyle == MergeStyleRebase && cfg.AllowRebase ||
		mergeStyle == MergeStyleRebaseMerge && cfg.AllowRebaseMerge ||
		mergeStyle == MergeStyleSquash && cfg.AllowSquash ||
		mergeStyle == MergeStyleFastForwardOnly && cfg.AllowFastForwardOnly ||
		mergeStyle == MergeStyleManuallyMerged && cfg.AllowManualMerge
}

// GetDefaultMergeStyle returns the default merge style for this pull request
func (cfg *PullRequestsConfig) GetDefaultMergeStyle() MergeStyle {
	if len(cfg.DefaultMergeStyle) != 0 {
		return cfg.DefaultMergeStyle
	}

	if setting.Repository.PullRequest.DefaultMergeStyle != "" {
		return MergeStyle(setting.Repository.PullRequest.DefaultMergeStyle)
	}

	return MergeStyleMerge
}

// IsUpdateStyleAllowed returns if update style is allowed
func (cfg *PullRequestsConfig) IsUpdateStyleAllowed(updateStyle UpdateStyle) bool {
	return updateStyle == UpdateStyleMerge ||
		updateStyle == UpdateStyleRebase && cfg.AllowRebaseUpdate
}

// GetDefaultUpdateStyle returns the default update style for this pull request
func (cfg *PullRequestsConfig) GetDefaultUpdateStyle() UpdateStyle {
	if len(cfg.DefaultUpdateStyle) != 0 {
		return cfg.DefaultUpdateStyle
	}

	if setting.Repository.PullRequest.DefaultUpdateStyle != "" {
		return UpdateStyle(setting.Repository.PullRequest.DefaultUpdateStyle)
	}

	return UpdateStyleMerge
}

// Represents the current format for `sub` claim generation when using `enable-openid-connect: true` on an Action.
//
// We try to follow GitHub's format for the `sub` claim because it should allow third-party integrations, which may have
// existing knowledge and code that works with GitHub's OIDC tokens, to reuse that knowledge and code in the future to
// implement Forgejo support.  As GitHub's format changes, we may implement those format changes to maintain that
// familarity.  Forgejo isn't required to do so, though -- if future changes from GitHub don't make sense for Forgejo,
// or vice-versa, this format matching effort may be discarded.
type OIDCSubjectFormat string

var (
	// Default is the current, most preferred method of generating an `sub` JWT claim for an Actions JWT token.  It is
	// an empty string which allows [ActionsConfig] to always default to the current preferred default value for new
	// repositories.  At present, it is a `sub` claim that contains information about the repository owner and
	// repository where the action occurred, their immutable identifiers (ID numbers), and the event that triggered the
	// Action.
	//
	// Immutable identifiers have been added since OIDCSubjectFormatLegacyForgejo15.  The intent of adding them is to
	// protect resource servers which may be requiring a specific subject claim from having that claim be impersonated
	// when a user or repository are renamed or deleted.  For example, if a JWT from my-org/my-repo is trusted, but then
	// my-org is deleted and a new user takes ownership of the name my-org, they should not be granted the same trust.
	//
	// Example: repo:my-org-123456/my-repo-456789:ref:refs/heads/main
	OIDCSubjectFormatDefault OIDCSubjectFormat // defaults to ""

	// The `sub` JWT claim generation that was shipped in Forgejo 15.  Contains information about the repository owner
	// and repository where the action occurred and the event that triggered the Action.
	//
	// Example: repo:my-org/my-repo:ref:refs/heads/main
	OIDCSubjectFormatLegacyForgejo15 OIDCSubjectFormat = "legacy-forgejo-v15"
)

type ActionsConfig struct {
	DisabledWorkflows []string

	// Format of the OIDC 'sub' claim that will be used when `enable-openid-connect` is true in an Action.
	OIDCSubjectFormat OIDCSubjectFormat `json:",omitempty"`

	// DefaultTokenPermissions is "read" or "write" for the job token of a workflow without `permissions:`, or empty
	// for the instance default ([actions] DEFAULT_TOKEN_PERMISSIONS).
	DefaultTokenPermissions string `json:",omitempty"`

	// RunRetentionDays shortens the time runs of this repository are kept (0 = no repository setting), see
	// actions_model.EffectiveRunRetentionDays.
	RunRetentionDays int64 `json:",omitempty"`
}

// EffectiveDefaultTokenPermissions returns the repository default token permissions, else the instance default.
func (cfg *ActionsConfig) EffectiveDefaultTokenPermissions() string {
	if cfg.DefaultTokenPermissions == "read" || cfg.DefaultTokenPermissions == "write" {
		return cfg.DefaultTokenPermissions
	}
	return setting.Actions.DefaultTokenPermissions
}

func (cfg *ActionsConfig) EnableWorkflow(file string) {
	cfg.DisabledWorkflows = util.SliceRemoveAll(cfg.DisabledWorkflows, file)
}

func (cfg *ActionsConfig) ToString() string {
	return strings.Join(cfg.DisabledWorkflows, ",")
}

func (cfg *ActionsConfig) IsWorkflowDisabled(file string) bool {
	return slices.Contains(cfg.DisabledWorkflows, file)
}

func (cfg *ActionsConfig) DisableWorkflow(file string) {
	if slices.Contains(cfg.DisabledWorkflows, file) {
		return
	}

	cfg.DisabledWorkflows = append(cfg.DisabledWorkflows, file)
}

// FromDB fills up a ActionsConfig from serialized format.
func (cfg *ActionsConfig) FromDB(bs []byte) error {
	return json.UnmarshalHandleDoubleEncode(bs, &cfg)
}

// ToDB exports a ActionsConfig to a serialized format.
func (cfg *ActionsConfig) ToDB() ([]byte, error) {
	return json.Marshal(cfg)
}

// BeforeSet is invoked from XORM before setting the value of a field of this object.
func (r *RepoUnit) BeforeSet(colName string, val xorm.Cell) {
	if colName == "type" {
		switch unit.Type(db.Cell2Int64(val)) {
		case unit.TypeExternalWiki:
			r.Config = new(ExternalWikiConfig)
		case unit.TypeExternalTracker:
			r.Config = new(ExternalTrackerConfig)
		case unit.TypePullRequests:
			r.Config = new(PullRequestsConfig)
		case unit.TypeIssues:
			r.Config = new(IssuesConfig)
		case unit.TypeActions:
			r.Config = new(ActionsConfig)
		case unit.TypeCode:
			r.Config = new(CodeConfig)
		case unit.TypeWiki:
			r.Config = new(WikiConfig)
		case unit.TypeReleases, unit.TypeProjects, unit.TypePackages:
			fallthrough
		default:
			r.Config = new(UnitConfig)
		}
	}
}

// Unit returns Unit
func (r *RepoUnit) Unit() unit.Unit {
	return unit.Units[r.Type]
}

// CodeConfig returns config for unit.TypeCode
func (r *RepoUnit) CodeConfig() *CodeConfig {
	return r.Config.(*CodeConfig)
}

// PullRequestsConfig returns config for unit.TypePullRequests
func (r *RepoUnit) PullRequestsConfig() *PullRequestsConfig {
	return r.Config.(*PullRequestsConfig)
}

// ReleasesConfig returns config for unit.TypeReleases
func (r *RepoUnit) ReleasesConfig() *UnitConfig {
	return r.Config.(*UnitConfig)
}

// ExternalWikiConfig returns config for unit.TypeExternalWiki
func (r *RepoUnit) ExternalWikiConfig() *ExternalWikiConfig {
	return r.Config.(*ExternalWikiConfig)
}

// WikiConfig returns config for unit.TypeWiki, the zero value when the unit has none
func (r *RepoUnit) WikiConfig() *WikiConfig {
	if cfg, ok := r.Config.(*WikiConfig); ok && cfg != nil {
		return cfg
	}
	return new(WikiConfig)
}

// IssuesConfig returns config for unit.TypeIssues
func (r *RepoUnit) IssuesConfig() *IssuesConfig {
	return r.Config.(*IssuesConfig)
}

// ExternalTrackerConfig returns config for unit.TypeExternalTracker
func (r *RepoUnit) ExternalTrackerConfig() *ExternalTrackerConfig {
	return r.Config.(*ExternalTrackerConfig)
}

// ActionsConfig returns config for unit.ActionsConfig
func (r *RepoUnit) ActionsConfig() *ActionsConfig {
	return r.Config.(*ActionsConfig)
}

func getUnitsByRepoID(ctx context.Context, repoID int64) (units []*RepoUnit, err error) {
	var tmpUnits []*RepoUnit
	if err := availableUnitsSession(ctx).And("`repo_unit`.repo_id = ?", repoID).Find(&tmpUnits); err != nil {
		return nil, err
	}

	for _, u := range tmpUnits {
		if !u.Type.UnitGlobalDisabled() {
			units = append(units, u)
		}
	}

	return units, nil
}

// availableUnitsSession selects the repo_unit rows the site policy and the organization owner don't hide. It joins
// repository only when something is hidden, so an empty policy costs nothing.
func availableUnitsSession(ctx context.Context) *xorm.Session {
	cond := AvailableUnitCond(ctx, "`repository`.owner_id", "`repo_unit`.type")
	if !cond.IsValid() {
		return db.GetEngine(ctx).Where(builder.NewCond())
	}
	return db.GetEngine(ctx).Select("`repo_unit`.*").Join("INNER", "repository", "`repository`.id = `repo_unit`.repo_id").Where(cond)
}

// GetRepoUnitForUpdate locks the stored unit row of a repository with a no-op UPDATE (a row lock on PostgreSQL and
// MySQL, the write lock on SQLite), then reads it, so that two writers in transactions can't overwrite each other.
func GetRepoUnitForUpdate(ctx context.Context, repoID int64, tp unit.Type) (*RepoUnit, bool, error) {
	if _, err := db.Exec(ctx, "UPDATE `repo_unit` SET type = type WHERE repo_id = ? AND type = ?", repoID, tp); err != nil {
		return nil, false, err
	}
	u := &RepoUnit{}
	has, err := db.GetEngine(ctx).Where("repo_id = ? AND type = ?", repoID, tp).Get(u)
	return u, has, err
}

// UpdateRepoUnit updates the provided repo unit
func UpdateRepoUnit(ctx context.Context, unit *RepoUnit) error {
	_, err := db.GetEngine(ctx).ID(unit.ID).Update(unit)
	if err != nil {
		return fmt.Errorf("UpdateRepoUnit: %v", err)
	}
	return nil
}
