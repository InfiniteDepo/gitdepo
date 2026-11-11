// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

// OrgBranchWorkflow represents the branch workflow settings of an organization, and the body to change them
type OrgBranchWorkflow struct {
	// DeleteBranchAfterMerge is one of inherit, off, default-on and always
	DeleteBranchAfterMerge string `json:"delete_branch_after_merge"`
	// EnforceDeleteBranchAfterMerge locks the value for all repositories of the organization
	EnforceDeleteBranchAfterMerge bool `json:"enforce_delete_branch_after_merge"`
}

// RepoBranchWorkflow represents the branch workflow settings of a repository
type RepoBranchWorkflow struct {
	// DeleteBranchAfterMerge is the repository's own value: inherit, off, default-on or always
	DeleteBranchAfterMerge string `json:"delete_branch_after_merge"`
	// EffectiveDeleteBranchAfterMerge is the value that applies: off, default-on or always
	EffectiveDeleteBranchAfterMerge string `json:"effective_delete_branch_after_merge"`
	// Source tells where the effective value comes from: instance, org or repo
	Source string `json:"source"`
	// Locked is true when the organization enforces the value
	Locked bool `json:"locked"`
	// LockedBy is the organization that enforces the value
	LockedBy string `json:"locked_by,omitempty"`
}

// EditRepoBranchWorkflowOption options to change the branch workflow settings of a repository
type EditRepoBranchWorkflowOption struct {
	// DeleteBranchAfterMerge is one of inherit, off, default-on and always
	// required: true
	DeleteBranchAfterMerge string `json:"delete_branch_after_merge" binding:"Required"`
}

// BranchType is a kind of branch told by the start of its name
type BranchType struct {
	// Name is shown in the interface, 1 to 50 characters
	Name string `json:"name"`
	// Prefix starts the names of the branches of this type; at most 100 characters, no comma, different for every type
	Prefix string `json:"prefix"`
	// Base is the branch the type's pull requests target: development, production or branch (the one named in base_branch)
	Base string `json:"base"`
	// BaseBranch is the branch for base branch; it may not exist yet, then the development branch is used
	BaseBranch string `json:"base_branch,omitempty"`
	// Off turns the type off: its branches have no type
	Off bool `json:"off"`
}

// BranchNaming is what the branching model asks of the names of new branches
type BranchNaming struct {
	// RequireBranchType refuses new branches and renames whose name is not a branch type or release prefix followed by a name, the development, production, default or a base branch, or an exception; it needs an enabled type, a release prefix or an exception
	RequireBranchType bool `json:"require_branch_type"`
	// Exceptions are glob patterns of branch names that are allowed anyway: case-sensitive, matched against the whole name, at most 20
	Exceptions []string `json:"exceptions"`
	// ExemptUsers may create any branch name; every such creation is recorded in the audit log. Deploy keys, tokens, Actions and administrators are exempt only when named here
	ExemptUsers []string `json:"exempt_users"`
	// ExemptTeams are teams of the organization whose members are exempt, like ExemptUsers
	ExemptTeams []string `json:"exempt_teams"`
}

// BranchingModel names the development branch and the release branch prefixes
type BranchingModel struct {
	// DevelopmentBranch is where every chain of release branches ends; empty is the repository's default branch
	DevelopmentBranch string `json:"development_branch"`
	// ReleasePrefixes start the names of release branches; the rest of the name is read as a version
	ReleasePrefixes []string `json:"release_prefixes"`
	// ProductionBranch is merged forward into the development branch; empty is none
	ProductionBranch string `json:"production_branch"`
	// Types are the branch types besides Release, whose prefixes are the release prefixes; at most 20
	Types []BranchType `json:"types"`
	// DefaultPRTarget is the branch new pull requests target when their branch has no type and the request names no base; empty is the default branch
	DefaultPRTarget string `json:"default_pr_target"`
	// BranchNaming holds the require-a-branch-type setting, its exception patterns and the exempt users and teams
	BranchNaming BranchNaming `json:"branch_naming"`
	// MergeForward merges a pull request merged into a release branch into every later release branch and the development branch, and one merged into the production branch into the development branch
	MergeForward bool `json:"merge_forward"`
	// MergeForwardNeverBypass makes a step that branch protection refuses open a pull request; otherwise a step counts as an extension of the approved pull request: whoever merged it must be allowed to merge into the target, whose required approvals and status checks are skipped
	MergeForwardNeverBypass bool `json:"merge_forward_never_bypass"`
	// MergeForwardAnyoneMaySkip lets everyone who merges choose not to merge forward; otherwise only those who may change the branching model
	MergeForwardAnyoneMaySkip bool `json:"merge_forward_anyone_may_skip"`
}

// OrgBranchingModel represents the branching model of an organization, and the body to change it
type OrgBranchingModel struct {
	// DevelopmentBranch is where every chain of release branches ends; empty is each repository's default branch
	DevelopmentBranch string `json:"development_branch"`
	// ReleasePrefixes start the names of release branches; empty, with no production branch, removes the branching model
	ReleasePrefixes []string `json:"release_prefixes"`
	// ProductionBranch is merged forward into the development branch; empty is none
	ProductionBranch string `json:"production_branch"`
	// Types are the branch types besides Release, whose prefixes are the release prefixes; at most 20
	Types []BranchType `json:"types"`
	// DefaultPRTarget is the branch new pull requests target when their branch has no type and the request names no base; empty is the default branch
	DefaultPRTarget string `json:"default_pr_target"`
	// BranchNaming holds the require-a-branch-type setting, its exception patterns and the exempt users and teams
	BranchNaming BranchNaming `json:"branch_naming"`
	// MergeForward merges a pull request merged into a release branch into every later release branch and the development branch, and one merged into the production branch into the development branch
	MergeForward bool `json:"merge_forward"`
	// MergeForwardNeverBypass makes a step that branch protection refuses open a pull request; otherwise a step counts as an extension of the approved pull request: whoever merged it must be allowed to merge into the target, whose required approvals and status checks are skipped
	MergeForwardNeverBypass bool `json:"merge_forward_never_bypass"`
	// MergeForwardAnyoneMaySkip lets everyone who merges choose not to merge forward; otherwise only those who may change the branching model
	MergeForwardAnyoneMaySkip bool `json:"merge_forward_anyone_may_skip"`
	// Enforce locks the branching model for all repositories of the organization; it needs a release prefix
	Enforce bool `json:"enforce"`
}

// RepoBranchingModel represents the branching model of a repository and what it makes of the repository's branches
type RepoBranchingModel struct {
	// Inherit is true when the repository has no branching model of its own
	Inherit bool `json:"inherit"`
	// Own is the repository's own branching model, absent when it inherits
	Own *BranchingModel `json:"own,omitempty"`
	// Effective is the branching model that applies; its development branch is resolved to a branch name
	Effective BranchingModel `json:"effective"`
	// Source tells where the effective value comes from: none, org or repo
	Source string `json:"source"`
	// Locked is true when the organization enforces the branching model
	Locked bool `json:"locked"`
	// LockedBy is the organization that enforces the branching model
	LockedBy string `json:"locked_by,omitempty"`
	// ReleaseBranches are the release branches in version order
	ReleaseBranches []string `json:"release_branches"`
	// IgnoredBranches have a release prefix but no version after it
	IgnoredBranches []string `json:"ignored_branches"`
}

// EditRepoBranchingModelOption options to change the branching model of a repository
type EditRepoBranchingModelOption struct {
	// Inherit removes the repository's own branching model; the other fields are then ignored
	Inherit           bool     `json:"inherit"`
	DevelopmentBranch string   `json:"development_branch"`
	ReleasePrefixes   []string `json:"release_prefixes"`
	ProductionBranch  string   `json:"production_branch"`
	// Types are the branch types besides Release, whose prefixes are the release prefixes; at most 20
	Types []BranchType `json:"types"`
	// DefaultPRTarget is the branch new pull requests target when their branch has no type and the request names no base; empty is the default branch
	DefaultPRTarget string `json:"default_pr_target"`
	// BranchNaming holds the require-a-branch-type setting, its exception patterns and the exempt users and teams
	BranchNaming BranchNaming `json:"branch_naming"`
	MergeForward bool         `json:"merge_forward"`
	// MergeForwardNeverBypass makes a step that branch protection refuses open a pull request; otherwise a step counts as an extension of the approved pull request: whoever merged it must be allowed to merge into the target, whose required approvals and status checks are skipped
	MergeForwardNeverBypass bool `json:"merge_forward_never_bypass"`
	// MergeForwardAnyoneMaySkip lets everyone who merges choose not to merge forward; otherwise only those who may change the branching model
	MergeForwardAnyoneMaySkip bool `json:"merge_forward_anyone_may_skip"`
}
