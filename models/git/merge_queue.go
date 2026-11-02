// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package git

import (
	"fmt"
	"slices"
	"time"

	"forgejo.org/modules/util"
)

// Merge queue defaults, used where a rule stores 0
const (
	DefaultMergeQueueBuildConcurrency = 5
	DefaultMergeQueueMinGroupSize     = 1
	DefaultMergeQueueMaxGroupSize     = 5
	DefaultMergeQueueWaitMinutes      = 5
	DefaultMergeQueueCheckTimeout     = 60
	MaxMergeQueueSize                 = 100  // upper bound of the concurrency and group sizes
	MaxMergeQueueMinutes              = 1440 // upper bound of the wait time and the check timeout
)

// MergeQueueConfig is the merge queue setting of a rule with the defaults applied.
type MergeQueueConfig struct {
	BuildConcurrency int
	MinGroupSize     int
	MaxGroupSize     int
	WaitTime         time.Duration
	CheckTimeout     time.Duration
	MergeStyle       string // "" = the style chosen for the pull request
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// MergeQueueConfig returns the merge queue setting of the rule with the defaults applied.
func (protectBranch *ProtectedBranch) MergeQueueConfig() MergeQueueConfig {
	return MergeQueueConfig{
		BuildConcurrency: orDefault(protectBranch.MergeQueueBuildConcurrency, DefaultMergeQueueBuildConcurrency),
		MinGroupSize:     orDefault(protectBranch.MergeQueueMinGroupSize, DefaultMergeQueueMinGroupSize),
		MaxGroupSize:     orDefault(protectBranch.MergeQueueMaxGroupSize, min(DefaultMergeQueueMaxGroupSize, orDefault(protectBranch.MergeQueueBuildConcurrency, DefaultMergeQueueBuildConcurrency))),
		WaitTime:         time.Duration(orDefault(protectBranch.MergeQueueWaitMinutes, DefaultMergeQueueWaitMinutes)) * time.Minute,
		CheckTimeout:     time.Duration(orDefault(protectBranch.MergeQueueCheckTimeoutMinutes, DefaultMergeQueueCheckTimeout)) * time.Minute,
		MergeStyle:       protectBranch.MergeQueueMergeStyle,
	}
}

// MergeQueueRule returns the first of rules (as GetMatchedProtectedBranchRules returns them: repository, project,
// organization) that requires a merge queue, nil if none does.
func MergeQueueRule(rules []*ProtectedBranch) *ProtectedBranch {
	for _, pb := range rules {
		if pb.RequireMergeQueue {
			return pb
		}
	}
	return nil
}

// ErrInvalidMergeQueueConfig is returned for merge queue settings out of range
var ErrInvalidMergeQueueConfig = util.NewInvalidArgumentErrorf("merge queue settings out of range: concurrency and group sizes 0 to %d, the minimum group size at most the maximum and the concurrency, times 0 to %d minutes, merge style merge, rebase, rebase-merge, squash or empty", MaxMergeQueueSize, MaxMergeQueueMinutes)

// MergeQueueConfigError names the merge queue setting that is out of range: merge_style, build_concurrency,
// min_group_size, max_group_size, wait or check_timeout
type MergeQueueConfigError struct {
	Field string
}

func (e *MergeQueueConfigError) Error() string {
	return fmt.Sprintf("%s: %v", e.Field, ErrInvalidMergeQueueConfig)
}

func (e *MergeQueueConfigError) Unwrap() error { return ErrInvalidMergeQueueConfig }

// ValidateMergeQueue checks the merge queue settings of the rule; 0 means the default. The error is a
// *MergeQueueConfigError.
func (protectBranch *ProtectedBranch) ValidateMergeQueue() error {
	inRange := func(v, maxV int) bool { return v >= 0 && v <= maxV }
	cfg := protectBranch.MergeQueueConfig()
	var field string
	switch {
	case !slices.Contains([]string{"", "merge", "rebase", "rebase-merge", "squash"}, protectBranch.MergeQueueMergeStyle):
		field = "merge_style"
	case !inRange(protectBranch.MergeQueueBuildConcurrency, MaxMergeQueueSize):
		field = "build_concurrency"
	case !inRange(protectBranch.MergeQueueMaxGroupSize, MaxMergeQueueSize) || protectBranch.MergeQueueMaxGroupSize > cfg.BuildConcurrency:
		field = "max_group_size"
	case !inRange(protectBranch.MergeQueueMinGroupSize, MaxMergeQueueSize) || cfg.MinGroupSize > cfg.MaxGroupSize:
		field = "min_group_size"
	case !inRange(protectBranch.MergeQueueWaitMinutes, MaxMergeQueueMinutes):
		field = "wait"
	case !inRange(protectBranch.MergeQueueCheckTimeoutMinutes, MaxMergeQueueMinutes):
		field = "check_timeout"
	default:
		return nil
	}
	return &MergeQueueConfigError{Field: field}
}
