// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mergequeue

import (
	"testing"
	"time"

	git_model "forgejo.org/models/git"
	pull_model "forgejo.org/models/pull"
	"forgejo.org/modules/timeutil"

	"github.com/stretchr/testify/assert"
)

func TestMarkGrouping(t *testing.T) {
	now := timeutil.TimeStampNow()
	entries := func(states ...string) []*ViewEntry {
		view := make([]*ViewEntry, len(states))
		for i, s := range states {
			view[i] = &ViewEntry{MergeQueueEntry: &pull_model.MergeQueueEntry{EnqueuedUnix: now - 60}, State: s}
		}
		return view
	}
	cfg := git_model.MergeQueueConfig{MaxGroupSize: 5, MinGroupSize: 4, WaitTime: 10 * time.Minute}

	view := entries(StatePassed, StateTesting, StatePassed, StateWaiting)
	markGrouping(view, cfg)
	assert.Equal(t, StateGrouping, view[0].State)
	assert.Equal(t, StateTesting, view[1].State)
	assert.Equal(t, StateGrouping, view[2].State)
	assert.Equal(t, 3, view[0].GroupPassed, "as merge counts: up to the last passed one")
	assert.Equal(t, 4, view[0].GroupMin)
	assert.Equal(t, now-60+600, view[0].GroupUntil)

	// the group is complete, the wait time is over, or nothing passed: it merges as soon as it can
	for _, tc := range []struct {
		view []*ViewEntry
		cfg  git_model.MergeQueueConfig
	}{
		{entries(StatePassed, StatePassed, StateTesting, StatePassed), cfg},
		{entries(StatePassed), git_model.MergeQueueConfig{MaxGroupSize: 5, MinGroupSize: 3}},
		{entries(StatePassed), git_model.MergeQueueConfig{MaxGroupSize: 5, MinGroupSize: 1, WaitTime: time.Hour}},
	} {
		markGrouping(tc.view, tc.cfg)
		assert.Equal(t, StatePassed, tc.view[0].State)
	}
	view = entries(StateTesting)
	markGrouping(view, cfg)
	assert.Equal(t, StateTesting, view[0].State)
}
