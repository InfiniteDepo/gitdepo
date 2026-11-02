// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package setting

import (
	"testing"

	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePersonalRepos(t *testing.T) {
	for in, want := range map[string]string{"": "allowed", "allowed": "allowed", "Private_Only": "private_only", "disabled": "disabled"} {
		got, err := parsePersonalRepos(in)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := parsePersonalRepos("private")
	require.Error(t, err)
}

func TestPersonalReposEffectiveMode(t *testing.T) {
	defer test.MockVariableValue(&Repository.PersonalRepos, PersonalReposPrivateOnly)()
	assert.Equal(t, PersonalReposPrivateOnly, PersonalReposState{}.EffectiveMode())
	assert.Equal(t, PersonalReposAllowed, PersonalReposState{Mode: "allowed"}.EffectiveMode())
	assert.Equal(t, PersonalReposDisabled, PersonalReposState{Mode: "invalid"}.EffectiveMode())
}

func TestPersonalReposEffectiveSizeLimit(t *testing.T) {
	defer test.MockVariableValue(&Repository.PersonalReposSizeLimit, 50)()
	assert.EqualValues(t, 50, PersonalReposState{}.EffectiveSizeLimit(), "nothing stored: app.ini")
	assert.EqualValues(t, 0, PersonalReposState{Mode: "allowed"}.EffectiveSizeLimit(), "stored off")
	assert.EqualValues(t, 7, PersonalReposState{Mode: "allowed", SizeLimit: 7}.EffectiveSizeLimit())
	assert.EqualValues(t, 0, PersonalReposState{Mode: "allowed", SizeLimit: -7}.EffectiveSizeLimit(), "negative is off")
	assert.EqualValues(t, 0, PersonalReposState{Mode: "invalid"}.EffectiveSizeLimit(), "unreadable")
}

func TestLoadPersonalReposSizeLimit(t *testing.T) {
	defer test.MockVariableValue(&Repository.PersonalReposSizeLimit, 0)()
	cfg, err := NewConfigProviderFromData("[repository]\nPERSONAL_REPOS_SIZE_LIMIT = 50 MiB\n")
	require.NoError(t, err)
	loadRepositoryFrom(cfg)
	assert.EqualValues(t, 50<<20, Repository.PersonalReposSizeLimit)
}
