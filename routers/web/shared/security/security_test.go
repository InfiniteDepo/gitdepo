// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package security

import (
	"strings"
	"testing"
	"unicode/utf8"

	"forgejo.org/modules/optional"

	"github.com/stretchr/testify/assert"
)

func TestFormVersionOrRange(t *testing.T) {
	// anything that is not operator-shaped is an exact version, whatever a version parser would say of it
	for _, c := range [][2]string{
		{"npm", "4.17.20"},
		{"npm", "v1.2.3"},
		{"npm", "1.0.0-rc.1"},
		{"npm", "2.1.0+build"},
		{"npm", "4.17"},
		{"npm", "1"},
		{"PyPI", "1!2.0"},
		{"Packagist", "dev-main"},
		{"Go", "v1.2.3"},
		{"Maven", "1.0-SNAPSHOT"},
		{"npm", "file:../x"},
	} {
		v := c[1]
		assert.False(t, isRange(v), c)
		assert.Equal(t, v, Form{Ecosystem: c[0], Version: v}.usage().Version, c)
		assert.Empty(t, Form{Ecosystem: c[0], Version: v}.usage().Range, c)
	}
	for _, c := range [][2]string{
		{"npm", "=1.2.3"},
		{"npm", "^4.0.0"},
		{"npm", "~1.2"},
		{"npm", ">=2,<3"},
		{"npm", ">=1.2 <2"},
		{"npm", "1.x"},
		{"npm", "1.2.X"},
		{"npm", "*"},
		{"npm", "1 - 2"},
		{"npm", "1 || 2"},
		{"Maven", "[1.0,2.0)"},
		{"PyPI", "!=1.0"},
		{"PyPI", "==1.0"},
	} {
		v := c[1]
		assert.True(t, isRange(v), c)
		assert.Equal(t, v, Form{Ecosystem: c[0], Version: v}.usage().Range, c)
		assert.Empty(t, Form{Ecosystem: c[0], Version: v}.usage().Version, c)
	}
	assert.False(t, isRange(""))
}

func TestClip(t *testing.T) {
	assert.Equal(t, "CVE-1", clip("CVE-1"))
	got := clip("a" + strings.Repeat("é", 100)) // the 64-byte cut falls inside a rune
	assert.Equal(t, "a"+strings.Repeat("é", 31)+"…", got)
	assert.True(t, utf8.ValidString(got))
}

func TestFormSearched(t *testing.T) {
	assert.False(t, Form{}.searched(Vulnerabilities))
	assert.False(t, Form{Ecosystem: "npm", State: "all", Project: "x", Owner: "y"}.searched(Vulnerabilities), "only the fields that name something count")
	assert.True(t, Form{Advisory: "CVE-2024-1"}.searched(Vulnerabilities))
	assert.True(t, Form{Name: "lodash"}.searched(Vulnerabilities))
	assert.False(t, Form{Ecosystem: "npm", Direct: true}.searched(Dependencies))
	assert.True(t, Form{Name: "lodash"}.searched(Dependencies))
	assert.True(t, Form{Version: "1.0.0"}.searched(Dependencies), "so that a missing package is told")
}

func TestFormQuery(t *testing.T) {
	assert.Empty(t, Form{}.Query())
	q := Form{Advisory: "CVE-2024-1", Ecosystem: "npm", Name: "lodash", Version: "^4", State: "all", Project: "p", Owner: "o", Direct: true}.Query()
	assert.Equal(t, "advisory=CVE-2024-1&direct=true&ecosystem=npm&name=lodash&owner=o&project=p&state=all&version=%5E4", q.Encode())
	assert.Equal(t, optional.Some(true), Form{Direct: true}.usage().Direct)
	assert.False(t, Form{}.usage().Direct.Has())
}
