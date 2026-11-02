// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package mergequeue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaim(t *testing.T) {
	const key = "1:main"
	assert.True(t, claim(key))
	assert.False(t, claim(key), "one pass at a time")
	assert.True(t, next(key, false), "a pass asked for while one runs makes it go again")
	assert.False(t, next(key, false))
	assert.True(t, next(key, true))

	// a failing pass releases the branch, and reports a pass asked for meanwhile
	assert.False(t, claim(key))
	assert.True(t, release(key))
	assert.True(t, claim(key), "the branch is free after a failed pass")
	assert.False(t, release(key))
}
