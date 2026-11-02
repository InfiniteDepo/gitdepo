// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: MIT

package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Doc IDs use ':' as separator, which can't appear in a ref name, so branch a + file b/c differs from branch a/b + file c.
func TestFilenameIndexerID(t *testing.T) {
	assert.Equal(t, "1_develop:a/b.go", FilenameIndexerID(1, "develop", "a/b.go"))
	assert.NotEqual(t, FilenameIndexerID(1, "a", "b/c"), FilenameIndexerID(1, "a/b", "c"))
}
