// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package issue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTemplateDirFile(t *testing.T) {
	assert.True(t, IsTemplateDirFile(".forgejo/ISSUE_TEMPLATE/bug.yaml"))
	assert.True(t, IsTemplateDirFile("ISSUE_TEMPLATE/bug.md"))
	assert.False(t, IsTemplateDirFile(".forgejo/ISSUE_TEMPLATE/../secret.md"))
	assert.False(t, IsTemplateDirFile(".forgejo/ISSUE_TEMPLATE/sub/bug.md"))
	assert.False(t, IsTemplateDirFile("README.md"))
	assert.False(t, IsTemplateDirFile(".forgejo/ISSUE_TEMPLATE/bug.txt"))
	assert.False(t, IsTemplateDirFile(".forgejo/ISSUE_TEMPLATE.md"))
	assert.False(t, IsTemplateDirFile(""))
}
