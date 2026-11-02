// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package agit

import (
	"errors"
	"fmt"
	"testing"

	git_model "forgejo.org/models/git"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPRTitleRefusal(t *testing.T) {
	require.NoError(t, prTitleRefusal(errors.New("other")))

	err := prTitleRefusal(fmt.Errorf("wrapped: %w", &git_model.ErrPRTitleRule{Message: "use KEY-1\x1b[2J\nfake: ok\r"}))
	require.Error(t, err)
	assert.Equal(t, "pull request title refused: use KEY-1 [2J fake: ok ", err.Error())

	err = prTitleRefusal(&git_model.ErrPRTitleRule{})
	assert.Equal(t, "pull request title refused: the title does not follow the title rules of this repository", err.Error())
	err = prTitleRefusal(&git_model.ErrPRTitleRule{Invalid: true, Message: "ignored"})
	assert.Contains(t, err.Error(), "invalid")
}
