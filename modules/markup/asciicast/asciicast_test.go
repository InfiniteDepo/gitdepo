// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package asciicast

import (
	"bytes"
	"strings"
	"testing"

	"forgejo.org/modules/markup"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRender_Project(t *testing.T) {
	for metas, expected := range map[string]string{
		"org|":     `/org/leaf/raw/branch/main/a.cast`,
		"org|proj": `/org/proj/leaf/raw/branch/main/a.cast`,
	} {
		owner, group, _ := strings.Cut(metas, "|")
		m := map[string]string{"user": owner, "repo": "leaf", "BranchNameSubURL": "branch/main"}
		if group != "" {
			m["group"] = group
		}
		var out bytes.Buffer
		require.NoError(t, Renderer{}.Render(&markup.RenderContext{Metas: m, RelativePath: "a.cast"}, nil, &out))
		assert.Contains(t, out.String(), expected)
	}
}
