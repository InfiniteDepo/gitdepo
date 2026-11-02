// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package drawio

import (
	"strings"
	"testing"

	"forgejo.org/modules/markup"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func render(t *testing.T, standalone bool, input string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := markup.Render(&markup.RenderContext{Ctx: t.Context(), Type: "drawio", InStandalonePage: standalone}, strings.NewReader(input), &out)
	return out.String(), err
}

func TestRender(t *testing.T) {
	defer test.MockVariableValue(&setting.StaticURLPrefix, "/sub")()
	const xml = `<mxfile><diagram>"><script>alert(1)</script>&amp;</diagram></mxfile>`

	t.Run("NotStandalone", func(t *testing.T) {
		out, err := render(t, false, xml)
		require.Error(t, err)
		assert.NotContains(t, out, "<script")
	})

	t.Run("Standalone", func(t *testing.T) {
		out, err := render(t, true, xml)
		require.NoError(t, err)
		assert.Contains(t, out, `<div class="mxgraph" data-mxgraph="{&#34;lightbox&#34;:false,`)
		assert.Contains(t, out, `&#34;xml&#34;:&#34;&lt;mxfile&gt;&lt;diagram&gt;\&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;amp;&lt;/diagram&gt;&lt;/mxfile&gt;&#34;}`)
		assert.NotContains(t, out, "<script>alert")
		assert.Contains(t, out, "mxStencilRegistry.allowEval=false;")
		assert.Contains(t, out, `<script src="/sub/assets/vendor/drawio/viewer-static-32.0.2.min.js"></script>`)
	})

	t.Run("TooLarge", func(t *testing.T) {
		defer test.MockVariableValue(&setting.UI.MaxDisplayFileSize, int64(len(xml)-1))()
		out, err := render(t, true, xml)
		require.Error(t, err)
		assert.NotContains(t, out, "mxgraph")
	})
}

func TestExtensions(t *testing.T) {
	defer test.MockVariableValue(&setting.DrawioEnabled, true)()
	assert.Equal(t, []string{".drawio", ".drawio.xml"}, Renderer{}.Extensions())

	setting.DrawioEnabled = false
	assert.Empty(t, Renderer{}.Extensions())
}
