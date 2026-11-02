// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBrandMentions(t *testing.T) {
	assert.Empty(t, BrandMentions(`<html><head><title>gitdepo</title><script>var x = "Forgejo";</script></head>
<body>Powered by gitdepo <a href="https://forgejo.org">based on Forgejo</a>
<a href="https://github.com/InfiniteDepo/gitdepo">InfiniteDepo/gitdepo</a> MyForgejoTeam1
<pre><code>$ forgejo-runner daemon</code></pre><input placeholder="next.forgejo.org"></body></html>`))

	assert.Equal(t, []string{"Welcome to Forgejo"}, BrandMentions(`<body><p>Welcome to Forgejo</p></body>`))
	assert.Equal(t, []string{"GitHat"}, BrandMentions(`<head><title>GitHat</title></head>`))
	assert.Equal(t, []string{"CodeHat"}, BrandMentions(`<head><title>CodeHat</title></head>`))
	assert.Equal(t, []string{"spoved"}, BrandMentions(`<head><title>spoved</title></head>`))
	assert.Equal(t, []string{"Spoved"}, BrandMentions(`<head><title>Spoved</title></head>`))
	assert.Equal(t, []string{"Gitdepo"}, BrandMentions(`<head><title>Gitdepo</title></head>`))
	assert.Equal(t, []string{"GITDEPO"}, BrandMentions(`<head><title>GITDEPO</title></head>`))
	assert.Equal(t, []string{"forgejo"}, BrandMentions(`<p>forgejo</p>`))
	assert.Equal(t, []string{"$ forgejo daemon"}, BrandMentions(`<pre><code>$ forgejo daemon</code></pre>`))
	assert.Equal(t, []string{"Forgejo"}, BrandMentions(`<input placeholder="Forgejo">`))
	assert.Equal(t, []string{"Forgejo forge"}, BrandMentions(`<meta property="og:description" content="Forgejo forge">`))
	assert.Equal(t, []string{"Forgejo"}, BrandMentions(`<a class="other" href="#">Forgejo</a>`))
}
