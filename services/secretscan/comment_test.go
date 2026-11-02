// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretscan

import (
	"strings"
	"testing"

	"forgejo.org/modules/secretdetection"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// the work of the comment check is bounded by a count of candidates and bytes, not by the time it takes
func TestCommentCandidatesBudget(t *testing.T) {
	for _, comment := range []string{
		strings.Repeat("a.=", 333),
		strings.Repeat("ab.=", 250),
		strings.Repeat("aaaaaaaaaaaaaaa.b=", 55),
		strings.Repeat("a.", 500),
		strings.Repeat("a/", 500),
		strings.Repeat("a/", 50) + strings.Repeat("A=", 400) + strings.Repeat("/a", 50),
	} {
		c := newCommentCandidates()
		err := c.addComment(comment)
		if err != nil {
			require.ErrorIs(t, err, ErrCommentTooCostly, comment[:8])
		}
		assert.LessOrEqual(t, c.count, maxCandidates+1, comment[:8])
		assert.LessOrEqual(t, c.bytes, maxCandidateBytes+maxCandidateLen, comment[:8])
		assert.LessOrEqual(t, len(c.hashes), c.count, comment[:8])
	}
	// many different candidates run out of the budget: refused
	var parts strings.Builder
	for i := range 250 {
		parts.WriteString(string([]byte{'a' + byte(i%26), 'a' + byte(i/26%26), 'a' + byte(i/676), '.'}))
	}
	c := newCommentCandidates()
	require.ErrorIs(t, c.addComment(parts.String()), ErrCommentTooCostly)
	// a run with more delimiters than positions are tried is refused, never cut (its middle could be the secret)
	c = newCommentCandidates()
	far := strings.Repeat("/", 51) + strings.Repeat("a", 300) + "/" + strings.Repeat("b", 40) + "/" + strings.Repeat("a", 300) + strings.Repeat("/", 51)
	require.ErrorIs(t, c.addComment(far), ErrCommentTooCostly)

	// the budget is shared by the texts of a comment, and a repeated candidate is counted once
	c = newCommentCandidates()
	require.NoError(t, c.addComment("plain words and a token-like-thing-of-some-length"))
	n := c.count
	assert.Positive(t, n)
	require.NoError(t, c.addComment("plain words and a token-like-thing-of-some-length"))
	assert.Equal(t, n, c.count, "the same candidates again cost nothing")
	require.NoError(t, c.addComment("another-token-like-thing-of-some-length"))
	assert.Greater(t, c.count, n, "new ones add to the same count")

	// realistic comments with links are accepted
	for _, comment := range []string{
		"see https://git.example.com/org/project/-/blob/main/docs/security/rotation.md#L12-L40 and " +
			"https://git.example.com/org/project/-/blob/main/src/service/auth/token_store.go#L5 and " +
			"https://git.example.com/org/project/-/blob/main/src/service/auth/token_store_test.go and " +
			"https://git.example.com/org/project/-/blob/main/config/prod/secrets.yaml and " +
			"https://git.example.com/org/project/-/blob/main/config/dev/settings.toml",
		"fixed in https://ci.example.com/job/build-and-test/1234/artifact/report/index.html, docs: https://docs.example.com/guide/security/rotating-credentials/overview.html",
	} {
		c = newCommentCandidates()
		require.NoError(t, c.addComment(comment), comment)
	}

	// a plain comment that holds a secret is still refused by the detector, one that holds a fingerprinted one is found
	secret := "ghp" + "_" + "Ab1Cd2Ef3Gh4" + "Ij5Kl6Mn7Op8" + "Qr9St0Uv1Wx2"
	require.ErrorIs(t, newCommentCandidates().addComment("it was "+secret), ErrCommentSecret)
	bare := "wJalrXUtn" + "FEMI/K7MDENG/" + "bPxRfiCY" + "Zq3vT8kLm1"
	c = newCommentCandidates()
	require.NoError(t, c.addComment("old key: **"+bare+"**"))
	assert.Contains(t, c.hashes, secretdetection.Fingerprint([]byte(bare)))

	// the value joined to other text with _ + = . / - # :
	for _, form := range []string{bare + "_old", "tok_" + bare, bare + "+1", bare + "==", "a=" + bare + "=b", "/srv/" + bare + "_bak/x", "x:" + bare + "#y"} {
		c = newCommentCandidates()
		require.NoError(t, c.addComment(form), form)
		assert.Contains(t, c.hashes, secretdetection.Fingerprint([]byte(bare)), form)
	}
}
