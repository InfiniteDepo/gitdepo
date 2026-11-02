// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lateSecrets are secrets of rules that run late, built from parts.
func lateSecrets() map[string]string {
	return map[string]string{
		"private-key":               "-----BEGIN RSA PRIVATE" + " KEY-----\n" + fake(64, b64) + "\n" + fake(64, b64) + "\n-----END RSA PRIVATE" + " KEY-----",
		"slack-token":               "xoxb-" + "1234567890" + "-" + fake(24, alnum),
		"stripe-live-key":           "sk_" + "live_" + fake(24, alnum),
		"generic-secret-assignment": `password = "` + fake(28, alnum) + `"`,
		"cacme":                     "acme_" + fake(32, alnum),
		"github-token":              "ghp_" + fake(36, alnum),
	}
}

// Decoys for the first rules of the order must not starve the later rules
// (red team round 6: two AWS rules took the whole budget).
func TestDecoysForTwoRulesDoNotStarveTheRest(t *testing.T) {
	d, err := NewDetector(append(BuiltinRules(), CustomRule("cacme", "n", `acme_([A-Za-z0-9]{32})`, []string{"acme"})))
	require.NoError(t, err)
	units := []string{
		"aws_secret=" + strings.Repeat("A", 40) + "\n",
		"AKIA" + strings.Repeat("A", 16) + " " + strings.Repeat("A", 40) + "\n",
	}
	for _, hdr := range []bool{false, true} {
		var sb strings.Builder
		if hdr {
			sb.WriteString(keywordLine + "acme\n")
		}
		for _, u := range units {
			sb.Write(repeatTo(u, 1<<20/slowdown))
			sb.WriteString("\n")
		}
		for _, s := range lateSecrets() {
			sb.WriteString(s + "\n")
		}
		fs, _ := d.Scan([]byte(sb.String()))
		for id := range lateSecrets() {
			assert.Positive(t, countRuleIn(fs, id), "%s (keyword line %v)", id, hdr)
		}
	}
}

// The same with a line of every keyword, 3 MiB of aws_secret decoys, and the
// secrets before and after them.
func TestKeywordLineAndAWSDecoysKeepLaterRules(t *testing.T) {
	d := allRulesDetector(t)
	secrets := "ghp_" + fake(36, alnum) + "\n" + "xoxb-1234567890-" + fake(24, alnum) + "\n" + "token = " + fake(40, hexa) + "\n"
	decoys := string(repeatTo("aws_secret = "+strings.Repeat("A", 40)+"\n", 3<<20/slowdown))
	for name, content := range map[string]string{
		"after":  keywordLine + decoys + "\n" + secrets,
		"before": keywordLine + secrets + "\n" + decoys,
	} {
		fs, _ := d.Scan([]byte(content))
		for _, id := range []string{"github-token", "slack-token", "forgejo-access-token"} {
			assert.Equal(t, 1, countRuleIn(fs, id), "%s: %s", name, id)
		}
	}
}

// Prose after a line with the keywords of the rules that have no literal
// prefix is cheap, and a token after it is found with complete=true. The time
// is compared with a scan of the prose alone (the best of three runs each), so
// a slow or busy machine slows both: a search per keyword and rule made it
// about 25 times the prose alone, sharing the gate's hits about twice.
func TestKeywordLineThenProseFindsTheToken(t *testing.T) {
	d := allRulesDetector(t)
	prose := repeatTo("The quick brown fox jumps over the lazy dog, and then it rests. ", 9<<20/slowdown)
	content := append([]byte(keywordLine), prose...)
	content = append(content, []byte("\nghp_"+fake(36, alnum)+"\n")...)
	best := func(b []byte) time.Duration {
		var least time.Duration
		for i := range 3 {
			start := time.Now()
			d.Scan(b)
			if took := time.Since(start); i == 0 || took < least {
				least = took
			}
		}
		return least
	}
	baseline, took := best(prose), best(content)
	t.Logf("prose alone %v, after the keyword line %v", baseline, took)
	assert.Less(t, took, 3*baseline+200*time.Millisecond*slowdown)
	fs, complete := d.Scan(content)
	assert.True(t, complete)
	assert.Equal(t, 1, countRuleIn(fs, "github-token"))
}

// Worst custom rules first, decoys for them, then a match of a later custom
// rule and a token.
func TestCustomRulesDoNotStarveALaterCustomRule(t *testing.T) {
	rules := append(BuiltinRules(), worstCustomRules()...)
	rules = append(rules, CustomRule("cacme", "n", `acme_([A-Za-z0-9]{32})`, []string{"acme"}))
	d, err := NewDetector(rules)
	require.NoError(t, err)
	content := keywordLine + "acme kw0 aba\n" + strings.Repeat("a", 4<<20/slowdown) + "\nacme_" + fake(32, alnum) + "\nghp_" + fake(36, alnum) + "\n"
	fs, _ := d.Scan([]byte(content))
	assert.Equal(t, 1, countRuleIn(fs, "cacme"))
	assert.Equal(t, 1, countRuleIn(fs, "github-token"))
}

// Rules that share a keyword share its hits: each still finds its own tokens,
// also when the scan stops keeping hits early.
func TestSharedKeywordFindsEveryRulesTokens(t *testing.T) {
	defer func(v int) { keptHitsBase = v }(keptHitsBase)
	rules := []Rule{
		{ID: "acme-anchored", Name: "n", Type: "acme", Keywords: []string{"acme_"}, Regex: `(acme_[a-z0-9]{24})`, SecretGroup: 1, Window: 32, Anchored: true},
		{ID: "acme-window", Name: "n", Type: "acme", Keywords: []string{"acme"}, Regex: `acme_key\s*=\s*"([A-Z0-9]{20})"`, SecretGroup: 1, Window: 64},
		{ID: "acme-window2", Name: "n", Type: "acme", Keywords: []string{"acme_", "other"}, Regex: `acme_id:([0-9]{12})\b`, SecretGroup: 1, Window: 64},
	}
	d, err := NewDetector(rules)
	require.NoError(t, err)
	var b strings.Builder
	for range 3 {
		b.WriteString("acme_" + fake(24, "abcdefghijklmnopqrstuvwxyz0123456789") + "\n")
		b.WriteString(`acme_key = "` + fake(20, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") + "\"\n")
		b.WriteString("acme_id:" + fake(12, "0123456789") + "\n" + strings.Repeat("acme ", 50) + "\n")
	}
	for _, base := range []int{1024, 0} {
		keptHitsBase = base
		fs, complete := d.Scan([]byte(b.String()))
		assert.True(t, complete)
		for _, r := range rules {
			assert.Equal(t, 3, countRuleIn(fs, r.ID), "%s, keptHitsBase %d", r.ID, base)
		}
	}
}
