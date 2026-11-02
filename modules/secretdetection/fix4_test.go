// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostileUnits are the worst inputs of the red-team and review reports: text
// made of one keyword shape, repeated to the size of the blob.
func hostileUnits() map[string]string {
	return map[string]string{
		"tokentoken":        "token",
		"keykey":            "key",
		"awsaws":            "aws",
		"aws_secret_":       "aws_secret_",
		"aws gap units":     strings.Repeat("aws", 10) + "secret" + strings.Repeat("aws", 10) + "=" + strings.Repeat(" ", 150) + "x\n",
		"aws ws-run":        "aws_secret_access_key=" + strings.Repeat(" ", 200),
		"akia ids":          "AKIA" + strings.Repeat("A", 16) + " ",
		"akia ids + b64":    "AKIA" + strings.Repeat("A", 16) + " " + strings.Repeat("ab+/", 5) + " ",
		"token ws":          "token=" + strings.Repeat(" ", 90),
		"token word run":    "token_" + strings.Repeat("a", 14),
		"key ws":            "key = \"" + strings.Repeat("a", 19) + " ",
		"password quote":    "password='" + strings.Repeat("a", 99),
		"AZDO dense":        strings.Repeat("a", 76) + "AZDO" + "aaaa ",
		"azdo lower":        "azdo",
		"AZDO glued":        strings.Repeat("aAZDO", 40),
		"secret assignment": "secret = '" + strings.Repeat("ab", 8) + "' ",
	}
}

func repeatTo(unit string, size int) []byte {
	return []byte(strings.Repeat(unit, size/len(unit)+1)[:size])
}

// worstCustomRules are accepted custom patterns that cost the most per byte of
// their own keyword.
func worstCustomRules() []Rule {
	var rules []Rule
	for i, p := range []struct{ pattern, keyword string }{
		{`(aaa[^@]{0,140})@`, "aaa"},
		{`(?i)(aba[a-z]{0,40}[a-z]{0,40}[a-z]{0,40})@`, "aba"},
		{`(kw0\pL{0,30}\pN{0,30}[^\n]{0,60})Z`, "kw0"},
		{`(aaa.{0,140})@`, "aaa"},
		{`([^@]{0,100}aaa[^@]{0,100})@`, "aaa"},
		{`(?i)([\pL\pN]{0,40}aaa[\pL\pN]{0,40})@`, "aaa"},
	} {
		rules = append(rules, CustomRule(fmt.Sprintf("c%d", i), "n", p.pattern, []string{p.keyword}))
	}
	for len(rules) < 20 {
		r := rules[len(rules)%6]
		r.ID = fmt.Sprintf("c%d", len(rules))
		rules = append(rules, r)
	}
	return rules
}

// TestHostileInputsAreBounded: every hostile blob of 10 MiB finishes within a
// bound (the target is 1 s, the bound 3 s: about 0.9 s here at most) or says
// it did not finish. Reports each time with -v.
func TestHostileInputsAreBounded(t *testing.T) {
	d := allRulesDetector(t)
	// The work budget is not time: under -race the same work takes 10 times
	// longer, so the budget (and the blob) are cut to a tenth there.
	size := 2 << 20 / slowdown
	d.MaxWork = max(MinMaxWork, WorkPerByte*size) / slowdown
	bound := 3 * time.Second * slowdown
	for name, unit := range hostileUnits() {
		in := repeatTo(unit, size)
		start := time.Now()
		_, complete := d.Scan(in)
		el := time.Since(start)
		t.Logf("%-18s %6.2fs complete=%v", name, el.Seconds(), complete)
		assert.Less(t, el, bound, name)
	}
	custom, err := NewDetector(worstCustomRules())
	require.NoError(t, err)
	custom.MaxWork = d.MaxWork
	for _, unit := range []string{"aaa", "aba", "kw0", "aaa b"} {
		in := repeatTo(unit, size)
		start := time.Now()
		_, complete := custom.Scan(in)
		el := time.Since(start)
		t.Logf("20 custom rules on %-6s %6.2fs complete=%v", unit, el.Seconds(), complete)
		assert.Less(t, el, bound, unit)
	}
}

func TestMaxWorkStopsAScan(t *testing.T) {
	d := allRulesDetector(t)
	in := repeatTo("AKIA"+strings.Repeat("A", 16)+" ", 4<<20)
	_, complete := d.Scan(in)
	assert.False(t, complete, "the default budget is spent by 200,000 rejected matches")
	d.MaxWork = 1 << 40
	start := time.Now()
	_, complete = d.Scan(repeatTo("a quiet text without keywords\n", 4<<20))
	assert.True(t, complete)
	assert.Less(t, time.Since(start), 3*time.Second*slowdown)
	d.MaxWork = 1 << 10
	_, complete = d.Scan(repeatTo("token = 'x'\n", 1<<20))
	assert.False(t, complete, "a tiny budget is spent at once")
}

func TestCustomRuleCapAndWindow(t *testing.T) {
	rule := CustomRule("c", "n", `acme_[a-z]{32}`, []string{"acme_"})
	assert.Equal(t, 5+32, rule.Window, "the window is the longest match")
	assert.Equal(t, 5+4*32, CustomRule("c", "n", `acme_[a-z\x{e9}]{32}`, []string{"acme_"}).Window, "non-ASCII classes count 4 bytes")
	var rules []Rule
	for i := range MaxCustomRules {
		rule.ID = fmt.Sprintf("c%d", i)
		rules = append(rules, rule)
	}
	_, err := NewDetector(rules)
	require.NoError(t, err)
	rule.ID = "one-more"
	_, err = NewDetector(append(rules, rule))
	require.Error(t, err)
}

func TestPaddedAssignmentsAreFound(t *testing.T) {
	d := allRulesDetector(t)
	hex := fake(40, hexa)
	aws := fake(40, b64)
	assert.Equal(t, 1, countRule(d, "token = "+strings.Repeat(" ", 80)+hex, "forgejo-access-token"), "80 spaces")
	assert.Equal(t, 1, countRule(d, "aws_secret_access_key = "+strings.Repeat(" ", 200)+aws, "aws-secret-access-key"), "200 spaces")
	assert.Equal(t, 1, countRule(d, "aws_secret_access_key:\n"+strings.Repeat(" ", 200)+aws, "aws-secret-access-key"), "newline and deep indent")
	assert.Equal(t, 1, countRule(d, "password = "+strings.Repeat(" ", 250)+"'"+fake(24, alnum)+"'", "generic-secret-assignment"), "250 spaces")
}

func TestAWSKeyIDAfterAWordByteIsRefused(t *testing.T) {
	d := allRulesDetector(t)
	id := "AKIA" + fake(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	secret := fake(40, b64)
	assert.Equal(t, 1, countRule(d, "id "+id+" "+secret, "aws-secret-access-key-near-id"))
	assert.Zero(t, countRule(d, "idx"+id+" "+secret, "aws-secret-access-key-near-id"), "glued to a word")
	assert.Zero(t, countRule(d, "id "+id+"x "+secret, "aws-secret-access-key-near-id"), "glued after")
}
