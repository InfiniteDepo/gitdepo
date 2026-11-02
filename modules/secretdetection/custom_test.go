// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ValidateStoredRule is ValidateCustomRule without a test string: it refuses the same rules, for the same reasons.
func TestValidateStoredRule(t *testing.T) {
	kw := []string{"acme-key"}
	pattern := `acme-key-[a-z0-9]{20}`
	require.NoError(t, ValidateStoredRule("rule", pattern, kw))
	for _, c := range []struct {
		name, pattern string
		keywords      []string
		want          error
	}{
		{"", pattern, kw, ErrCustomNameInvalid},
		{strings.Repeat("n", MaxCustomNameLen+1), pattern, kw, ErrCustomNameInvalid},
		{"r", strings.Repeat("a", MaxCustomPatternLen+1), kw, ErrPatternTooLong},
		{"r", `acme-key-(`, kw, ErrPatternInvalid},
		{"r", `(acme-key-[a-z0-9]+)+`, kw, ErrPatternTooComplex},
		{"r", `acme-key-[a-z0-9]+`, kw, ErrPatternTooComplex},
		{"r", `a{0}`, kw, ErrPatternMatchesEmpty},
		{"r", pattern, nil, ErrKeywordMissing},
		{"r", pattern, []string{"ab"}, ErrKeywordMissing},
		{"r", pattern, []string{strings.Repeat("k", MaxCustomKeywordLen+1)}, ErrKeywordMissing},
		{"r", pattern, []string{"aaa", "bbb", "ccc", "ddd", "eee", "fff"}, ErrKeywordMissing},
		{"r", `[a-z]{8,12}`, kw, ErrPatternMatchesTooMuch},
		{"r", pattern, []string{"acme-key", "the"}, ErrKeywordTooCommon},
		{"r", pattern, []string{"HTTPS"}, ErrKeywordTooCommon},
	} {
		err := ValidateStoredRule(c.name, c.pattern, c.keywords)
		require.ErrorIs(t, err, c.want, "%q %q", c.name, c.pattern)
		assert.NotEqual(t, "other", RefusalCode(err), "every refusal has a code")
	}
	assert.Equal(t, "invalid", RefusalCode(fmt.Errorf("%w: quoted text", ErrPatternInvalid)))
	assert.Equal(t, "other", RefusalCode(errors.New("x")))
}

// A pattern or name that holds a literal secret would be stored and audited as it is.
func TestCustomRuleHoldingASecretIsRefused(t *testing.T) {
	leaked := "ghp_" + fake(36, alnum)
	pattern := `acme-key-[a-z0-9]{20}`
	test := "K=acme-" + "key-" + strings.Repeat("a1", 10)
	require.NoError(t, ValidateCustomRule("rule", pattern, test, []string{"acme-key"}))
	require.ErrorIs(t, ValidateCustomRule("rule", pattern+"|"+regexp.QuoteMeta(leaked), test, []string{"acme-key"}), ErrPatternHoldsSecret)
	require.ErrorIs(t, ValidateCustomRule("leak "+leaked, pattern, test, []string{"acme-key"}), ErrPatternHoldsSecret)
	withToken := pattern + ` (ghp_[A-Za-z0-9]{36})`
	require.NoError(t, ValidateCustomRule("rule", withToken, test+" "+leaked, []string{"acme-key"}))
	require.ErrorIs(t, ValidateCustomRule("rule", withToken, test+" "+leaked, []string{"acme-key", leaked}), ErrPatternHoldsSecret, "a keyword")

	// the refusal names the field and the format, never the token
	for field, err := range map[string]error{
		"name":     ValidateCustomRule("leak "+leaked, pattern, test, []string{"acme-key"}),
		"pattern":  ValidateCustomRule("rule", pattern+"|"+regexp.QuoteMeta(leaked), test, []string{"acme-key"}),
		"keywords": ValidateCustomRule("rule", withToken, test+" "+leaked, []string{"acme-key", leaked}),
	} {
		var holds *HoldsSecretError
		require.ErrorAs(t, err, &holds, field)
		assert.Equal(t, field, holds.Field)
		assert.Equal(t, "GitHub token", holds.Format)
		assert.NotContains(t, err.Error(), leaked)
	}
}

// A pattern that doesn't parse keeps the parser's error, so a page can say what is wrong in plain words; only the
// keyword-in-match refusal is ErrKeywordNotInMatch.
func TestCustomRuleRefusalDetails(t *testing.T) {
	var serr *syntax.Error
	require.ErrorAs(t, ValidateStoredRule("r", `acme-(key`, []string{"acme"}), &serr)
	assert.Equal(t, syntax.ErrMissingParen, serr.Code)

	test := "K=acme-" + "key-" + strings.Repeat("a1", 10)
	err := ValidateCustomRule("r", `acme-key-[a-z0-9]{20}`, test, []string{"zork"})
	require.ErrorIs(t, err, ErrKeywordNotInMatch)
	require.ErrorIs(t, err, ErrKeywordMissing)
	assert.Equal(t, "keywords", RefusalCode(err))
	for _, keywords := range [][]string{nil, {"ac"}, {"a", "b", "c", "d", "e", "f"}} {
		err := ValidateCustomRule("r", `acme-key-[a-z0-9]{20}`, test, keywords)
		require.ErrorIs(t, err, ErrKeywordMissing)
		require.NotErrorIs(t, err, ErrKeywordNotInMatch, "%q", keywords)
	}
}

// The custom rules have a budget of their own: however much work they need, a built-in rule gets its whole budget.
func TestCustomRulesNeverStarveBuiltins(t *testing.T) {
	builtin, ok := RuleByID("github-token")
	require.True(t, ok)
	secret := "ghp_" + fake(36, alnum)
	// placeholder tokens make the built-in rule work (one regex call each); the custom rules' keyword is everywhere
	content := append(repeatTo("acme_ ghp_"+strings.Repeat("x", 36)+" zz\n", 512<<10), []byte(" "+secret+"\n")...)
	alone, err := NewDetector([]Rule{builtin})
	require.NoError(t, err)
	found := func(d *Detector) bool { fs, _ := d.Scan(content); return len(fs) == 1 }
	work := 1 << 10 // the least budget (by powers of 2) with which the built-in rule alone reaches the secret
	for alone.MaxWork = work; !found(alone); alone.MaxWork = work {
		work *= 2
	}
	require.Greater(t, work, 1<<12, "the decoys cost the built-in rule work")
	rules := []Rule{builtin}
	for i := range MaxCustomRules {
		rules = append(rules, CustomRule(fmt.Sprintf("c%d", i), "n", `acme_[^@]{0,60}@`, []string{"acme_"}))
	}
	mixed, err := NewDetector(rules)
	require.NoError(t, err)
	mixed.MaxWork = work
	fs, complete := mixed.Scan(content)
	assert.False(t, complete, "the custom rules ran out of their budget")
	require.Len(t, fs, 1)
	assert.Equal(t, "github-token", fs[0].RuleID)
}
