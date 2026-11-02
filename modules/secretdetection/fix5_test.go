// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBOMWithoutNULScansBothForms(t *testing.T) {
	le := binary.LittleEndian
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	cjk := strings.Repeat("日本語の設定ファイル。", 400)
	// decoded and raw: the UTF-16 CJK file gives one finding
	fs, complete := d.Scan(utf16Bytes(le, cjk+"\r\nGITHUB_TOKEN="+token+"\r\n", true))
	assert.Len(t, fs, 1)
	assert.True(t, complete)
	// bytes that are no UTF-16 are scanned as bytes, once
	fs, complete = d.Scan([]byte("\xff\xfe  GITHUB_TOKEN=" + token))
	assert.Len(t, fs, 1)
	assert.True(t, complete)
}

func TestWindowIsBelowTheChunk(t *testing.T) {
	_, err := NewDetector([]Rule{{ID: "w", Regex: `abc[0-9]{4}`, Keywords: []string{"abc"}, Window: workChunk}})
	require.Error(t, err)
	_, err = NewDetector([]Rule{{ID: "w", Regex: `abc[0-9]{4}`, Keywords: []string{"abc"}, Window: workChunk - 1}})
	require.NoError(t, err)
	for _, r := range worstCustomRules() {
		assert.Less(t, r.Window, workChunk)
	}
	// a pattern that would need a window of 64 KiB or more falls back to the default
	big := CustomRule("c", "n", `acme_[a-z]{0,100}`+strings.Repeat(`[a-z]{0,100}`, 3), []string{"acme_"})
	assert.Less(t, big.Window, workChunk)
}

func TestACustomRuleDoesNotStarveTheOthers(t *testing.T) {
	custom := worstCustomRules()[0]
	rules := append([]Rule{custom}, BuiltinRules()...) // custom first: NewDetector moves it last
	d, err := NewDetector(rules)
	require.NoError(t, err)
	token := "ghp_" + fake(36, alnum)
	aws := fake(40, b64)
	in := strings.Repeat("aaa", 100000) + "\n" + strings.Repeat("AKIAIOSFODNN7EXAMPLE\n", 5<<20/21) +
		"T=" + token + "\naws_secret_access_key = " + aws + "\n"
	fs, complete := d.Scan([]byte(in))
	assert.False(t, complete, "the rules that ran out of their share are reported")
	assert.Equal(t, 1, countRuleIn(fs, "github-token"))
	assert.Equal(t, 1, countRuleIn(fs, "aws-secret-access-key"))
}

func TestCheapDecoysDoNotBurnTheBudget(t *testing.T) {
	d := defaultRulesDetector(t)
	hex := fake(40, hexa)
	decoys := strings.Repeat("token="+strings.Repeat("0", 40)+"\n", 1536<<10/47)
	fs, complete := d.Scan([]byte(decoys + "token = " + hex + "\n"))
	assert.True(t, complete)
	assert.Equal(t, 1, countRuleIn(fs, "forgejo-access-token"))
}

func TestEscapedQuoteJSON(t *testing.T) {
	d := allRulesDetector(t)
	assert.Equal(t, 1, countRule(d, `{\"token\":\"`+fake(40, hexa)+`\"}`, "forgejo-access-token"))
	assert.Equal(t, 1, countRule(d, `{\"aws_secret_access_key\":\"`+fake(40, b64)+`\"}`, "aws-secret-access-key"))
	assert.Equal(t, 1, countRule(d, `{\"password\":\"`+fake(32, alnum)+`\"}`, "generic-secret-assignment"))
	// the plain forms still work, and a quote closed by an escape is not part of the secret
	assert.Equal(t, 1, countRule(d, `password = "`+fake(32, alnum)+`"`, "generic-secret-assignment"))
}

// The hit check refuses what the aws-secret-access-key pattern would accept: a
// "=" as the first of 40 bytes after blanks. Pinned so that it stays refused.
func TestAWSSecretAfterBlankAndEqualsIsRefused(t *testing.T) {
	d := allRulesDetector(t)
	assert.Zero(t, countRule(d, "aws_secret_access_key ="+fake(39, b64), "aws-secret-access-key"))
	assert.Equal(t, 1, countRule(d, "aws_secret_access_key = "+fake(40, b64), "aws-secret-access-key"))
}

func TestCustomMarkIsNotTheType(t *testing.T) {
	var rules []Rule
	for range MaxCustomRules + 1 {
		rules = append(rules, Rule{ID: "x", Type: "custom", Regex: `abc[0-9]{4}`})
	}
	_, err := NewDetector(rules)
	require.NoError(t, err, "only CustomRule makes a custom rule")
}
