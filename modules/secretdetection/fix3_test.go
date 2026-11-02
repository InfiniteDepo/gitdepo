// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func customDetector(t *testing.T, pattern string, keywords ...string) *Detector {
	t.Helper()
	d, err := NewDetector([]Rule{CustomRule("c", "n", pattern, keywords)})
	require.NoError(t, err)
	return d
}

func TestUnboundedRepeatsAreRefused(t *testing.T) {
	test := "acme_abcdefghij"
	for _, pattern := range []string{
		`acme_(?:[\s\S]*Q|[0-9x]{8})`, // the reviewers' patterns
		`acme(\w{8})(?:\w*Z)?`,
		`acme_[a-z]+`,
		`acme_[a-z]*`,
		`acme_[a-z]{8,}`,
		`acme_(?:ab)+[a-z]{8}`,
		`acme_(?:[a-z]{8,})?`,
	} {
		err := ValidateCustomRule("rule", pattern, test, []string{"acme_"})
		require.ErrorIs(t, err, ErrPatternTooComplex, pattern)
		assert.Equal(t, "pattern is too complex", err.Error())
	}
	// a counted repeat with an upper bound is fine
	require.NoError(t, ValidateCustomRule("rule", `acme_[a-z]{8,50}`, test, []string{"acme_"}))
}

func TestRejectedMatchesAreCappedForCustomRules(t *testing.T) {
	d := customDetector(t, `acme_([a-z]{8})`, "acme_")
	placeholders := strings.Repeat("acme_xxxxxxxx\n", MaxRejectedPerRule+10)
	fs, complete := d.Scan([]byte(placeholders + "T=acme_" + fake(8, "abcdefghijklmnopqrstuvwxyz")))
	assert.False(t, complete, "the rule stopped, so the scan is partial")
	assert.Empty(t, fs)
	// below the cap everything is found
	fs, complete = d.Scan([]byte(strings.Repeat("acme_xxxxxxxx\n", 100) + "T=acme_" + fake(8, "abcdefghijklmnopqrstuvwxyz")))
	assert.True(t, complete)
	assert.Len(t, fs, 1)
}

func TestCustomKeywordMustBeInTheMatchWhenScanning(t *testing.T) {
	pattern := `(?:zork|\t)([a-z]{8,20})` // the keyword is only in one branch
	require.NoError(t, ValidateCustomRule("rule", pattern, "zorkabcdefghij", []string{"zork"}))
	d := customDetector(t, pattern, "zork")
	word := fake(10, "abcdefghijklmnopqrstuvwxyz")
	assert.Empty(t, scanOf(d, []byte("if zork != nil {\n\treturn "+word+"\n}\n")), "a tab branch, zork only nearby")
	assert.Len(t, scanOf(d, []byte("x zork"+word)), 1)
	// also when the keyword is in an optional part
	d = customDetector(t, `(?:acme_)?([a-z]{8,20})`, "acme_")
	assert.Empty(t, scanOf(d, []byte("acme_ and "+word+"\n")))
}

func TestCustomWindowsAreNeverCut(t *testing.T) {
	// one merged window of 1.7 MiB with the secret at its far end: a cut
	// window used to hide it, or fingerprint a shortened secret
	dense := strings.Repeat("acme_ filler text goes here\n", 60000)
	secret := "acme_" + fake(12, alnum)
	d := customDetector(t, `acme_[A-Za-z0-9]{12}`, "acme_")
	d.MaxWork = 1 << 30 // the custom rules' default budget runs out on so dense a file, which is not tested here
	fs, complete := d.Scan([]byte(dense + secret + "\n"))
	assert.Len(t, fs, 1)
	assert.True(t, complete)
	assert.Equal(t, Fingerprint([]byte(secret)), fs[0].Fingerprint)
}

func TestBuiltInWindowedRulesHaveNoBudget(t *testing.T) {
	d := allRulesDetector(t)
	aws := strings.Repeat("aws region us-east-1 arn:aws:s3:::bucket/key\n", 50000)
	require.Greater(t, len(aws), 2<<20)
	fs, complete := d.Scan([]byte(aws + "aws_secret_access_key = " + fake(40, b64) + "\n"))
	assert.True(t, complete)
	assert.Equal(t, 1, countRuleIn(fs, "aws-secret-access-key"))

	azdo := strings.Repeat("azdo is the short name\n", 100000)
	require.Greater(t, len(azdo), 2<<20)
	pat := fake(76, alnum) + "AZDO" + fake(4, alnum)
	fs, complete = d.Scan([]byte(azdo + "pat = " + pat + "\n"))
	assert.True(t, complete)
	assert.Equal(t, 1, countRuleIn(fs, "azure-devops-pat"))
}

func countRuleIn(fs []Finding, id string) int {
	n := 0
	for _, f := range fs {
		if f.RuleID == id {
			n++
		}
	}
	return n
}

func utf16Bytes(bo binary.AppendByteOrder, s string, bom bool) []byte {
	var out []byte
	if bom {
		out = bo.AppendUint16(out, 0xFEFF)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		out = bo.AppendUint16(out, u)
	}
	return out
}

func TestUTF16IsDecodedLeniently(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	body := "# env\r\nGITHUB_TOKEN=" + token + "\r\n"
	le, be := binary.LittleEndian, binary.BigEndian
	for name, content := range map[string][]byte{
		"odd length LE":      append(utf16Bytes(le, body, true), 'x'),
		"odd length BE":      append(utf16Bytes(be, body, true), 'x'),
		"lone high at end":   append(utf16Bytes(le, body, true), 0x00, 0xd8),
		"lone low in middle": append(append(utf16Bytes(le, "a\r\n", true), 0x00, 0xdc), utf16Bytes(le, body, false)...),
		"swapped pair":       append(append(utf16Bytes(le, "a\r\n", true), 0x00, 0xdc, 0x00, 0xd8), utf16Bytes(le, body, false)...),
		"no BOM LE":          utf16Bytes(le, body, false),
		"no BOM BE":          utf16Bytes(be, body, false),
	} {
		fs, complete := d.Scan(content)
		assert.Len(t, fs, 1, name)
		assert.True(t, complete, name)
	}
	// CJK text has no NUL byte: with a BOM it is decoded, and a secret after it is found
	cjk := strings.Repeat("日本語の設定ファイル。", 400)
	fs, complete := d.Scan(utf16Bytes(le, cjk+"\r\nGITHUB_TOKEN="+token+"\r\n", true))
	assert.Len(t, fs, 1)
	assert.True(t, complete)
	// UTF-32 and other NUL-heavy data stays binary
	var u32 []byte
	for _, r := range body {
		u32 = le.AppendUint32(u32, uint32(r))
	}
	fs, complete = d.Scan(u32)
	assert.Empty(t, fs)
	assert.True(t, complete)
	// nothing could be read from a body that is there: not "complete"
	fs, complete = d.Scan([]byte{0xff, 0xfe, 0x00})
	assert.Empty(t, fs)
	assert.False(t, complete)
}

func TestSentenceAndSuffixBoundaries(t *testing.T) {
	d := allRulesDetector(t)
	azure := "abc" + "8Q~" + fake(34, alnum)
	assert.Equal(t, 1, countRule(d, "The secret is "+azure+".", "azure-ad-client-secret"), "full stop after the secret")
	assert.Zero(t, countRule(d, "The secret is "+azure+"x", "azure-ad-client-secret"), "glued to a word")
	key := "AIza" + fake(35, alnum)
	assert.Equal(t, 1, countRule(d, "key "+key+"-backup", "gcp-api-key"), "hyphen after the key")
	assert.Zero(t, countRule(d, "key "+key+"q", "gcp-api-key"))
}

// TestHostileAzureDevOpsBlobIsBounded: three shapes of a 10 MiB blob made for
// azure-devops-pat (lowercase hits, capitals without the 76 bytes before, and
// capitals that pass the check every time) all stay fast, with every default
// rule on. The target is under 1 s; the bound is generous for slow machines.
func TestHostileAzureDevOpsBlobIsBounded(t *testing.T) {
	d := defaultRulesDetector(t)
	const size = 10 << 20
	for name, blob := range map[string][]byte{
		"lowercase": []byte(strings.Repeat("azdo "+strings.Repeat("a", 120)+"\n", size/126+1)[:size]),
		"no prefix": []byte(strings.Repeat("AZDO "+strings.Repeat("a", 120)+"\n", size/126+1)[:size]),
		"every hit": azdoHostile(size),
	} {
		start := time.Now()
		_, complete := d.Scan(blob)
		assert.True(t, complete, name)
		assert.Less(t, time.Since(start), 5*time.Second*slowdown, name)
	}
}

// TestDefaultRulesScanMinifiedJSFast: a keyword on every few bytes (token,
// key, akia) costs a few bytes per hit. Measured about 50 MB/s; the bound is
// 5 MB/s (a tenth), so a slow machine passes and a pass over everything per
// rule does not.
func TestDefaultRulesScanMinifiedJSFast(t *testing.T) {
	d := defaultRulesDetector(t)
	js := minifiedJS(4 << 20)
	start := time.Now()
	_, complete := d.Scan(js)
	assert.True(t, complete)
	assert.Less(t, time.Since(start), time.Duration(float64(len(js))/5e6*float64(time.Second))*time.Duration(slowdown))
}
