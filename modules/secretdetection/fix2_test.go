// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"forgejo.org/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomRuleShapes(t *testing.T) {
	// The worst patterns of the reviews: slow after a rare keyword, or on bytes
	// the corpus lacks. Every one is refused by its shape.
	r8 := func(open string) string { return "(" + open + strings.Repeat("[^@]{0,100}", 8) + ")@QZKW" }
	for name, tt := range map[string]struct {
		pattern, test string
		keywords      []string
	}{
		"nested after keyword":     {`acme(?:[\w-]{0,9}){0,100}Q`, "acmeabcdefghQ", []string{"acme"}},
		"nested letters":           {`acme(?:\pL{0,9}){0,100}Z`, "acmeabcdefghZ", []string{"acme"}},
		"keyword and nine repeats": {"acme_" + strings.Repeat(`[\s\S]{0,100}`, 9) + "Z", "acme_secretvalue123 Z", []string{"acme_"}},
		"keyword and negations":    {"acme_" + strings.Repeat(`[^Z]{0,100}`, 9) + "Z", "acme_secretvalue123Z", []string{"acme_"}},
		"html":                     {r8("<"), "<abcdefghij@QZKW", []string{"qzkw", "<ab"}},
		"quote":                    {r8("'"), "'abcdefghij@QZKW", []string{"qzkw", "'ab"}},
		"hash":                     {r8("#"), "#abcdefghij@QZKW", []string{"qzkw", "#ab"}},
		"star in plus":             {`acme_(?:[a-z]+x)+Z`, "acme_abxabxabxabxZ", []string{"acme_"}},
		"star in star":             {`acme_(?:[a-z]*x)*Z`, "acme_abxabxabxabxZ", []string{"acme_"}},
		"nested angle":             {`(<(?:[^@]{0,100}){0,9})@QZKW`, "<abcdefghij@QZKW", []string{"qzkw", "<ab"}},
		"sum of repeats":           {`acme_[a-z]{0,100}[0-9]{0,100}[A-Z]{0,100}`, "acme_abcdefgh", []string{"acme_"}},
		"big program":              {"acme_" + strings.Repeat("(?:[a-c]x|[d-f]y|gz)", 40) + "=[a-z0-9]{8}", "acme_ax=abcdefgh", []string{"acme_"}},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, ValidateCustomRule("rule", tt.pattern, tt.test, tt.keywords), ErrPatternTooComplex)
		})
	}

	acme := "acme_[A-Za-z0-9]{30}"
	test := "acme_" + fake(30, alnum)
	require.NoError(t, ValidateCustomRule("r", acme, test, []string{"acme_"}))
	require.ErrorIs(t, ValidateCustomRule("r", acme, test, []string{"acme_", "zork"}), ErrKeywordMissing, "every keyword must be in the match")
	require.ErrorIs(t, ValidateCustomRule("r", acme, test, []string{"acme_", "the"}), ErrKeywordTooCommon, "a keyword all over ordinary files")
	require.ErrorIs(t, ValidateCustomRule("r", acme, test, []string{"acme_", "acm", "cme", "me_", "e_" + "a", "_ab"}), ErrKeywordMissing, "more than five")
	require.ErrorIs(t, ValidateCustomRule("r", acme, test, []string{strings.Repeat("a", 65)}), ErrKeywordMissing)
	require.NoError(t, ValidateCustomRule("r", acme, test, []string{"acme_", "acm", "cme", "me_", "e_" + test[5:6]}))
	// nesting of a quest is fine, repeats of a group that holds no repeat too
	require.NoError(t, ValidateCustomRule("r", `acme_(?:ab)?(?:cd){1,4}([a-z0-9]{12})`, "acme_abcdcd0123456789", []string{"acme_"}))
}

// TestAcceptedCustomRulesAreBounded generates patterns, and for every one that
// validation's shape rules accept checks the scan of 2 MiB of keyword-dense
// text: the windows cap (1 MiB per rule) keeps it under a second.
func TestAcceptedCustomRulesAreBounded(t *testing.T) {
	atoms := []string{`[a-z]`, `\w`, `[^@]`, `.`, `\pL`, `\s`, `[\s\S]`, `[^Z]`, `[A-Za-z0-9_-]`, `\S`, `[^"']`}
	var x uint32 = 7
	next := func(n int) int {
		x = x*1664525 + 1013904223
		return int(x>>8) % n
	}
	dense := strings.Repeat("acme_ the quick brown fox <div class=\"x\">@QZ #! 0123456789 _-'\n", 2<<20/60+1)[:2<<20]
	accepted, worst := 0, time.Duration(0)
	for range 300 {
		var p strings.Builder
		p.WriteString("acme_")
		for range 1 + next(6) {
			atom := atoms[next(len(atoms))]
			switch next(4) {
			case 0:
				p.WriteString(fmt.Sprintf("%s{%d,%d}", atom, next(5), 5+next(100)))
			case 1:
				p.WriteString(atom + "+")
			case 2:
				p.WriteString(atom + "*")
			default:
				p.WriteString(atom)
			}
		}
		p.WriteString("Z")
		if checkComplexity(p.String()) != nil {
			continue
		}
		accepted++
		d, err := NewDetector([]Rule{CustomRule("c", "n", p.String(), []string{"acme_"})})
		require.NoError(t, err)
		start := time.Now()
		_, _ = d.Scan([]byte(dense))
		elapsed := time.Since(start)
		worst = max(worst, elapsed)
		assert.Less(t, elapsed, 3*time.Second*time.Duration(slowdown), "pattern %q", p.String())
	}
	t.Logf("accepted %d of 300 generated patterns, slowest scan of 2 MiB: %v", accepted, worst)
	assert.Greater(t, accepted, 20)
}

func TestNoAttemptCap(t *testing.T) {
	d := allRulesDetector(t)
	keyID := "AKIA" + fake(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	real := "ghp_" + fake(36, alnum)
	for name, content := range map[string]string{
		"aws example": strings.Repeat("AKIAIOSFODNN7EXAMPLE\n", 20000) + keyID,
		"x tokens":    strings.Repeat("ghp_"+strings.Repeat("x", 36)+"\n", 20000) + "T=" + real,
		"glued":       strings.Repeat("a"+real+"\n", 20000) + "T=" + real, // boundary refused
	} {
		fs, _ := d.Scan([]byte(content))
		assert.NotEmpty(t, fs, name)
	}
}

func TestScanReportsWhenItIsPartial(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	complete := func(content []byte) bool {
		_, c := d.Scan(content)
		return c
	}
	assert.True(t, complete([]byte(token)))
	assert.True(t, complete(nil))
	assert.True(t, complete([]byte("\x00"+token)), "binary is skipped on purpose")
	assert.True(t, complete([]byte("version https://git-lfs.github.com/spec/v1\noid sha256:"+fake(64, hexa)+"\nsize 1\n")))

	d.MaxContentSize = 100
	assert.True(t, complete([]byte(strings.Repeat("a", 100))))
	fs, c := d.Scan([]byte(strings.Repeat("a", 90) + " " + token))
	assert.False(t, c, "cut at MaxContentSize")
	assert.Empty(t, fs)
	d.MaxContentSize = 0
	assert.False(t, complete([]byte(strings.Repeat("a", DefaultMaxContentSize)+" "+token)), "default size")

	// a rule that reached its cap may have more findings
	d.MaxMatchesPerRule = 2
	_, c = d.Scan([]byte(strings.Repeat(token+"\n", 5)))
	assert.False(t, c)
	d.MaxMatchesPerRule = 0

	// a custom rule over the MaxWork budget
	cd, err := NewDetector([]Rule{CustomRule("c", "n", `acme_([a-z0-9]{12})`, []string{"acme_"})})
	require.NoError(t, err)
	small, c := cd.Scan([]byte("x acme_abcdef012345 y"))
	assert.True(t, c)
	assert.Len(t, small, 1)
	dense := []byte(strings.Repeat("acme_ some text here and there, "+strings.Repeat("0", 100)+"\n", 40000)) // 5 MiB
	cd.MaxWork = 1 << 20
	_, c = cd.Scan(dense)
	assert.False(t, c)

	// UTF-16 over the limit
	d.MaxContentSize = 100
	assert.False(t, complete(append([]byte{0xFF, 0xFE}, utf16LE(strings.Repeat("a", 500))...)))
}

func utf16LE(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestPrivateKeyEscapesNeverDropAKey(t *testing.T) {
	d := defaultRulesDetector(t)
	body := make([]string, 25)
	for i := range body {
		body[i] = fake(64, b64)[i%7:] + fake(i%7, b64) // every line has a / or +
	}
	pem := "-----BEGIN PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END PRIVATE KEY-----\n"
	jsonStr := func(s string) string {
		b, err := json.Marshal(s)
		require.NoError(t, err)
		return string(b)
	}
	php := strings.ReplaceAll(jsonStr(pem), "/", `\/`)
	encrypted := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----\n"
	want := fpOf(scanOf(d, []byte(pem))[0])
	forms := map[string]string{
		"json":              jsonStr(pem),
		"php":               php,
		"json in json":      jsonStr(jsonStr(pem)),
		"shell":             strings.ReplaceAll(pem, "\n", `\\n`),
		"tabs":              `"-----BEGIN PRIVATE KEY-----\n\t` + strings.Join(body, `\n\t`) + `\n-----END PRIVATE KEY-----"`,
		"unicode escapes":   strings.ReplaceAll(jsonStr(pem), "+", `+`),
		"gcp php":           strings.ReplaceAll(jsonStr(`{"type": "service_account", "private_key": `+jsonStr(pem)+"}"), "/", `\/`),
		"triple":            jsonStr(jsonStr(jsonStr(pem))),
		"encrypted in json": jsonStr(encrypted),
	}
	for name, content := range forms {
		t.Run(name, func(t *testing.T) {
			fs := scanOf(d, []byte(content))
			var keys []Finding
			for _, f := range fs {
				if f.RuleID == "private-key" || f.RuleID == "gcp-service-account-key" {
					keys = append(keys, f)
				}
			}
			require.NotEmpty(t, keys)
			if name == "encrypted in json" {
				return // the armor headers are dropped, the body is the same
			}
			assert.Equal(t, want, fpOf(keys[0]))
		})
	}
	// the armor headers of a plain encrypted key give the same fingerprint as the body alone
	assert.Equal(t, want, fpOf(scanOf(d, []byte(encrypted))[0]))
	assert.Equal(t, want, fpOf(scanOf(d, []byte(jsonStr(encrypted)))[0]))

	// a body that is no clean base64 is still reported
	odd := "-----BEGIN PRIVATE KEY-----\n" + fake(64, b64) + `\q` + fake(10, b64) + "\n-----END PRIVATE KEY-----\n"
	assert.Len(t, scanOf(d, []byte(odd)), 1)
}

// TestUTF16OnlyWhenItIsUTF16: a byte order mark makes a file UTF-16 (decoded
// leniently, see TestUTF16IsDecodedLeniently); that a Latin-1 file starting
// with FF FE is read as UTF-16 too is a documented limit.
func TestUTF16OnlyWhenItIsUTF16(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	// Without a NUL in the first 8000 bytes the file is scanned as UTF-16 and
	// as bytes, so a Latin-1 file or a damaged one still gives its secret.
	for name, content := range map[string]string{
		"fake LE BOM":    "\xff\xfe\nGITHUB_TOKEN=" + token + "\n",
		"fake BE BOM":    "\xfe\xff\nGITHUB_TOKEN=" + token + "\n",
		"latin-1 start":  "\xff\xfe  GITHUB_TOKEN=" + token,
		"odd length":     "\xff\xfeGITHUB_TOKEN=" + token,
		"lone surrogate": "\xff\xfeA\xd8AA GITHUB_TOKEN=" + token,
		"swapped unit":   "\xff\xfeA\xdcA\xd8 GITHUB_TOKEN=" + token,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Len(t, scanOf(d, []byte(content)), 1)
		})
	}
	// a real surrogate pair before the token
	text := "emoji \U0001F600\nGITHUB_TOKEN=" + token
	fs := scanOf(d, append([]byte{0xFF, 0xFE}, utf16LE(strings.NewReplacer("\U0001F600", "😀").Replace(text))...))
	_ = fs
	var units []byte
	for _, u := range []rune{0xD83D, 0xDE00} {
		units = append(units, byte(u), byte(u>>8))
	}
	enc := append([]byte{0xFF, 0xFE}, utf16LE("emoji ")...)
	enc = append(enc, units...)
	enc = append(enc, utf16LE("\nGITHUB_TOKEN="+token)...)
	fs = scanOf(d, enc)
	require.Len(t, fs, 1)
	assert.Equal(t, 2, fs[0].StartLine)
}

func TestLFSVersionLineIsExact(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	oid := fake(64, hexa)
	for name, content := range map[string]string{
		"text after the version": "version https://git-lfs.github.com/spec/v1 GITHUB_TOKEN=" + token + "\noid sha256:" + oid + "\nsize 12\n",
		"key glued to version":   "version https://git-lfs.github.com/spec/v1 AKIA" + fake(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") + "\noid sha256:" + oid + "\nsize 1",
	} {
		assert.NotEmpty(t, scanOf(d, []byte(content)), name)
	}
}

func TestAzureDevOpsPATIsFastOnHostileText(t *testing.T) {
	rule, ok := RuleByID("azure-devops-pat")
	require.True(t, ok)
	d, err := NewDetector([]Rule{rule})
	require.NoError(t, err)
	hostile := []byte(strings.Repeat("azdo "+strings.Repeat("a", 120)+"\n", 1<<20/126))
	start := time.Now()
	fs, complete := d.Scan(hostile)
	assert.Empty(t, fs)
	assert.True(t, complete, "a built-in rule has no window budget")
	assert.Less(t, time.Since(start), 5*time.Second*slowdown, "about 0.7 s here; was 2.9 s for 4 MiB")
	// a token at the start of a window, in the middle of a long alphanumeric run, and at the end
	pat := fake(76, alnum) + "AZDO" + fake(4, alnum)
	for name, content := range map[string]string{"start": pat, "end of line": "x " + pat + "\n", "after a long run": strings.Repeat("a", 5000) + " " + pat} {
		fs, _ := d.Scan([]byte(content))
		assert.Len(t, fs, 1, name)
	}
	fs, _ = d.Scan([]byte(strings.Repeat("b", 50) + pat))
	assert.Empty(t, fs, "part of a longer word")
}

func TestEscapesBeforeToken(t *testing.T) {
	d := allRulesDetector(t)
	gh := "ghp_" + fake(36, alnum)
	for name, content := range map[string]string{
		`"`:      `{"a":"x"` + gh + `"}`,
		`=`:      `?access_token=` + gh,
		`\x3d`:   `b'access_token\x3d` + gh + `'`,
		`&#34;`:  `<a title=&#34;` + gh + `&#34;>`,
		`&#x22;`: `<a title=&#x22;` + gh + `>`,
		`\r\n`:   `{"a":"line\r\n` + gh + `"}`,
		`%0A`:    `a=1%0A` + gh,
	} {
		assert.NotZero(t, countRule(d, content, "github-token"), name)
	}
	assert.Zero(t, countRule(d, `x\u00zz`+gh, "github-token"), "not an escape")
	assert.Zero(t, countRule(d, `xu0022`+gh, "github-token"))
}

func TestKnownPublicKeysArePlaceholders(t *testing.T) {
	d := allRulesDetector(t)
	// the emulator's key, from parts (it is the same everywhere)
	azurite := "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/" + "K1SZFPTOtr/KBHBeksoGMGw=="
	assert.Equal(t, azurite, azuriteKey)
	for _, c := range []string{"AccountKey=" + azurite, `"AccountKey": "` + azurite + `"`, "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=" + azurite + ";"} {
		assert.Zero(t, countRule(d, c, "azure-storage-account-key"), c)
	}
	// a key that only looks like it is still found
	other := azurite[:80] + "abcdef=="
	assert.Equal(t, 1, countRule(d, "AccountKey="+other, "azure-storage-account-key"))
	// the jwt.io example token
	jwtio := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	assert.Zero(t, countRule(d, jwtio, "jwt"))
	assert.Equal(t, 1, countRule(d, strings.TrimSuffix(jwtio, "c")+"d", "jwt"))
}

func TestCustomSecretMinimumAtScanTime(t *testing.T) {
	d, err := NewDetector([]Rule{CustomRule("c", "n", `acme_(\w{1,40})`, []string{"acme_"})})
	require.NoError(t, err)
	assert.Empty(t, scanOf(d, []byte("acme_a")))
	assert.Empty(t, scanOf(d, []byte("acme_abc1234")))
	assert.Len(t, scanOf(d, []byte("acme_abc12345")), 1)
	assert.Len(t, scanOf(d, []byte("acme_"+fake(40, alnum))), 1)
}

func TestCustomRuleOnlyRunsNearKeywords(t *testing.T) {
	d, err := NewDetector([]Rule{CustomRule("c", "n", `acme_([a-z0-9]{10})[ ]{0,3}tail`, []string{"acme_"})})
	require.NoError(t, err)
	content := strings.Repeat("filler line without it\n", 100000) + "x acme_abcdef0123 tail\n" + strings.Repeat("more\n", 100000)
	fs, complete := d.Scan([]byte(content))
	require.Len(t, fs, 1)
	assert.Equal(t, 100001, fs[0].StartLine)
	assert.True(t, complete)
	assert.True(t, regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fs[0].Fingerprint))
}

// TestDefaultRulesScanRandomBase64Fast: with every default rule on, random base64
// (which holds "aws", "akia", ... by chance) scans at 20 MB/s or more.
func TestDefaultRulesScanRandomBase64Fast(t *testing.T) {
	d := defaultRulesDetector(t)
	text := fake(4<<20, b64)
	var w strings.Builder
	for i := 0; i < len(text); i += 76 {
		w.WriteString(text[i:min(i+76, len(text))] + "\n")
	}
	start := time.Now()
	_, complete := d.Scan([]byte(w.String()))
	assert.True(t, complete)
	assert.Less(t, time.Since(start), time.Duration(float64(w.Len())/5e6*float64(time.Second))*time.Duration(slowdown)) // 4x the measured speed
}
