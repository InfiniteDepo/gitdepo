// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package secretdetection

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fpOf(f Finding) string { return f.Fingerprint }

func TestPlaceholdersDoNotHideARealSecret(t *testing.T) {
	d := allRulesDetector(t)
	real := "ghp_" + fake(36, alnum)
	keyID := "AKIA" + fake(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	for name, content := range map[string]string{
		"allowlisted":     strings.Repeat("fixture = \"ghp_"+strings.Repeat("x", 36)+"\"\n", 150) + "TOKEN=" + real + "\n",
		"low entropy":     strings.Repeat("ghp_"+strings.Repeat("ab", 18)+"\n", 150) + real,
		"aws example":     strings.Repeat("AKIAIOSFODNN7EXAMPLE\n", 150) + keyID,
		"jwt without alg": strings.Repeat(jwtNoAlg()+"\n", 150) + "x " + real,
	} {
		t.Run(name, func(t *testing.T) {
			fs := scanOf(d, []byte(content))
			found := false
			for _, f := range fs {
				found = found || f.RuleID == "github-token" || f.RuleID == "aws-access-key-id"
			}
			assert.True(t, found, "real secret after placeholders")
		})
	}
}

func jwtNoAlg() string {
	return b64url(`{"typ":"JWT"}`) + "." + b64url(`{"sub":"1234567890","name":"Jane Roe"}`) + "." + fake(43, b64u)
}

func TestZeroLimitsMeanDefaults(t *testing.T) {
	d := allRulesDetector(t)
	d.MaxMatchesPerRule = 0
	d.MaxContentSize = 0
	assert.Len(t, scanOf(d, []byte("ghp_"+fake(36, alnum))), 1)
	d.MaxMatchesPerRule = -1
	d.MaxContentSize = -1
	assert.Len(t, scanOf(d, []byte("ghp_"+fake(36, alnum))), 1)
}

func TestLongLinesAreScanned(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	for name, content := range map[string]string{
		"padding":   strings.Repeat(" ", 16<<10) + token,
		"minified":  strings.Repeat("a;", 100000) + "k=\"" + "sk_live_" + fake(24, alnum) + "\";" + strings.Repeat("b;", 100000),
		"far right": strings.Repeat("x", 1<<20) + " " + token,
		"CR only":   strings.Repeat(strings.Repeat("a", 100)+"\r", 400) + token,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Len(t, scanOf(d, []byte(content)), 1)
		})
	}
}

func TestLineNumbers(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	for _, tt := range []struct {
		name, eol string
	}{{"LF", "\n"}, {"CRLF", "\r\n"}, {"CR", "\r"}} {
		t.Run(tt.name, func(t *testing.T) {
			content := "one" + tt.eol + "two" + tt.eol + tt.eol + "  x=" + token + tt.eol + "five"
			fs := scanOf(d, []byte(content))
			require.Len(t, fs, 1)
			if tt.eol == "\r" { // as git counts: only LF ends a line
				assert.Equal(t, [3]int{1, 1, 14}, [3]int{fs[0].StartLine, fs[0].EndLine, fs[0].StartCol})
				return
			}
			assert.Equal(t, [3]int{4, 4, 5}, [3]int{fs[0].StartLine, fs[0].EndLine, fs[0].StartCol})
		})
	}
	t.Run("mixed endings", func(t *testing.T) {
		content := "a\r\nb\rc\nd\r\r\n" + token
		fs := scanOf(d, []byte(content))
		require.Len(t, fs, 1)
		assert.Equal(t, 4, fs[0].StartLine, "only LF ends a line")
		assert.Equal(t, 1, fs[0].StartCol)
	})
	t.Run("several findings and a PEM block", func(t *testing.T) {
		pem := pemBlock("RSA PRIVATE KEY", 4)
		fs := scanOf(d, []byte(token+"\r\n"+pem+token))
		require.Len(t, fs, 3)
		assert.Equal(t, [2]int{1, 1}, [2]int{fs[0].StartLine, fs[0].EndLine})
		assert.Equal(t, [2]int{3, 6}, [2]int{fs[1].StartLine, fs[1].EndLine})
		assert.Equal(t, 8, fs[2].StartLine)
	})
}

func TestLFSPointerOnlySkipsRealPointers(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	oid := fake(64, "0123456789abcdef")
	pointer := "version https://git-lfs.github.com/spec/v1\noid sha256:" + oid + "\nsize 12345\n"
	assert.Empty(t, scanOf(d, []byte(pointer)))
	assert.NotEmpty(t, scanOf(d, []byte(pointer+"GITHUB_TOKEN="+token+"\n")), "other content after the pointer")
	assert.NotEmpty(t, scanOf(d, []byte("version https://git-lfs.github.com/spec/v1\nGITHUB_TOKEN="+token+"\n")))
	assert.NotEmpty(t, scanOf(d, []byte("version https://git-lfs.github.com/spec/v10000 "+token)))
	assert.NotEmpty(t, scanOf(d, []byte(pointer+strings.Repeat("# padding\n", 100)+token)), "longer than 1024 bytes")
	assert.NotEmpty(t, scanOf(d, []byte("version https://git-lfs.github.com/spec/v1\noid sha256:short\nsize 1\n"+token)))
}

func TestUTF16IsDecoded(t *testing.T) {
	d := allRulesDetector(t)
	token := "ghp_" + fake(36, alnum)
	text := "first line\r\nGITHUB_TOKEN=" + token + "\r\n"
	encode := func(bo binary.AppendByteOrder, bom bool) []byte {
		var out []byte
		if bom {
			out = bo.AppendUint16(out, 0xFEFF)
		}
		for _, u := range utf16.Encode([]rune(text)) {
			out = bo.AppendUint16(out, u)
		}
		return out
	}
	for name, content := range map[string][]byte{"LE": encode(binary.LittleEndian, true), "BE": encode(binary.BigEndian, true)} {
		t.Run(name, func(t *testing.T) {
			fs := scanOf(d, content)
			require.Len(t, fs, 1)
			assert.Equal(t, 2, fs[0].StartLine)
			assert.Equal(t, 14, fs[0].StartCol)
		})
	}
	assert.Len(t, scanOf(d, encode(binary.LittleEndian, false)), 1, "no BOM: NULs on one side of the pairs is UTF-16 ASCII")
	assert.Empty(t, scanOf(d, []byte("\x00\nGITHUB_TOKEN="+token)))
	assert.Empty(t, scanOf(d, []byte("\xff\xfe")), "BOM only")
	assert.Empty(t, scanOf(d, []byte("\xff\xfeg")), "odd length")
}

func TestTokenBoundaries(t *testing.T) {
	d := allRulesDetector(t)
	gh := "ghp_" + fake(36, alnum)
	aws := "AKIA" + fake(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	gcp := "AIza" + fake(35, b64u)
	for name, tt := range map[string]struct{ content, rule string }{
		"JSON newline escape":  {`{"log":"line\n` + gh + `"}`, "github-token"},
		"JSON tab escape":      {`"a\t` + aws + `"`, "aws-access-key-id"},
		"URL encoded":          {"https://s3.example.org/b?AWSAccessKeyId%3D" + aws, "aws-access-key-id"},
		"URL encoded token":    {"https://h.example.org/?q=1&token%3D" + gh, "github-token"},
		"GCP URL":              {"https://maps.googleapis.com/maps/api/js?key=" + gcp + "&callback=init", "gcp-api-key"},
		"GCP comma":            {`["x",` + gcp + `,"y"]`, "gcp-api-key"},
		"GCP paren":            {"init(" + gcp + ")", "gcp-api-key"},
		"GCP tag":              {"<key>" + gcp + "</key>", "gcp-api-key"},
		"GCP brace":            {"{k:" + gcp + "}", "gcp-api-key"},
		"two tokens one comma": {gcp + "," + "AIza" + fake(35, alnum+"_-")[1:] + "_", "gcp-api-key"},
		"underscore after":     {gh + "_suffix", "github-token"},
		"azure semicolon":      {"ClientSecret=" + fake(3, alnum) + "8Q~" + fake(34, alnum) + ";TenantId=x", "azure-ad-client-secret"},
		"azure ampersand":      {"client_secret=" + fake(3, alnum) + "8Q~" + fake(34, alnum) + "&grant_type=x", "azure-ad-client-secret"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.NotZero(t, countRule(d, tt.content, tt.rule))
		})
	}
	assert.Equal(t, 2, countRule(d, gcp+","+"AIza"+fake(35, b64u)[1:]+"x", "gcp-api-key"), "adjacent tokens")
	for name, content := range map[string]string{
		"letter before":    "x" + gh,
		"longer run":       gh + strings.Repeat("A", 300),
		"gcp longer":       gcp + "x",
		"gcp letter first": "x" + gcp,
	} {
		assert.Zero(t, countRule(d, content, "github-token")+countRule(d, content, "gcp-api-key"), name)
	}
}

func TestSecretLengthCaps(t *testing.T) {
	long, err := NewDetector([]Rule{{ID: "r", Regex: `(?s)BEGIN(.*)END`, SecretGroup: 1, Keywords: []string{"begin"}}})
	require.NoError(t, err)
	assert.Len(t, scanOf(long, []byte("BEGIN"+fake(1000, b64)+"END")), 1)
	assert.Empty(t, scanOf(long, []byte("BEGIN"+strings.Repeat(fake(64, b64), 17)+"END")), "over 1 KiB")

	d := allRulesDetector(t)
	assert.Len(t, scanOf(d, []byte(pemBlock("RSA PRIVATE KEY", 100))), 1, "a 4096 bit key is about 3.3 KiB")
	assert.Len(t, scanOf(d, []byte(pemBlock("RSA PRIVATE KEY", 240))), 1, "a 16384 bit key is about 12 KiB")
	assert.Len(t, scanOf(d, []byte(pemBlock("PGP PRIVATE KEY BLOCK", 600))), 1, "a PGP export with subkeys is about 40 KiB")
	assert.Empty(t, scanOf(d, []byte(pemBlock("RSA PRIVATE KEY", 1100))), "over 64 KiB")
}

func TestScanDropsOversizedSecret(t *testing.T) { TestSecretLengthCaps(t) }

func TestPrivateKeyFingerprintIsStable(t *testing.T) {
	d := defaultRulesDetector(t)
	body := make([]string, 6)
	for i := range body {
		body[i] = fake(64, b64)[i:] + fake(i, b64)
	}
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END RSA PRIVATE KEY-----\n"
	yaml := "key: |\n    -----BEGIN RSA PRIVATE KEY-----\n    " + strings.Join(body, "\n    ") + "\n    -----END RSA PRIVATE KEY-----\n"
	gcp := gcpJSON("service_account", `-----BEGIN RSA PRIVATE KEY-----\n`+strings.Join(body, `\n`)+`\n-----END RSA PRIVATE KEY-----\n`)
	// the old (PKCS#1) header in the GCP rule too, as the rule takes both
	forms := map[string]string{
		"pem":  pem,
		"crlf": strings.ReplaceAll(pem, "\n", "\r\n"),
		"yaml": yaml,
		"gcp":  gcp,
		"json": `{"k": "` + strings.ReplaceAll(strings.TrimSuffix(pem, "\n"), "\n", `\n`) + `"}`,
	}
	var want string
	for name, content := range forms {
		fs := scanOf(d, []byte(content))
		require.Len(t, fs, 1, name)
		if want == "" {
			want = fpOf(fs[0])
		}
		assert.Equal(t, want, fpOf(fs[0]), name)
	}
	assert.Equal(t, "gcp-service-account-key", scanOf(d, []byte(gcp))[0].RuleID)
	// a different key is a different fingerprint
	other := scanOf(d, []byte(pemBlock("RSA PRIVATE KEY", 5)))
	require.Len(t, other, 1)
	assert.NotEqual(t, want, fpOf(other[0]))
}

func TestPrivateKeyArmorHeaders(t *testing.T) {
	d := allRulesDetector(t)
	pgp := "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nComment: Alice <alice@corp.test> (work)\n\n" + fake(64, b64) + "\n" + fake(60, b64) + "\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----\n"
	assert.Equal(t, 1, countRule(d, pgp, "private-key"))
	enc := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n" + fake(64, b64) + "\n" + fake(60, b64) + "\n-----END RSA PRIVATE KEY-----\n"
	assert.Equal(t, 1, countRule(d, enc, "private-key"))
	// a fake BEGIN line before a real key must not swallow it
	assert.Equal(t, 1, countRule(d, "-----BEGIN PRIVATE KEY-----\n"+fake(64, b64)+"\n"+pemBlock("PRIVATE KEY", 4), "private-key"))
	assert.Zero(t, countRule(d, "-----BEGIN PRIVATE KEY-----\n<paste your key here, 64 or more characters, between the lines>\n-----END PRIVATE KEY-----\n", "private-key"))
}

func TestForgejoTokenContexts(t *testing.T) {
	d := allRulesDetector(t)
	hex40 := fake(40, hexa)
	count := func(content string) int {
		n := 0
		for _, f := range scanOf(d, []byte(content)) {
			if strings.HasPrefix(f.RuleID, "forgejo-access-token") {
				n++
			}
		}
		return n
	}
	for _, tp := range []string{
		`{"Authorization": "token ` + hex40 + `"}`,
		`headers = {'Authorization': 'Bearer ` + hex40 + `'}`,
		"Authorization: token " + hex40,
		"token: " + hex40,
		"https://bob:" + hex40 + "@git.corp.test/x.git",
		"https://" + hex40 + "@git.corp.test/x.git",
	} {
		assert.Equal(t, 1, count(tp), tp)
	}
	for _, fp := range []string{
		"token_fingerprint = " + strings.ToUpper(hex40),
		"next_page_token: " + strings.ToUpper(hex40),
		"https://" + hex40 + ".mirror.corp.test/",
		"https://user:" + hex40 + ".corp.test/",
		"commit " + hex40,
	} {
		assert.Zero(t, count(fp), fp)
	}
}

type ruleTest struct {
	rule      string
	positives []string
	negatives []string
}

// moreRuleTests are TestRules entries for the formats added after the first
// rules, and the second batch of true and false positives of older rules.
func moreRuleTests() []ruleTest {
	hex40 := fake(40, hexa)
	hex64 := fake(64, hexa)
	return []ruleTest{
		{
			"gitlab-token",
			[]string{
				"gloas-" + hex64,
				"glcbt-" + fake(3, alnum) + "_" + fake(20, b64u),
				"glsoat-" + fake(20, b64u),
				"glffct-" + fake(20, b64u),
				"glpat-" + fake(40, b64u) + ".01." + fake(7, "abcdefghijklmnopqrstuvwxyz0123456789"),
				"glrt-t1_" + fake(30, b64u) + ".01." + fake(7, "abcdefghijklmnopqrstuvwxyz0123456789"),
				"GR1348941" + fake(20, b64u),
			},
			[]string{"glcbt-short", "glsoat-" + strings.Repeat("x", 20), "GR1348941short", "gloas-<token>", "glffct-" + strings.Repeat("a", 20)},
		},
		{
			"forgejo-oauth2-secret",
			[]string{"client_secret: gto_" + fake(52, "abcdefghijklmnopqrstuvwxyz234567"[:32]), "code=gta_" + fake(52, "abcdefghijklmnopqrstuvwxyz234567")},
			[]string{"gto_" + fake(51, "abcdefghijklmnopqrstuvwxyz234567"), "gto_" + strings.Repeat("a", 52), "gto_<secret>", "gto_" + strings.ToUpper(fake(52, "abcdefghijklmnopqrstuvwxyz234567"))},
		},
		{
			"slack-token",
			[]string{
				"xapp-1-A" + fake(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") + "-" + "2109876543210-" + fake(32, hexa),
				"xoxe.xoxp-1-" + fake(170, alnum),
				"xoxe-1-" + fake(146, alnum),
				"xoxb-210987654321-" + fake(24, alnum),
				"xoxa-2-" + fake(24, alnum),
			},
			[]string{"xapp-1-short", "xoxe-1-short", "xoxe.xoxp-1-short", "xoxb-210987654321", "xapp-your-token"},
		},
		{
			"azure-devops-pat",
			[]string{"pat: " + fake(76, alnum) + "AZDO" + fake(4, alnum), `"` + fake(76, alnum) + "AZDO" + fake(4, alnum) + `"`},
			[]string{fake(76, alnum) + "AZDO" + fake(3, alnum), fake(76, alnum) + "AZDX" + fake(4, alnum), "x" + fake(76, alnum) + "AZDO" + fake(4, alnum), strings.Repeat("a", 76) + "AZDO" + "abcd"},
		},
		{
			"azure-shared-access-key",
			[]string{"Endpoint=sb://ns.example.org/;SharedAccessKeyName=root;SharedAccessKey=" + fake(43, b64) + "=", "SharedAccessKey=" + fake(43, b64) + "="},
			[]string{"SharedAccessKey=<key>", "SharedAccessKey=" + fake(40, b64) + "=", "SharedAccessKey=" + strings.Repeat("x", 43) + "="},
		},
		{
			"azure-storage-account-key",
			[]string{`"AccountKey": "` + fake(86, b64) + `=="`, "accountKey: " + fake(86, b64) + "==", `storage_account_key = "` + fake(86, b64) + `=="`},
			[]string{`"AccountKey": "<key>"`, "accountKey: " + fake(40, b64) + "=="},
		},
		{
			"stripe-live-key",
			[]string{"sk_live_" + fake(200, alnum), "sk_live_51" + fake(98, alnum)},
			[]string{"sk_live_" + fake(250, alnum)[:5], "sk_live_" + strings.Repeat("a", 250)},
		},
		{
			"github-token",
			[]string{"ghs_" + fake(36, alnum), "ghs_" + fake(100, alnum)},
			[]string{"ghs_" + fake(300, alnum)},
		},
		{
			"aws-secret-access-key",
			[]string{"aws configure set aws_secret_access_key " + fake(40, b64), "--aws-secret-access-key " + fake(40, b64)},
			[]string{"--aws-secret-access-key " + fake(39, b64)},
		},
		{
			"forgejo-access-token-header",
			[]string{`{"Authorization": "token ` + hex40 + `"}`, `headers = {'Authorization': 'Bearer ` + hex40 + `'}`, "Authorization: token " + hex40},
			[]string{"Authorization: token " + strings.ToUpper(hex40), "Authorization: token " + fake(39, hexa), "Authorization: Basic " + hex40},
		},
		{
			"forgejo-access-token-netrc",
			[]string{"machine git.corp.test login bob password " + hex40, "machine git.corp.test\n  login bob\n  password " + hex40},
			[]string{"machine git.corp.test login bob password " + fake(39, hexa), "machine git.corp.test login bob password " + hex40 + "ab"},
		},
		{
			"forgejo-access-token-url",
			[]string{"https://bob:" + hex40 + "@git.corp.test/x.git", "https://" + hex40 + "@git.corp.test/x.git"},
			[]string{"https://" + hex40 + ".mirror.corp.test/", "https://user:" + hex40 + ".corp.test/", "https://bob:" + fake(39, hexa) + "@git.corp.test/x.git"},
		},
		{
			"jwt",
			[]string{},
			[]string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
		},
		{
			"generic-secret-assignment",
			[]string{},
			[]string{`NoKeyFound = "gpg.error.no_gpg_keys_found"`, `key = "actions.run_retention_days_long"`},
		},
	}
}

// defaultRulesDetector has the rules a caller enables without being asked.
func defaultRulesDetector(t testing.TB) *Detector {
	t.Helper()
	var rules []Rule
	for _, r := range BuiltinRules() {
		if !r.DefaultOff {
			rules = append(rules, r)
		}
	}
	d, err := NewDetector(rules)
	require.NoError(t, err)
	return d
}

func FuzzScan(f *testing.F) {
	token := "ghp_" + fake(36, alnum)
	for _, seed := range []string{
		"", "\n", "\r", "\r\n\r", token, "a\r\nb\rc\n" + token + "\r",
		pemBlock("RSA PRIVATE KEY", 3), strings.ReplaceAll(pemBlock("PRIVATE KEY", 3), "\n", "\r"),
		gcpJSON("service_account", `-----BEGIN PRIVATE KEY-----\n`+fake(64, b64)+`\n-----END PRIVATE KEY-----\n`),
		"AKIA" + fake(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") + "\nsecret: " + fake(40, b64),
		"https://bob:" + fake(40, hexa) + "@git.corp.test/", "\x00" + token, "\xff\xfe" + "g\x00h\x00",
		"version https://git-lfs.github.com/spec/v1\noid sha256:" + fake(64, hexa) + "\nsize 1\n",
		jwtNoAlg(), "key = \"" + fake(30, alnum) + "\"", strings.Repeat("eyJ", 100),
	} {
		f.Add([]byte(seed), uint8(0), uint8(0))
	}
	d := allRulesDetector(f)
	f.Fuzz(func(t *testing.T, content []byte, maxSize, maxFindings uint8) {
		d.MaxContentSize = int(maxSize) * 8 // 0 is the default
		d.MaxMatchesPerRule = int(maxFindings) % 5
		fs := scanOf(d, content)
		lines := 1 + bytes.Count(content, []byte("\n")) + bytes.Count(content, []byte("\r")) - bytes.Count(content, []byte("\r\n"))
		if len(content) >= 2 && (content[0] == 0xFF && content[1] == 0xFE || content[0] == 0xFE && content[1] == 0xFF) {
			lines = len(content) // decoded text may have more line breaks than bytes of the original
		}
		perRule := map[string]int{}
		for i, f := range fs {
			if f.StartLine < 1 || f.EndLine < f.StartLine || f.EndLine > lines || f.StartCol < 1 || len(f.Fingerprint) != 64 {
				t.Fatalf("bad finding %+v in %d lines", f, lines)
			}
			if i > 0 && (f.StartLine < fs[i-1].StartLine || f.StartLine == fs[i-1].StartLine && f.StartCol < fs[i-1].StartCol) {
				t.Fatalf("unsorted: %+v after %+v", f, fs[i-1])
			}
			if perRule[f.RuleID]++; d.MaxMatchesPerRule > 0 && perRule[f.RuleID] > d.MaxMatchesPerRule {
				t.Fatalf("%d findings of %s", perRule[f.RuleID], f.RuleID)
			}
		}
	})
}

// scanOf is the findings of Scan.
func scanOf(d *Detector, content []byte) []Finding {
	fs, _ := d.Scan(content)
	return fs
}
