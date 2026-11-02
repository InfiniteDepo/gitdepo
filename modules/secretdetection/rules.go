// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// NOTICE: many of the patterns below are adapted from gitleaks v8.28.0,
// config/gitleaks.toml (https://github.com/gitleaks/gitleaks/tree/v8.28.0),
// which is licensed under the MIT licence:
//
//	MIT License
//
//	Copyright (c) 2019 Zachary Rice
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.
//
// Changes: narrowed to the rules listed here, secret groups and boundaries
// reworked, allowlists and the JWT/GCP/Forgejo/AWS-secret rules are our own.

package secretdetection

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"forgejo.org/modules/json"
)

// firebaseSampleKeys are the GCP API keys of the Firebase SDK samples
// (gitleaks' allowlist), without the AIza prefix so no full key is a literal.
var firebaseSampleKeys = []string{
	"SyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs", "SyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM", "SyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
	"SyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0", "yDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A", "SyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
	"SyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4", "SyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY", "SyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
	"SyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ", "SyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g", "SyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
	"SyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw", "SyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE", "SyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY",
}

var firebaseSampleKeysRegex = `^AIza(?:` + strings.Join(firebaseSampleKeys, "|") + `)$`

// placeholders are dropped by every built-in rule: documentation examples,
// runs of x, ${VAR} and {{ var }} templates, <token> markers.
var placeholders = []string{`(?i)example`, `(?i)x{5,}`, `\$\{`, `\{\{`, `<[^<>\s]{2,40}>`}

// Sets of bytes for Rule.TokenChars.
const (
	alnumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	wordChars  = alnumChars + "_-"
)

// builtinRules: the generic rule last, so a specific rule wins an overlap; see
// curlHeaderRules for the curl rules' places.
var builtinRules = slices.Concat(baseRules, gitleaksRules, curlUserRules, gitleaksServiceRules, curlHeaderRules, []Rule{genericRule})

var baseRules = []Rule{
	{
		ID: "aws-access-key-id", Name: "AWS access key ID", Type: "aws",
		Keywords:    []string{"akia", "asia", "abia", "acca", "a3t"},
		Regex:       `((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars,
	},
	{
		// The secret key is 40 base64 characters, which is too common alone:
		// it counts after aws_secret_access_key (or similar) = ... or a space.
		ID: "aws-secret-access-key", Name: "AWS secret access key", Type: "aws",
		Keywords:    []string{"aws"},
		Regex:       `(?i)aws[\w.-]{0,30}secret[\w.-]{0,30}(?:\\?["'])?(?:\s*(?::=|=>|[:=])\s*|\s+)(?:\\?["'])?([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`,
		SecretGroup: 1, MinEntropy: 4, Window: 512, Anchored: true, HitCheck: awsSecretHit,
	},
	{
		// ... or within 120 bytes after an access key ID.
		ID: "aws-secret-access-key-near-id", Name: "AWS secret access key next to a key ID", Type: "aws",
		Keywords:    []string{"akia", "asia", "abia", "acca", "a3t"},
		Regex:       `\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b[\s\S]{0,120}?[^A-Za-z0-9/+=]([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)`,
		SecretGroup: 1, MinEntropy: 4.3, Window: 256, Anchored: true, HitCheck: awsIDHit,
	},
	{
		ID: "azure-storage-account-key", Name: "Azure storage account key", Type: "azure",
		Keywords:    []string{"accountkey", "storage_key", "storage_account_key", "storageaccount_key", "storagekey", "storageaccountkey"},
		Regex:       `(?i)(?:accountkey|storage_?(?:account_?)?key)["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{86}==)`,
		SecretGroup: 1, MinEntropy: 4,
		Window:    512,
		Allowlist: []string{"^" + regexp.QuoteMeta(azuriteKey) + "$"},
	},
	{
		// Service Bus, Event Hub and IoT Hub connection strings.
		ID: "azure-shared-access-key", Name: "Azure shared access key", Type: "azure",
		Keywords:    []string{"sharedaccesskey"},
		Regex:       `(?i)sharedaccesskey["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{43}=)`,
		SecretGroup: 1, MinEntropy: 4,
		Window: 512,
	},
	{
		// The 84 character PAT format (2024) has AZDO at bytes 77 to 80.
		ID: "azure-devops-pat", Name: "Azure DevOps personal access token", Type: "azure",
		Keywords:    []string{"azdo"},
		Regex:       `([A-Za-z0-9]{76}AZDO[A-Za-z0-9]{4})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: alnumChars,
		// The regex has no literal prefix: the hit "AZDO" (this case only) sits
		// 76 bytes into the match, and 76 alphanumerics must come before it.
		Window: 4, Anchored: true, KeywordOffset: 76, HitCheck: azdoHit,
	},
	{
		// The older PATs are 52 lowercase characters with no marker, so they
		// only count within 40 bytes after azure, devops or ado_pat.
		ID: "azure-devops-pat-legacy", Name: "Azure DevOps personal access token (52 characters)", Type: "azure",
		Keywords:    []string{"azure", "devops", "ado_pat"},
		Regex:       `(?i:azure|devops|ado_pat)[^\r\n]{0,40}?[^0-9a-z\r\n]([0-9a-z]{52})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: alnumChars, Window: 100, Anchored: true, HitCheck: azdoLegacyHit,
	},
	{
		ID: "azure-ad-client-secret", Name: "Azure AD client secret", Type: "azure",
		Keywords:    []string{"q~"},
		Regex:       `([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "_~.-", TrailingOK: ".",
		Window: 64,
	},
	{
		// type and private_key sit in the same JSON object, type first. The
		// secret is the key body, as for the private-key rule, so one key has
		// one fingerprint wherever it is stored.
		ID: "gcp-service-account-key", Name: "GCP service account private key", Type: "gcp",
		Keywords:    []string{"service_account"},
		Regex:       `"type"\s*:\s*"service_account"[\s\S]{0,600}?"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----\s*((?:\\+[nrt/]|\\u[0-9a-fA-F]{4}|[A-Za-z0-9+/=\s]){64,}?)(?:\\+[nrt]|\s)*-----END (?:RSA )?PRIVATE KEY-----`,
		SecretGroup: 1, MinEntropy: 3, Normalize: normalizePEM, MaxSecretLen: maxPrivateKeyLen,
	},
	{
		ID: "gcp-api-key", Name: "GCP API key", Type: "gcp",
		Keywords:    []string{"aiza"},
		Regex:       `(AIza[\w-]{35})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: wordChars, TrailingOK: "-",
		Allowlist: []string{firebaseSampleKeysRegex},
	},
	{
		// ghp_ personal, gho_ OAuth, ghu_ user-to-server, ghs_ server-to-server, ghr_ refresh.
		ID: "github-token", Name: "GitHub token", Type: "github",
		Keywords:    []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		Regex:       `(gh[pousr]_[0-9A-Za-z]{36,251})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars,
	},
	{
		// The legacy form is 40 hex characters, as an OAuth app's client
		// secret: it counts after a github name that ends in a secret, pat,
		// key or password word (github_secret, GITHUB_CLIENT_SECRET). A bare
		// GITHUB_TOKEN is left to the Forgejo rules: Actions on gitdepo set
		// it to gitdepo's own job token.
		ID: "github-legacy-token", Name: "GitHub token or client secret (40 hex characters)", Type: "github",
		Keywords:    []string{"github"},
		Regex:       `(?i:github)(?:[\w.-]{0,20}[_.-])?(?i:secret|pat|key|password)(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?([0-9a-f]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 512, Anchored: true, HitCheck: githubHit,
	},
	{
		ID: "github-fine-grained-pat", Name: "GitHub fine-grained personal access token", Type: "github",
		Keywords:    []string{"github_pat_"},
		Regex:       `(github_pat_[0-9A-Za-z_]{82})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "_",
	},
	{
		// personal, deploy, runner, pipeline trigger, feature flag, incoming
		// mail, agent, CI job, SCIM, feature flag client and OAuth application
		// secret tokens, the routable form (a dot and 9 characters at the
		// end) and the runner registration token.
		ID: "gitlab-token", Name: "GitLab token", Type: "gitlab",
		Keywords:    []string{"glpat-", "gldt-", "glrt-", "glptt-", "glft-", "glimt-", "glagent-", "glcbt-", "glsoat-", "glffct-", "gloas-", "gr1348941"},
		Regex:       `(gl(?:pat|dt|rt|ptt|ft|imt|agent|cbt|soat|ffct|oas)-[0-9A-Za-z_-]{20,300}(?:\.[0-9a-z]{9})?|GR1348941[0-9A-Za-z_-]{20})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars,
		Window: 400,
	},
	// An access token of Forgejo, Gitea and gitdepo is 40 hex characters (hex
	// of 20 random bytes, models/auth/access_token.go) with no prefix, so it
	// only counts in a context that says it is a credential. One rule per
	// context, so each regex starts with its own words: `token = <hex>`,
	// `Authorization: token <hex>` (also as a JSON or YAML key), a .netrc
	// password and the password of a URL (https://user:<hex>@host).
	{
		ID: "forgejo-access-token", Name: "Forgejo, Gitea or gitdepo access token", Type: "forgejo",
		Keywords:    []string{"token"},
		Regex:       `(?i:token)[\w.-]{0,20}(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?([0-9a-f]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 512, Anchored: true, HitCheck: tokenHit,
	},
	{
		ID: "forgejo-access-token-header", Name: "Forgejo, Gitea or gitdepo access token in an Authorization header", Type: "forgejo",
		Keywords:    []string{"authorization"},
		Regex:       `(?i:authorization)["']?\s*[:=]\s*["']?(?i:token|bearer)\s+([0-9a-f]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars,
		Window: 512,
	},
	{
		ID: "forgejo-access-token-netrc", Name: "Forgejo, Gitea or gitdepo access token in a .netrc file", Type: "forgejo",
		Keywords:    []string{"machine"},
		Regex:       `machine\s+\S{1,64}\s+login\s+\S{1,64}\s+password\s+([0-9a-f]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars,
	},
	{
		ID: "forgejo-access-token-url", Name: "Forgejo, Gitea or gitdepo access token in a URL", Type: "forgejo",
		Keywords:    []string{"://"},
		Regex:       `://(?:[^\s/:@]{1,64}:)?([0-9a-f]{40})@`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars,
	},
	{
		// OAuth2 application client secrets (gto_) and authorization codes
		// (gta_) of the instance: base32 of 32 random bytes (models/auth/oauth2.go).
		ID: "forgejo-oauth2-secret", Name: "Forgejo, Gitea or gitdepo OAuth2 secret", Type: "forgejo",
		Keywords:    []string{"gto_", "gta_"},
		Regex:       `(gt[ao]_[a-z2-7]{52})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars,
	},
	{
		// PEM private keys, RSA, EC, DSA, OPENSSH, PGP and plain PKCS#8. The
		// secret is the block body, without the BEGIN and END lines, with
		// optional armor headers (Proc-Type, Comment) in front.
		ID: "private-key", Name: "Private key", Type: "private-key",
		Keywords:    []string{"-----begin"},
		Regex:       `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----(?:\s|\\+[nrt])*((?:[A-Za-z][A-Za-z-]{1,29}:[^\r\n\\]{0,200}(?:[\r\n]|\\+[nrt])+\s*)*[A-Za-z0-9+/=\s\\]{64,}?)\s*-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`,
		SecretGroup: 1, MinEntropy: 3, Normalize: normalizePEM, MaxSecretLen: maxPrivateKeyLen,
	},
	{
		// xoxb bot, xoxp user, xoxa app (xoxa-2-<3 IDs>-<hex>), xoxr refresh,
		// legacy xoxs/xoxo (<3 IDs>-<hex>) and the legacy forms with one
		// group of digits, xapp app-level, xoxe rotating tokens.
		ID: "slack-token", Name: "Slack token", Type: "slack",
		Keywords:    []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxo-", "xapp-", "xoxe"},
		Regex:       `(xapp-[0-9]-[A-Za-z0-9]{6,}-[0-9]{8,}-[A-Za-z0-9]{32,}|xoxe\.xox[bp]-[0-9]-[A-Za-z0-9]{100,}|xoxe-[0-9]-[A-Za-z0-9]{100,}|xox[bparso]-[0-9]{1,14}(?:-[0-9A-Za-z]{8,64}){1,4})`,
		SecretGroup: 1, MinEntropy: 2, TokenChars: alnumChars,
	},
	{
		ID: "slack-webhook-url", Name: "Slack webhook URL", Type: "slack",
		Keywords:    []string{"hooks.slack.com"},
		Regex:       `hooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9+/]{43,56})`,
		SecretGroup: 1, MinEntropy: 3,
	},
	{
		// live and prod (gitleaks' stripe-access-token)
		ID: "stripe-live-key", Name: "Stripe live secret key", Type: "stripe",
		Keywords:    []string{"sk_live_", "rk_live_", "sk_prod_", "rk_prod_"},
		Regex:       `((?:sk|rk)_(?:live|prod)_[0-9A-Za-z]{10,247})`,
		SecretGroup: 1, MinEntropy: 2, TokenChars: alnumChars,
		Window: 300,
	},
	{
		// Its own rule so users can mark test keys as "used in tests".
		ID: "stripe-test-key", Name: "Stripe test secret key", Type: "stripe",
		Keywords:    []string{"sk_test_", "rk_test_"},
		Regex:       `((?:sk|rk)_test_[0-9A-Za-z]{10,247})`,
		SecretGroup: 1, MinEntropy: 2, TokenChars: alnumChars,
		Window: 300,
	},
	{
		// Three base64url parts; header and payload start with eyJ (`{"`). The
		// signature may be empty (alg none, which still counts); a short one
		// of letters only ("signature") is a documentation sample. The token
		// of jwt.io's documentation is no secret. RS256 tokens with claims
		// are often over 1 KiB.
		ID: "jwt", Name: "JSON Web Token", Type: "jwt",
		Keywords:    []string{"eyj"},
		Regex:       `(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, MaxSecretLen: 8 << 10,
		Check:     jwtCheck,
		Allowlist: []string{jwtIOSignature},
	},
	{
		// A JWT in base64 on one line (a Kubernetes secret, base64 -w0; GNU
		// base64's wrapped output is not decoded): the secret is the decoded
		// JWT and its findings are the jwt rule's, so both forms are one alert.
		ID: "jwt-base64", Name: "JSON Web Token in base64", Type: "jwt", ReportAs: "jwt",
		Keywords:    []string{"zxlk"},
		Regex:       `(ZXlK[A-Za-z0-9+/]{40,}={0,2})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/", MaxSecretLen: 8 << 10,
		Normalize: decodeBase64JWT, Check: jwtCheck,
		Allowlist: []string{jwtIOSignature},
	},
}

// Dotted names (locale keys, settings) are no secrets.
var genericRule = Rule{
	ID: "generic-secret-assignment", Name: "Generic secret assignment", Type: "generic",
	Keywords:    []string{"secret", "password", "passwd", "token", "key"},
	Regex:       `(?i)(?:secret|password|passwd|token|key)[\w.-]{0,20}(?:\\?["'])?\s*(?::=|[:=])\s*\\?["']((?:[^\s"'\x60\\]|\\[^\s"'\x60]){20,100})\\?["']`,
	SecretGroup: 1, MinEntropy: 3.5, DefaultOff: true, Window: 512, Anchored: true, HitCheck: genericHit,
	Allowlist: []string{`^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$`},
}

// The hit checks below are the cheap exact tests of the hot rules: they let a
// keyword hit through to the regex only if the bytes around it have the shape
// of a match, so text that is all keywords costs a few comparisons per hit.

// azdoHit: AZDO in capitals with 76 alphanumeric bytes before it and 4 after.
func azdoHit(_, c []byte, p int) bool {
	if p < 76 || p+8 > len(c) || string(c[p:p+4]) != "AZDO" {
		return false
	}
	for _, b := range c[p-76 : p] {
		if !isAlnum(b) {
			return false
		}
	}
	for _, b := range c[p+4 : p+8] {
		if !isAlnum(b) {
			return false
		}
	}
	return true
}

// azdoLegacyHit: within 40 bytes of the line after the keyword (5 to 7
// bytes), a byte that is no lowercase alphanumeric, then exactly 52 of them.
func azdoLegacyHit(_, c []byte, p int) bool {
	isLowerAlnum := func(b byte) bool { return '0' <= b && b <= '9' || 'a' <= b && b <= 'z' }
	for i := p + len("azure"); i < len(c) && i <= p+len("ado_pat")+40 && c[i] != '\n' && c[i] != '\r'; i++ {
		if !isLowerAlnum(c[i]) && run(c, i+1, 52, isLowerAlnum) == 52 {
			return true
		}
	}
	return false
}

// githubHit: "github", a name rest, an assignment, then 40 hex digits.
func githubHit(_, c []byte, p int) bool { return hex40After(c, p+len("github"), 40) }

func isWord(b byte) bool { return isAlnum(b) || b == '_' }

func isBlank(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
}

func isQuote(b byte) bool { return b == '"' || b == '\'' }

// quoteLen is the length of the quote at c[i]: 1, or 2 with a backslash before
// it (JSON inside a string), else 0.
func quoteLen(c []byte, i int) int {
	switch {
	case i < len(c) && isQuote(c[i]):
		return 1
	case i+1 < len(c) && c[i] == '\\' && isQuote(c[i+1]):
		return 2
	}
	return 0
}

// valueAfter follows the shape name[\w.-]{0,gap}["']?, blanks, an assignment
// operator (:=, =>, : or =; with blankOnly a run of blanks alone will do),
// blanks, an optional quote (a required one with needQuote), and returns where
// the value starts. Blanks are bounded at 500 bytes, as the window is.
func valueAfter(c []byte, i, gap int, blankOnly, needQuote bool) (int, bool) {
	for n := 0; i < len(c) && n < gap && (isWord(c[i]) || c[i] == '.' || c[i] == '-'); n++ {
		i++
	}
	i += quoteLen(c, i)
	skip := func() int {
		start := i
		for end := i + 500; i < len(c) && i < end && isBlank(c[i]); i++ {
		}
		return i - start
	}
	blanks := skip()
	switch {
	case i+1 < len(c) && (c[i] == ':' && c[i+1] == '=' || c[i] == '=' && c[i+1] == '>'):
		i += 2
	case i < len(c) && (c[i] == ':' || c[i] == '='):
		i++
	case blankOnly && blanks > 0:
	default:
		return 0, false
	}
	skip()
	q := quoteLen(c, i)
	if q == 0 && needQuote {
		return 0, false
	}
	return i + q, true
}

func isHexLower(b byte) bool { return '0' <= b && b <= '9' || 'a' <= b && b <= 'f' }

func isB64(b byte) bool { return isAlnum(b) || b == '/' || b == '+' || b == '=' }

// run is the length of the run of bytes ok accepts at c[i:], up to max+1.
func run(c []byte, i, max int, ok func(byte) bool) int {
	n := 0
	for i+n < len(c) && n <= max && ok(c[i+n]) {
		n++
	}
	return n
}

// tokenHit: "token", a short name rest, an assignment, then 40 lowercase hex
// digits (as the pattern; capitals are the pattern's business, the hit only
// needs the digits to be there).
func tokenHit(_, c []byte, p int) bool { return hex40After(c, p+len("token"), 20) }

func hex40After(c []byte, i, gap int) bool {
	i, ok := valueAfter(c, i, gap, false, false)
	return ok && run(c, i, 40, func(b byte) bool { return isHexLower(b) || 'A' <= b && b <= 'F' }) >= 40
}

// genericHit: one of the generic rule's words, a quoted assignment, then 20 to
// 100 bytes without blanks or quotes and a closing quote.
func genericHit(lower, c []byte, p int) bool {
	for _, w := range []string{"secret", "password", "passwd", "token", "key"} {
		if !bytes.HasPrefix(lower[p:], []byte(w)) {
			continue
		}
		i, ok := valueAfter(c, p+len(w), 20, false, true)
		if !ok {
			continue
		}
		// units of the pattern: a byte, or a backslash with the byte it escapes
		// (a backslash before a quote ends the value instead)
		n, j := 0, i
	units:
		for j < len(c) && n <= 100 {
			switch b := c[j]; {
			case isBlank(b) || isQuote(b) || b == '`':
				break units
			case b == '\\':
				if j+1 >= len(c) || isBlank(c[j+1]) || isQuote(c[j+1]) || c[j+1] == '`' {
					break units
				}
				j++
			}
			j++
			n++
		}
		if n >= 20 && n <= 100 && quoteLen(c, j) > 0 {
			return true
		}
	}
	return false
}

// awsSecretHit: "aws", then within the 30 bytes the pattern allows a "secret",
// then an assignment and 40 base64 bytes.
func awsSecretHit(lower, c []byte, p int) bool {
	limit := min(len(lower), p+3+30+len("secret"))
	for from := p; ; {
		j := bytes.Index(lower[from:limit], []byte("secret"))
		if j < 0 {
			return false
		}
		if i, ok := valueAfter(c, from+j+len("secret"), 30, true, false); ok && run(c, i, 40, isB64) >= 40 {
			return true
		}
		from += j + 1
	}
}

// awsIDHit: a key ID that starts a word, has 16 more of A-Z2-7 and ends it,
// with a 40 byte base64 run in the 140 bytes after it.
func awsIDHit(_, c []byte, p int) bool {
	if p > 0 && isWord(c[p-1]) || p+20 > len(c) {
		return false
	}
	switch {
	case string(c[p:p+4]) == "AKIA", string(c[p:p+4]) == "ASIA", string(c[p:p+4]) == "ABIA", string(c[p:p+4]) == "ACCA":
	case string(c[p:p+3]) == "A3T" && ('A' <= c[p+3] && c[p+3] <= 'Z' || '0' <= c[p+3] && c[p+3] <= '9'):
	default:
		return false
	}
	for _, b := range c[p+4 : p+20] {
		if !('A' <= b && b <= 'Z' || '2' <= b && b <= '7') {
			return false
		}
	}
	if p+20 < len(c) && isWord(c[p+20]) {
		return false
	}
	// the secret: 40 base64 bytes after a non-base64 byte, within 121 bytes
	for i, n := p+20, 0; i < len(c) && n < 162; i, n = i+1, n+1 {
		if !isB64(c[i]) && run(c, i+1, 40, isB64) >= 40 {
			return true
		}
	}
	return false
}

func isAlnum(b byte) bool {
	return '0' <= b && b <= '9' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z'
}

// azuriteKey is the storage account key of the Azurite emulator, the same on
// every machine and in the Azure documentation. It is built from parts so the
// source holds no full key literal.
var azuriteKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/" + "K1SZFPTOtr/KBHBeksoGMGw=="

const maxPrivateKeyLen = 64 << 10 // PGP exports with several subkeys pass 16 KiB

// normalizePEM is the canonical form of a private key body: up to three
// layers of string escaping undone (JSON, PHP, shell: \\, \/, \n, \r, \t,
// \uXXXX), the armor header lines (Proc-Type, Comment, ...) dropped and all
// whitespace removed. If what is left is not base64 (text between the two
// dashed lines, an escape this doesn't know), the whitespace-stripped raw body
// is used instead: a match is never dropped, it only gets a less stable
// fingerprint.
func normalizePEM(secret []byte) []byte {
	s := string(secret)
	for range 3 {
		if !strings.Contains(s, `\`) {
			break
		}
		s = unescape(s)
	}
	var out []byte
	for line := range strings.SplitSeq(strings.ReplaceAll(s, "\r", "\n"), "\n") {
		if strings.Contains(line, ":") {
			continue
		}
		for _, c := range []byte(line) {
			switch {
			case c <= ' ':
			case 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '=':
				out = append(out, c)
			default:
				return stripSpace(secret)
			}
		}
	}
	return out
}

func stripSpace(b []byte) []byte {
	return slices.DeleteFunc(slices.Clone(b), func(c byte) bool { return c <= ' ' })
}

var controlEscapes = map[byte]byte{'n': '\n', 'r': '\r', 't': '\t'}

// unescape undoes one layer of backslash escapes.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n', 'r', 't':
			b.WriteByte(controlEscapes[s[i]])
		case '\\', '/':
			b.WriteByte(s[i])
		case 'u':
			if n, err := strconv.ParseUint(s[min(i+1, len(s)):min(i+5, len(s))], 16, 16); err == nil && i+5 <= len(s) {
				b.WriteRune(rune(n))
				i += 4
				continue
			}
			b.WriteString(`\u`)
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// jwtIOSignature is the signature of jwt.io's documentation token.
const jwtIOSignature = `\.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c$`

var jwtShape = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$`)

// decodeBase64JWT is the JWT a base64 text holds (a trailing line break
// dropped), or nothing.
func decodeBase64JWT(secret []byte) []byte {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(string(secret), "="))
	if err != nil {
		return nil
	}
	if raw = bytes.TrimRight(raw, "\r\n"); !jwtShape.Match(raw) {
		return nil
	}
	return raw
}

// jwtCheck: the first part of a JWT is a JSON object with "alg", and the
// signature is not a word: a signature shorter than 43 characters (32 bytes,
// HS256) of letters only. A cut real one (a line break in it) still counts.
func jwtCheck(secret []byte) bool {
	if sig := secret[bytes.LastIndexByte(secret, '.')+1:]; len(sig) > 0 && len(sig) < 43 && !bytes.ContainsFunc(sig, func(r rune) bool {
		return r < 'A' || r > 'Z' && r < 'a' || r > 'z'
	}) {
		return false
	}
	head, _, _ := strings.Cut(string(secret), ".")
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return false
	}
	var header map[string]any
	if json.Unmarshal(raw, &header) != nil {
		return false
	}
	_, ok := header["alg"]
	return ok
}

// BuiltinRules returns a copy of the built-in rules, generic ones (DefaultOff)
// included. Choosing which to use is up to the caller.
func BuiltinRules() []Rule {
	rules := make([]Rule, len(builtinRules))
	for i, r := range builtinRules {
		r.Keywords = slices.Clone(r.Keywords)
		r.Allowlist = append(slices.Clone(placeholders), r.Allowlist...)
		rules[i] = r
	}
	return rules
}

// RuleByID returns the built-in rule with that ID.
func RuleByID(id string) (Rule, bool) {
	for _, r := range BuiltinRules() {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
