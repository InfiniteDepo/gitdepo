// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// NOTICE: the rules below are adapted from gitleaks v8.30.1,
// cmd/generate/config/rules (https://github.com/gitleaks/gitleaks/tree/v8.30.1),
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
// Changes: boundaries are TokenChars instead of \b, prefixes are matched in
// their real case, rules that start with their keyword run anchored on its
// hits and keyword rules in windows, entropy minimums are gitleaks' or higher,
// families with one shape share a rule (digitalocean-token, huggingface-token,
// vault-token, anthropic-api-key), the keyword forms of two rules have IDs of
// their own (atlassian-api-token-legacy, sonar-api-token-legacy), the
// kubernetes and curl rules have one
// secret group (kubernetes: the value, not stopping past a YAML document
// break), a short-lived Bedrock key needs 100 bytes after its prefix, and the
// legacy Vault s. form and the bare 40 hex Sourcegraph form are left out.
// Tokens longer than their window (8 KiB for Bedrock short-lived, Fly.io and
// 1Password service accounts) are not reported.
// docker-hub-token, circleci-personal-token and buildkite-api-token are our
// own (token formats from the vendors' documentation).
// In rules_gitleaks_services.go also: gitleaks' rules of one shape share a
// rule (bittrex-api-key, planetscale-token, settlemint-access-token,
// shopify-token), stripe-access-token's prod keys are in stripe-live-key, the
// airtable personal access token and the facebook app token run on their own
// shape and near the word facebook, lob-api-key only where a live_ or test_
// value follows, the Flutterwave encryption key has its dash, hubspot-api-key
// needs a key name (hubspot_api_key, hubspot_token, hapikey: not a form ID)
// and ends at & or # too, trello-access-token also takes the 64-hex user token
// (as trufflehog), gitleaks' airtable-personnal-access-token is
// airtable-personal-access-token, and the
// public keys (flutterwave-public-key, lob-pub-api-key, mailgun-pub-key, the
// mapbox pk. token, new-relic-browser-api-token) and the bare numeric IDs
// (discord-client-id, asana-client-id) are left out. Public values a shape
// can't tell from a secret are still reported: Squarespace and Sendbird app
// IDs, a Discord app's public key (64 hex after discord), Algolia search-only
// keys.

package secretdetection

import (
	"bytes"
	"slices"
	"strings"
)

// assignRegex is gitleaks' keyword assignment: a name holding kw (case
// ignored), an assignment (=, :, ::=, =>, ?=, ||, a comma or an XML >), quotes,
// then the secret and a byte that ends it.
func assignRegex(kw, secret string) string {
	return `(?i:` + kw + `)[ \t\w.-]{0,20}[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(` + secret + `)(?:[\x60'"\s;]|\\[nr]|$)`
}

// assignWindow is the window of an assignRegex rule: the name, the assignment
// and the longest secret fit in it.
const assignWindow = 256

// A YAML line that is no document break (---), and the parts of a Kubernetes
// Secret: its kind line, and data: with the value of its first key (comments
// and a block scalar | or > allowed). The rules take any number of lines
// between kind and data, as far as the window reaches: a counted repeat of
// yamlLine ({0,30}) made RE2 track a thread per count, several seconds per
// MiB of kind: lines.
const (
	yamlLine  = `\n[ \t]*(?:[^-\s][^\n]*|-(?:[^-\n][^\n]*)?|--(?:[^-\n][^\n]*)?)?\r?`
	k8sKind   = `kind:[ \t]*["']?(?i:secret)["']?[ \t]*\r?`
	k8sData   = `data:[ \t]*\r?(?:\n[ \t]*#[^\n]*)*\n[ \t]*[\w.-]+:(?:[ \t]*[|>][-+]?[ \t]*\r?\n)?[ \t]*["']?([A-Za-z0-9+/]{10,}={0,3})`
	k8sWindow = 4096
	// k8sLookBack is the window of the data-first rule: kubectl prints data
	// (a TLS Secret's tls.crt and tls.key, or many keys) before kind.
	k8sLookBack = 16384
	curlPrefix  = `curl[^\r\n]*?(?:(?:\r?\n|\r)[^\r\n]*?){0,5}[ \t\r\n]`
	curlWindow  = 512
)

var gitleaksRules = []Rule{
	// AI and machine learning
	{
		ID: "openai-api-key", Name: "OpenAI API key", Type: "openai",
		Keywords:    []string{"t3blbkfj"},
		Regex:       `(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 100,
	},
	{
		ID: "anthropic-api-key", Name: "Anthropic API key", Type: "anthropic",
		Keywords:    []string{"sk-ant-api03-", "sk-ant-admin01-"},
		Regex:       `(sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA)`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 128, Anchored: true, HitCheck: prefixHit(108, "sk-ant-api03-", "sk-ant-admin01-"),
	},
	{
		// hf_ user and api_org_ organization tokens: 34 letters.
		ID: "huggingface-token", Name: "Hugging Face access token", Type: "huggingface",
		Keywords:    []string{"hf_", "api_org_"},
		Regex:       `((?:hf|api_org)_[A-Za-z]{34})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars + "_", Window: 48, Anchored: true, HitCheck: prefixHit(37, "hf_", "api_org_"),
	},
	{
		ID: "perplexity-api-key", Name: "Perplexity API key", Type: "perplexity",
		Keywords:    []string{"pplx-"},
		Regex:       `(pplx-[A-Za-z0-9]{48})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars, Window: 56, Anchored: true, HitCheck: prefixHit(53, "pplx-"),
	},
	{
		ID: "cohere-api-token", Name: "Cohere API key", Type: "cohere",
		Keywords:    []string{"cohere", "co_api_key"},
		Regex:       assignRegex(`cohere|co_api_key`, `[A-Za-z0-9]{40}`),
		SecretGroup: 1, MinEntropy: 4, Window: assignWindow,
	},
	{
		ID: "privateai-api-token", Name: "Private AI API key", Type: "privateai",
		Keywords:    []string{"privateai", "private_ai", "private-ai"},
		Regex:       assignRegex(`private[_-]?ai`, `[a-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "aws-amazon-bedrock-api-key-long-lived", Name: "Amazon Bedrock API key", Type: "aws",
		Keywords:    []string{"absk"},
		Regex:       `(ABSK[A-Za-z0-9+/]{109,269}={0,2})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/", Window: 288, Anchored: true, HitCheck: prefixHit(113, "ABSK"),
	},
	{
		// base64 of a presigned bedrock.amazonaws.com URL, valid up to 12 hours
		ID: "aws-amazon-bedrock-api-key-short-lived", Name: "Amazon Bedrock short-lived API key", Type: "aws",
		Keywords:    []string{"bedrock-api-key-"},
		Regex:       `(bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/]{100,}={0,2})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/", MaxSecretLen: 8 << 10, Window: 8192, Anchored: true, HitCheck: prefixHit(144, "bedrock-api-key-"),
	},

	// Package registries and build
	{
		ID: "npm-access-token", Name: "npm access token", Type: "npm",
		Keywords:    []string{"npm_"},
		Regex:       `(npm_[A-Za-z0-9]{36})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "_", Window: 48, Anchored: true, HitCheck: prefixHit(40, "npm_"),
	},
	{
		ID: "pypi-upload-token", Name: "PyPI upload token", Type: "pypi",
		Keywords:    []string{"pypi-ageichlwas5vcmc"},
		Regex:       `(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,1000})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 1024, Anchored: true, HitCheck: prefixHit(69, "pypi-AgEIcHlwaS5vcmc"),
	},
	{
		ID: "rubygems-api-token", Name: "RubyGems API key", Type: "rubygems",
		Keywords:    []string{"rubygems_"},
		Regex:       `(rubygems_[a-f0-9]{48})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 64, Anchored: true, HitCheck: prefixHit(57, "rubygems_"),
	},
	{
		ID: "nuget-config-password", Name: "NuGet feed password", Type: "nuget",
		Keywords:    []string{"<add key="},
		Regex:       `<add key="(?i:(?:cleartext)?password)"\s*value="([^"\r\n]{8,200})"\s*/>`,
		SecretGroup: 1, MinEntropy: 2, Window: 300, Anchored: true, HitCheck: prefixHit(0, `<add key="`),
		Allowlist: []string{`^33f!!lloppa$`, `^hal\+9ooo_da!sY$`, `^%\S.*%$`, `^\$\([\w.]+\)$`, `^#\{[^}]+\}#?$`},
	},
	{
		ID: "clojars-api-token", Name: "Clojars deploy token", Type: "clojars",
		Keywords:    []string{"clojars_"},
		Regex:       `(CLOJARS_[A-Za-z0-9]{60})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 72, Anchored: true, HitCheck: prefixHit(68, "CLOJARS_"),
	},
	{
		ID: "artifactory-api-key", Name: "JFrog Artifactory API key", Type: "jfrog",
		Keywords:    []string{"akcp"},
		Regex:       `(AKCp[A-Za-z0-9]{69})`,
		SecretGroup: 1, MinEntropy: 4.5, TokenChars: alnumChars, Window: 80, Anchored: true, HitCheck: prefixHit(73, "AKCp"),
	},
	{
		ID: "artifactory-reference-token", Name: "JFrog Artifactory reference token", Type: "jfrog",
		Keywords:    []string{"cmvmd"},
		Regex:       `(cmVmd[A-Za-z0-9]{59})`,
		SecretGroup: 1, MinEntropy: 4.5, TokenChars: alnumChars, Window: 72, Anchored: true, HitCheck: prefixHit(64, "cmVmd"),
	},
	{
		ID: "jfrog-api-key", Name: "JFrog API key", Type: "jfrog",
		Keywords:    []string{"jfrog", "artifactory", "bintray", "xray"},
		Regex:       assignRegex(`jfrog|artifactory|bintray|xray`, `[A-Za-z0-9]{73}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// A SHA-256 is 64 hex digits too: a checksum is no token.
		ID: "jfrog-identity-token", Name: "JFrog identity token", Type: "jfrog",
		Keywords:    []string{"jfrog", "artifactory", "bintray", "xray"},
		Regex:       assignRegex(`jfrog|artifactory|bintray|xray`, `[A-Za-z0-9]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
		Check: notHex,
	},
	{
		ID: "docker-hub-token", Name: "Docker Hub access token", Type: "docker",
		Keywords:    []string{"dckr_pat_", "dckr_oat_"},
		Regex:       `(dckr_pat_[A-Za-z0-9_-]{27}|dckr_oat_[A-Za-z0-9_-]{32})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 48, Anchored: true, HitCheck: prefixHit(36, "dckr_pat_", "dckr_oat_"),
	},

	// Cloud and infrastructure
	{
		ID: "digitalocean-token", Name: "DigitalOcean token", Type: "digitalocean",
		Keywords:    []string{"dop_v1_", "doo_v1_", "dor_v1_"},
		Regex:       `(do[opr]_v1_[a-f0-9]{64})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 80, Anchored: true, HitCheck: prefixHit(71, "dop_v1_", "doo_v1_", "dor_v1_"),
	},
	{
		// A UUID is also an app ID, so the name must say key, token, secret,
		// password or auth.
		ID: "heroku-api-key", Name: "Heroku API key", Type: "heroku",
		Keywords:    []string{"heroku"},
		Regex:       assignRegex(`heroku[\w.-]{0,20}?(?:key|token|secret|pass|auth)`, `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "heroku-api-key-v2", Name: "Heroku API key", Type: "heroku",
		Keywords:    []string{"hrku-aa"},
		Regex:       `(HRKU-AA[0-9A-Za-z_-]{58})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: wordChars, Window: 72, Anchored: true, HitCheck: prefixHit(65, "HRKU-AA"),
	},
	{
		ID: "flyio-access-token", Name: "Fly.io access token", Type: "flyio",
		Keywords:    []string{"fo1_", "fm1a_", "fm1r_", "fm2_"},
		Regex:       `(fo1_[\w-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars + "_", MaxSecretLen: 8 << 10, Window: 8192, Anchored: true, HitCheck: prefixHit(47, "fo1_", "fm1a_", "fm1r_", "fm2_"),
	},
	{
		ID: "netlify-access-token", Name: "Netlify access token", Type: "netlify",
		Keywords:    []string{"netlify"},
		Regex:       assignRegex(`netlify`, `[A-Za-z0-9=_-]{40,46}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "cloudflare-api-key", Name: "Cloudflare API token", Type: "cloudflare",
		Keywords:    []string{"cloudflare"},
		Regex:       assignRegex(`cloudflare`, `[A-Za-z0-9_-]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow, Check: notHex,
	},
	{
		ID: "cloudflare-global-api-key", Name: "Cloudflare global API key", Type: "cloudflare",
		Keywords:    []string{"cloudflare"},
		Regex:       assignRegex(`cloudflare`, `[a-f0-9]{37}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "cloudflare-origin-ca-key", Name: "Cloudflare Origin CA key", Type: "cloudflare",
		Keywords:    []string{"v1.0-"},
		Regex:       `(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 180, Anchored: true, HitCheck: prefixHit(176, "v1.0-"),
	},
	{
		ID: "alibaba-access-key-id", Name: "Alibaba Cloud AccessKey ID", Type: "alibaba",
		Keywords:    []string{"ltai"},
		Regex:       `(LTAI[A-Za-z0-9]{20})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 32, Anchored: true, HitCheck: prefixHit(24, "LTAI"),
	},
	{
		ID: "alibaba-secret-key", Name: "Alibaba Cloud AccessKey secret", Type: "alibaba",
		Keywords:    []string{"alibaba"},
		Regex:       assignRegex(`alibaba`, `[A-Za-z0-9]{30}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "hashicorp-tf-api-token", Name: "Terraform Cloud API token", Type: "hashicorp",
		Keywords:    []string{"atlasv1"},
		Regex:       `([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: wordChars, Window: 100,
	},
	{
		// hvs. service and hvb. batch tokens; the legacy s. form is too
		// common a prefix to match on its own.
		ID: "vault-token", Name: "HashiCorp Vault token", Type: "hashicorp",
		Keywords:    []string{"hvs.", "hvb."},
		Regex:       `(hvs\.[\w-]{90,120}|hvb\.[\w-]{138,300})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: wordChars, Window: 310, Anchored: true, HitCheck: prefixHit(94, "hvs.", "hvb."),
	},
	{
		ID: "pulumi-api-token", Name: "Pulumi access token", Type: "pulumi",
		Keywords:    []string{"pul-"},
		Regex:       `(pul-[a-f0-9]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(44, "pul-"),
	},
	{
		ID: "doppler-api-token", Name: "Doppler personal token", Type: "doppler",
		Keywords:    []string{"dp.pt."},
		Regex:       `(dp\.pt\.[A-Za-z0-9]{43})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 56, Anchored: true, HitCheck: prefixHit(49, "dp.pt."),
	},
	{
		ID: "1password-secret-key", Name: "1Password secret key", Type: "1password",
		Keywords:    []string{"a3-"},
		Regex:       `(A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})`,
		SecretGroup: 1, MinEntropy: 3.8, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(39, "A3-"),
	},
	{
		ID: "1password-service-account-token", Name: "1Password service account token", Type: "1password",
		Keywords:    []string{"ops_eyj"},
		Regex:       `(ops_eyJ[A-Za-z0-9+/]{250,}={0,3})`,
		SecretGroup: 1, MinEntropy: 4, TokenChars: alnumChars + "+/", MaxSecretLen: 8 << 10, Window: 8192, Anchored: true, HitCheck: prefixHit(257, "ops_eyJ"),
	},
	{
		// The value of the first key under data: of a Secret, kind first; the
		// next rule is the same with data first (kubectl's alphabetical order).
		// Not found by either: a blank line right after data:, or a - data:
		// list item.
		ID: "kubernetes-secret-yaml", Name: "Kubernetes Secret data", Type: "kubernetes",
		Keywords:    []string{"kind:"},
		Regex:       k8sKind + `(?:` + yamlLine + `)*?\n[ \t]*` + k8sData,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/=", MaxSecretLen: k8sWindow, Window: k8sWindow,
	},
	{
		ID: "kubernetes-secret-yaml-data-first", Name: "Kubernetes Secret data (data before kind)", Type: "kubernetes", ReportAs: "kubernetes-secret-yaml",
		Keywords: []string{"kind:"},
		// data: must follow a newline, so a data: at the start of a file (or
		// after a BOM) is missed: \A would also match at the start of the
		// window, in the middle of a line such as metadata:.
		Regex:       `\n[ \t]*` + k8sData + `["']?[ \t]*\r?(?:` + yamlLine + `)*?\n[ \t]*` + k8sKind + `(?:\n|\z)`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "+/=", MaxSecretLen: k8sLookBack, Window: k8sLookBack,
	},
	{
		ID: "databricks-api-token", Name: "Databricks API token", Type: "databricks",
		Keywords:    []string{"dapi"},
		Regex:       `(dapi[a-f0-9]{32}(?:-\d)?)`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(36, "dapi"),
	},
	{
		ID: "openshift-user-token", Name: "OpenShift user token", Type: "openshift",
		Keywords:    []string{"sha256~"},
		Regex:       `(sha256~[\w-]{43})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: wordChars, Window: 56, Anchored: true, HitCheck: prefixHit(50, "sha256~"),
	},
	{
		ID: "scalingo-api-token", Name: "Scalingo API token", Type: "scalingo",
		Keywords:    []string{"tk-us-"},
		Regex:       `(tk-us-[\w-]{48})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 56, Anchored: true, HitCheck: prefixHit(54, "tk-us-"),
	},
	{
		// "." is a token byte: not a file name (favicon.ico-<hash>.png)
		ID: "infracost-api-token", Name: "Infracost API key", Type: "infracost",
		Keywords:    []string{"ico-"},
		Regex:       `(ico-[A-Za-z0-9]{32})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + ".", Window: 40, Anchored: true, HitCheck: prefixHit(36, "ico-"),
	},
	{
		ID: "prefect-api-token", Name: "Prefect API key", Type: "prefect",
		Keywords:    []string{"pnu_"},
		Regex:       `(pnu_[A-Za-z0-9]{36})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(40, "pnu_"),
	},
	{
		ID: "defined-networking-api-token", Name: "Defined Networking API key", Type: "defined-networking",
		Keywords:    []string{"dnkey-"},
		Regex:       `(dnkey-[A-Za-z0-9=_-]{26}-[A-Za-z0-9=_-]{52})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: wordChars, Window: 90, Anchored: true, HitCheck: prefixHit(85, "dnkey-"),
	},

	// Version control and CI
	{
		ID: "bitbucket-client-id", Name: "Bitbucket OAuth client ID", Type: "bitbucket",
		Keywords:    []string{"bitbucket"},
		Regex:       assignRegex(`bitbucket`, `[A-Za-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow, Check: notHex,
	},
	{
		ID: "bitbucket-client-secret", Name: "Bitbucket OAuth client secret", Type: "bitbucket",
		Keywords:    []string{"bitbucket"},
		Regex:       assignRegex(`bitbucket`, `[A-Za-z0-9=_-]{64}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "atlassian-api-token", Name: "Atlassian API token", Type: "atlassian",
		Keywords:    []string{"atatt3"},
		Regex:       `(ATATT3[A-Za-z0-9_=-]{186})`,
		SecretGroup: 1, MinEntropy: 3.5, TokenChars: wordChars, Window: 200, Anchored: true, HitCheck: prefixHit(192, "ATATT3"),
	},
	{
		// The 24 character tokens had no prefix: after an atlassian, jira or
		// confluence name.
		ID: "atlassian-api-token-legacy", Name: "Atlassian API token (24 characters)", Type: "atlassian",
		Keywords:    []string{"atlassian", "confluence", "jira"},
		Regex:       assignRegex(`atlassian|confluence|jira`, `[A-Za-z0-9]{20}[a-fA-F0-9]{4}`),
		SecretGroup: 1, MinEntropy: 3.5, Window: assignWindow,
	},
	{
		ID: "gitlab-session-cookie", Name: "GitLab session cookie", Type: "gitlab",
		Keywords:    []string{"_gitlab_session="},
		Regex:       `_gitlab_session=([0-9a-z]{32})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 56, Anchored: true, HitCheck: prefixHit(48, "_gitlab_session="),
	},
	{
		ID: "codecov-access-token", Name: "Codecov access token", Type: "codecov",
		Keywords:    []string{"codecov"},
		Regex:       assignRegex(`codecov`, `[A-Za-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "travisci-access-token", Name: "Travis CI access token", Type: "travisci",
		Keywords:    []string{"travis"},
		Regex:       assignRegex(`travis`, `[A-Za-z0-9]{22}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		// squ_ user, sqp_ project and sqa_ global analysis tokens.
		ID: "sonar-api-token", Name: "SonarQube token", Type: "sonar",
		Keywords:    []string{"squ_", "sqp_", "sqa_"},
		Regex:       `(sq[upa]_[a-f0-9]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(44, "squ_", "sqp_", "sqa_"),
	},
	{
		ID: "sonar-api-token-legacy", Name: "SonarQube token (40 characters)", Type: "sonar",
		Keywords:    []string{"sonar"},
		Regex:       assignRegex(`sonar[_.-]?(?:login|token)`, `[A-Za-z0-9=_-]{40}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "droneci-access-token", Name: "Drone CI access token", Type: "droneci",
		Keywords:    []string{"droneci"},
		Regex:       assignRegex(`droneci`, `[A-Za-z0-9]{32}`),
		SecretGroup: 1, MinEntropy: 3, Window: assignWindow,
	},
	{
		ID: "sourcegraph-access-token", Name: "Sourcegraph access token", Type: "sourcegraph",
		Keywords:    []string{"sgp_"},
		Regex:       `(sgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 72, Anchored: true, HitCheck: prefixHit(44, "sgp_"),
	},
	{
		ID: "harness-api-key", Name: "Harness API key", Type: "harness",
		Keywords:    []string{"pat.", "sat."},
		Regex:       `((?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 80,
	},
	{
		ID: "octopus-deploy-api-key", Name: "Octopus Deploy API key", Type: "octopus-deploy",
		Keywords:    []string{"api-"},
		Regex:       `(API-[A-Z0-9]{26})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars + "-", Window: 32, Anchored: true, HitCheck: prefixHit(30, "API-"),
	},
	{
		ID: "circleci-personal-token", Name: "CircleCI personal API token", Type: "circleci",
		Keywords:    []string{"ccipat_"},
		Regex:       `(CCIPAT_[A-Za-z0-9]{22}_[a-fA-F0-9]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 72, Anchored: true, HitCheck: prefixHit(70, "CCIPAT_"),
	},
	{
		ID: "buildkite-api-token", Name: "Buildkite API access token", Type: "buildkite",
		Keywords:    []string{"bkua_"},
		Regex:       `(bkua_[a-z0-9]{40})`,
		SecretGroup: 1, MinEntropy: 3, TokenChars: alnumChars, Window: 48, Anchored: true, HitCheck: prefixHit(45, "bkua_"),
	},
}

// Credentials in curl commands (up to five continued lines after curl).
// curlHeaderRules run after all specific rules, so a known token in a header
// is reported as that token; curlUserRules run before the service rules,
// because the user:password pair holds the secret (Twilio's -u SK…:secret,
// where the SK… ID alone would hide the secret).
var curlHeaderRules = []Rule{
	{
		ID: "curl-auth-header", Name: "Credential in a curl header", Type: "curl",
		Keywords: []string{"curl"},
		Regex: curlPrefix + `(?:-H|--header)(?:=|[ \t]{0,5})["'](?i:authorization:[ \t]{0,5}(?:(?:basic|bearer|(?:api-)?token)[ \t]+)?|(?:x-(?:[a-z]+-)?)?(?:api-?)?(?:key|token):[ \t]{0,5})` +
			`([\w=~@.+/-]{8,})["']`,
		SecretGroup: 1, MinEntropy: 2.75, Window: curlWindow, Anchored: true, HitCheck: curlHeaderHit,
		Allowlist: []string{
			`(?i)^(?:your|my)[_-]`, `(?i)[_-]here$`, `^(?:[A-Z]+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)$`, `\.\.\.`, `(?i)redacted`,
			`(?i)^(?:access|api|auth|my|replace[_-]with)[._-]?(?:api[._-]?)?(?:jwt[._-]?)?(?:key|token)(?:[._-]?here)?$`, `(?i)^token\d*$`,
		},
	},
}

var curlUserRules = []Rule{
	{
		ID: "curl-auth-user", Name: "Password in a curl command", Type: "curl",
		Keywords: []string{"curl"},
		Regex: curlPrefix + `(?:-u|--user)(?:=|[ \t]{0,5})["']?` +
			`("[^"\r\n:]{3,}:[^"\r\n]{3,}"|(?:"[^"\r\n:]{3,}"|'[^'\r\n:]{3,}'|[^\s"':]{3,}):(?:"[^"\r\n]{3,}"|'[^'\r\n]{3,}'|[^\s"']{3,}))["']?(?:\s|\z)`,
		SecretGroup: 1, MinEntropy: 2, Window: curlWindow, Anchored: true, HitCheck: curlUserHit, Check: userIsNotPassword,
		Allowlist: []string{
			`^['"]?[^:'"]+['"]?:['"]?(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\*+|x+)['"]?$`,
			`['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?`,
			`^['"]?[^:'"]+['"]?:['"]?\[[^]]+]['"]?$`,
			`:['"]?(?:%\w+%|\{[A-Za-z_]+\})['"]?$`,
			`:['"]?\$\(`,
			`['"]?[^:]+['"]?:['"]?\$(?:\d|\w+|\{(?:\d|\w+)})['"]?`,
			`^['"]?\$`,
		},
	},
}

// curlHeaderHit and curlUserHit: the word curl, as written in a shell, and
// in the bytes after it the option with a value of the rule's shape, so curl
// commands without a literal credential ($TOKEN, <token>) cost no regex run.
func curlHeaderHit(lower, c []byte, p int) bool {
	after, ok := curlAfter(lower, c, p)
	if !ok {
		return false
	}
	isValue := func(b byte) bool { return isWord(b) || strings.IndexByte("=~@.+/-", b) >= 0 }
	for _, name := range []string{"authorization:", "key:", "token:"} {
		for off := 0; ; {
			i := bytes.Index(after[off:], []byte(name))
			if i < 0 {
				break
			}
			i += off
			off = i + 1
			if !bytes.Contains(after[:i], []byte("-h")) {
				continue
			}
			j := skipBlanks(after, i+len(name))
			for _, scheme := range []string{"basic", "bearer", "api-token", "token"} {
				if bytes.HasPrefix(after[j:], []byte(scheme)) && j+len(scheme) < len(after) && isBlank(after[j+len(scheme)]) {
					j = skipBlanks(after, j+len(scheme))
					break
				}
			}
			if run(after, j, 8, isValue) >= 8 {
				return true
			}
		}
	}
	return false
}

func curlUserHit(lower, c []byte, p int) bool {
	after, ok := curlAfter(lower, c, p)
	if !ok {
		return false
	}
	for off := 0; ; {
		i := bytes.Index(after[off:], []byte("-u"))
		if i < 0 {
			return false
		}
		off = i + off + 1
		j := off + 1
		if bytes.HasPrefix(after[j:], []byte("ser")) {
			j += 3
		}
		if j < len(after) && after[j] == '=' {
			j++
		}
		j = skipBlanks(after, j)
		if j < len(after) && isQuote(after[j]) {
			// a quoted user may hold blanks: 'deploy bot':pw or "deploy bot:pw"
			if k := bytes.IndexByte(after[j+1:], after[j]); k >= 3 && (j+k+2 < len(after) && after[j+k+2] == ':' || bytes.IndexByte(after[j+1:j+1+k], ':') >= 3) {
				return true
			}
		}
		field := after[j:]
		if k := bytes.IndexAny(field, " \t\r\n"); k >= 0 {
			field = field[:k]
		}
		if bytes.IndexByte(field, ':') >= 3 {
			return true
		}
	}
}

// curlAfter is the window after the word curl at p, if it is the word.
func curlAfter(lower, c []byte, p int) ([]byte, bool) {
	if string(c[p:min(len(c), p+4)]) != "curl" || p > 0 && isWord(c[p-1]) || p+4 < len(c) && isWord(c[p+4]) {
		return nil, false
	}
	return lower[p+4 : min(len(lower), p+4+curlWindow)], true
}

func skipBlanks(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return i
}

// prefixHit: the hit is one of prefixes in its real case (keywords are found
// in lowercase) with at least n token bytes from it on, so a keyword without
// a token after it costs no regex run.
func prefixHit(n int, prefixes ...string) func(_, c []byte, p int) bool {
	return func(_, c []byte, p int) bool {
		return slices.ContainsFunc(prefixes, func(s string) bool { return bytes.HasPrefix(c[p:], []byte(s)) }) &&
			run(c, p, n, isTokenByte) >= n
	}
}

func isTokenByte(b byte) bool { return isB64(b) || b == '_' || b == '-' || b == '.' || b == '~' }

// notHex: the secret is not all hex digits (a checksum or commit ID has the
// shape of these tokens).
func notHex(s []byte) bool { return strings.Trim(strings.ToLower(string(s)), "0123456789abcdef") != "" }

// userIsNotPassword: user:password with the same word twice (admin:admin) is
// a default in documentation, not a credential.
func userIsNotPassword(s []byte) bool {
	user, pw, _ := strings.Cut(string(s), ":")
	return strings.Trim(user, `"'`) != strings.Trim(pw, `"'`)
}
