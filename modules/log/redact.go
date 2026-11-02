// Copyright 2026 The gitdepo contributors.
// SPDX-License-Identifier: GPL-3.0-or-later

package log

import (
	"regexp"
	"slices"
	"strings"
	"sync"
)

const redacted = "[REDACTED]"

var (
	// header: the value runs to the end of the line or the closing quote of its JSON/quoted form
	redactHeader = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|set-cookie|cookie|x-api-key|api-key|x-license-key)(\\?["']?\s*[:=]\s*\\?["']?)(?:[^\r\n"'\\]|\\[^"'])*`)
	// "Bearer x" / "Basic x" / "token x": prose such as "basic settings" has only letters and is left alone
	redactScheme   = regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=-]{8,})`)
	redactUserinfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+):[^@/\s]+@`)
	// https://<token>@host
	redactUserToken = regexp.MustCompile(`(://)[^/\s@:]{8,}@`)
	redactShapes    = regexp.MustCompile(`\b(?:(?:gta|gto|gtr)_[A-Za-z0-9]{10,}|glpat-[A-Za-z0-9_-]{10,}|gh[pos]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|NRAK-[A-Z0-9]{10,}|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+)|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)

	// the regexes only run on input that contains one of these (the checks are linear and cheap)
	headerWords = []string{"authorization", "cookie", "api-key", "license-key"}
	schemeWords = []string{"bearer", "basic", "token"}
	shapeWords  = []string{"gta_", "gto_", "gtr_", "glpat-", "ghp_", "gho_", "ghs_", "github_pat_", "NRAK-", "xox", "eyJ", "PRIVATE KEY"}

	secretsMu sync.RWMutex
	secrets   []string
)

// A name is a secret name if it contains one of the long words (access_token, private_key, X-Amz-Signature, ...)
// or is, or ends in "_" / "-" plus, sig, code or pass (client-code, user_pass; not design or barcode).
var (
	secretWords  = []string{"token", "secret", "passw", "key", "cred", "auth", "session", "signature"}
	secretSuffix = []string{"sig", "code", "pass"}
)

// RegisterSecret makes Redact replace the literal value, e.g. a configured API key.
func RegisterSecret(s string) {
	if s == "" {
		return
	}
	secretsMu.Lock()
	defer secretsMu.Unlock()
	if !slices.Contains(secrets, s) {
		secrets = append(secrets, s)
	}
}

func redactLiterals(s string) string {
	secretsMu.RLock()
	defer secretsMu.RUnlock()
	for _, secret := range secrets {
		s = strings.ReplaceAll(s, secret, redacted)
	}
	return s
}

func isSecretName(name string) bool {
	name = strings.ToLower(name)
	for _, w := range secretWords {
		if strings.Contains(name, w) {
			return true
		}
	}
	for _, w := range secretSuffix {
		if name == w || strings.HasSuffix(name, "_"+w) || strings.HasSuffix(name, "-"+w) {
			return true
		}
	}
	return false
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

// redactPairs hides the value of name=value, "name":"value" (also backslash-escaped) and 'name': 'value' where the
// name is a secret name. A single linear scan: a regexp with an open-ended name prefix is far too slow on 1 MB input.
func redactPairs(s string) string {
	var out strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '=' && s[i] != ':' {
			continue
		}
		// find the end of the name: before optional spaces, and for ':' before the closing quote (and backslash)
		end := i
		for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
			end--
		}
		if s[i] == ':' {
			if end == 0 || (s[end-1] != '"' && s[end-1] != '\'') {
				continue
			}
			end--
			if end > 0 && s[end-1] == '\\' {
				end--
			}
		}
		start := end
		for start > 0 && isNameChar(s[start-1]) {
			start--
		}
		if start == end || !isSecretName(s[start:end]) {
			continue
		}
		// the value: after optional spaces, a backslash and a quote
		v := i + 1
		for v < len(s) && (s[v] == ' ' || s[v] == '\t') {
			v++
		}
		if v < len(s) && s[v] == '\\' && v+1 < len(s) && (s[v+1] == '"' || s[v+1] == '\'') {
			v++
		}
		if v < len(s) && (s[v] == '"' || s[v] == '\'') {
			v++
		}
		e := v
		for e < len(s) {
			c := s[e]
			if c == '\\' && e+1 < len(s) && s[e+1] != '"' && s[e+1] != '\'' {
				e += 2
				continue
			}
			if c == '&' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\'' || c == '<' || c == '>' ||
				c == ',' || c == ';' || c == ')' || c == '}' || c == '#' || c == '\\' {
				break
			}
			e++
		}
		if e == v || s[v:e] == redacted {
			continue
		}
		out.WriteString(s[last:v])
		out.WriteString(redacted)
		last = e
		i = e - 1
	}
	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// Redact hides credentials in free text, header lines and URLs. It is applied to the JSON log format only, after
// the caller cut the input to a size the cost of which is bounded.
func Redact(s string) string {
	s = redactLiterals(s)
	if containsAny(s, shapeWords) {
		s = redactShapes.ReplaceAllString(s, redacted)
	}
	lower := strings.ToLower(s)
	if containsAny(lower, headerWords) {
		s = redactHeader.ReplaceAllString(s, "${1}${2}"+redacted)
	}
	if containsAny(lower, schemeWords) {
		s = redactScheme.ReplaceAllStringFunc(s, func(m string) string {
			sub := redactScheme.FindStringSubmatch(m)
			if strings.Trim(sub[3], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
				return m
			}
			return sub[1] + sub[2] + redacted
		})
	}
	s = redactPairs(s)
	if strings.Contains(s, "://") && strings.Contains(s, "@") {
		s = redactUserinfo.ReplaceAllString(s, "${1}:"+redacted+"@")
		s = redactUserToken.ReplaceAllString(s, "${1}"+redacted+"@")
	}
	return s
}
