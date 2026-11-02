// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package dependency

import (
	"regexp"
	"strings"
)

// The line grammar of the YAML lock files (pnpm-lock.yaml, yarn.lock). They are read line by line, so a reader is
// only safe if it is no wider than what the tools write: every line of a file (in every section, also the ones
// that are not interpreted) must fully match one of the anchored patterns below, and anything else is a parse error.
// The patterns are kept here, in one place, to be audited against the writers:
//   - pnpm: js-yaml's dump (block style, 2 spaces, flow only for one-line maps and sequences of scalars, single
//     quotes where a plain scalar won't do, `? key` / `: value` for keys over 1024 characters);
//   - yarn berry: stringifySyml of @yarnpkg/parsers (a scalar is plain if it matches its simpleStringPattern, else
//     JSON.stringify'd; no flow collections; `? key` / `:` for keys over 1024 characters);
//   - yarn v1: the lockfile stringify of yarn 1 (`key value`, `key:` for a nested map, a key or value is wrapped in
//     double quotes unless it starts with a letter and has no `:`, white space, `\`, `"`, `,`, `[` or `]`).
//
// Every scalar is complete on its line. A double-quoted scalar has no backslash (YAML would decode an escape, the
// reader doesn't), a single-quoted one only `''` inside.

const (
	// yPlainFirst: a plain scalar starts with none of YAML's indicators `- ? : , [ ] { } # & * ! | > ' " % @ `
	yPlainFirst = `[^-?:,\[\]{}#&*!|>'"%@` + "`" + ` ]`
	// yPlain: words separated by spaces; no word ends with `:` (no `: ` and no trailing `:`), a later word doesn't
	// start with `#` (no ` #`), and no trailing space
	yPlain = `(?:` + yPlainFirst + `|` + yPlainFirst + `[^ ]*[^ :])(?: +(?:[^ :#]|[^ #][^ ]*[^ :]))*`
	// yFlowPlain: yPlain inside a flow collection, where `, [ ] { }` end a scalar
	yFlowPlain = `(?:` + yPlainFirst + `|` + yPlainFirst + `[^ ,\[\]{}]*[^ ,\[\]{}:])(?: +(?:[^ :#,\[\]{}]|[^ #,\[\]{}][^ ,\[\]{}]*[^ ,\[\]{}:]))*`
	ySingle    = `'(?:[^']|'')*'`
	yDouble    = `"[^"\\]*"`
	yScalar    = `(?:` + yPlain + `|` + ySingle + `|` + yDouble + `)`
	yFlowScal  = `(?:` + yFlowPlain + `|` + ySingle + `|` + yDouble + `)`
	// a flow collection on one line, as pnpm writes them: `{}`, `[]`, `{k: v, k: v}`, `[a, b]`, nothing nested
	yFlow  = `(?:\{(?:` + yFlowScal + `: ` + yFlowScal + `(?:, ` + yFlowScal + `: ` + yFlowScal + `)*)?\}|\[(?:` + yFlowScal + `(?:, ` + yFlowScal + `)*)?\])`
	yValue = `(?:` + yScalar + `|` + yFlow + `)`

	// yarn berry: simpleStringPattern (no `, [ ] { } : #` after the first character) or a JSON string
	bPlain  = yPlainFirst + `(?: *[^ ,\[\]{}:#])*`
	bScalar = `(?:` + bPlain + `|` + yDouble + `)`

	// yarn v1: a word that starts with a letter, or a JSON string
	v1Plain  = `[a-zA-Z][^:\s\\",\[\]]*`
	v1Scalar = `(?:` + v1Plain + `|` + yDouble + `)`
)

// The line forms, without the indentation.
var (
	pnpmPairRe    = regexp.MustCompile(`^(` + yScalar + `): (` + yValue + `)$`)             // key: value
	pnpmKeyRe     = regexp.MustCompile(`^(` + yScalar + `):$`)                              // key: (a map or sequence follows)
	pnpmItemRe    = regexp.MustCompile(`^- (` + yScalar + `)$`)                             // - scalar
	pnpmQKeyRe    = regexp.MustCompile(`^\? (` + yScalar + `)$`)                            // ? key (over 1024 characters)
	pnpmQValRe    = regexp.MustCompile(`^:(?: (` + yScalar + `):(?: (` + yValue + `))?)?$`) // its value: `:`, `: key:`, `: key: value`
	berryHeadRe   = regexp.MustCompile(`^(` + bScalar + `):$`)                              // "a@npm:^1, a@npm:^2":
	berryQKeyRe   = regexp.MustCompile(`^\? (` + bScalar + `)$`)                            // ? "header over 1024 characters", then `:`
	berryFieldRe  = regexp.MustCompile(`^(` + bPlain + `):(?: (` + bScalar + `))?$`)        // a field of an entry: plain key
	berryNestedRe = regexp.MustCompile(`^(` + bScalar + `):(?: (` + bScalar + `))?$`)       // deeper: `"@scope/a": "npm:^1"`
	v1HeadRe      = regexp.MustCompile(`^(` + v1Scalar + `(?:, ` + v1Scalar + `)*):$`)      // a@^1, "@s/b@^2":
	v1ScalarRe    = regexp.MustCompile(v1Scalar)                                            // one descriptor of a v1 header
	v1FieldRe     = regexp.MustCompile(`^(` + v1Scalar + `)(?::| (` + v1Scalar + `))$`)     // key value, or key:
	// a plain scalar js-yaml's default schema reads as something else than a string (null, bool, int, float,
	// timestamp, merge key), written loosely: refused where pnpm's value is read, since pnpm would see another text
	yTypedRe = regexp.MustCompile(`^(?:~|null|Null|NULL|true|True|TRUE|false|False|FALSE|<<|[-+]?[0-9_]+(?:\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|[-+]?\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?0[bB][01_]+|[-+]?0[xX][0-9a-fA-F_]+|[-+]?0[oO][0-7_]+|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}.*)$`)
)

// yamlBlock checks the indentation of block lines: 2 spaces a level, the line after a key line (`key:`) exactly
// one level deeper (a map or sequence follows; pnpm and yarn never write an empty value), and a line after one that
// ends with a value (`key: value`, `- item`) never deeper, since YAML would read it as a continuation of the value.
type yamlBlock struct {
	indent int
	open   bool
}

// line takes the next line; opens tells whether it is a key line. It reports whether the line's indentation is right.
func (b *yamlBlock) line(indent int, opens bool) bool {
	ok := indent%2 == 0 && (b.open && indent == b.indent+2 || !b.open && indent <= b.indent)
	b.indent, b.open = indent, opens
	return ok
}

// end reports whether the block may end here (not right after a key line).
func (b *yamlBlock) end() bool { return !b.open }

// unquoteYAML returns the text of a scalar that matched yScalar: a single-quoted scalar has two single quotes for
// one, a double-quoted one has no escape.
func unquoteYAML(s string) string {
	if len(s) >= 2 {
		switch s[0] {
		case '\'':
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		case '"':
			return s[1 : len(s)-1]
		}
	}
	return s
}

// plainTyped reports a plain scalar (one not quoted) that js-yaml would not read as a string.
func plainTyped(raw string) bool {
	return raw != "" && raw[0] != '\'' && raw[0] != '"' && yTypedRe.MatchString(raw)
}

// lineIndent splits a line into its indentation (spaces) and the rest.
func lineIndent(line string) (int, string) {
	t := strings.TrimLeft(line, " ")
	return len(line) - len(t), t
}
