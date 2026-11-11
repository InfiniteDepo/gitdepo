// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package glob matches glob patterns in linear time: a pattern is compiled to a Go regular expression (RE2), whose
// time grows linearly with the name. Patterns are matched against the whole name, case-sensitively.
//
// Pattern syntax, which is the one users see for branch protection rules and branch-name exceptions (CompileExact):
//   - `*` matches any run of characters except the separator (`/`), `?` one such character.
//   - `**` matches any run of characters, separators included. As a whole path segment it needs the segments around
//     it: `**/x` matches `a/x` but not `x`, and `a/**/b` matches `a/x/b`. A trailing `/**` matches everything below.
//   - `[abc]` and `[a-c]` match one character in the set, `[!abc]` one character not in it.
//   - `{a,b}` matches either alternative, which may hold other patterns; `{}` matches nothing.
//   - `\c` matches the character c, so `\*` is a literal star.
//
// Compile differs in one rule, kept for the approval-rule patterns: `**` as a whole path segment also matches no
// directory, so `**/x` matches `x` and `a/**/b` matches `a/b`.
package glob

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gobwas/glob/syntax"
	"github.com/gobwas/glob/syntax/ast"
)

// Compile compiles a gobwas glob pattern with the separators to an anchored regular expression: `*` matches any
// run of non-separators, `**` anything (a leading `**/` and `/**/` also nothing, so that `a/**/b` matches `a/b`
// and `**/x` matches `x`; a trailing `/**` matches everything below), `?` one non-separator, `{a,b}` either pattern, `[abc]`, `[!abc]` and `[a-z]`
// one character in (or not in) the class, separators included, and `\c` the character c.
func Compile(pattern string, separators ...rune) (*regexp.Regexp, error) {
	return compile(pattern, false, separators)
}

// CompileExact is Compile for the patterns gobwas decides itself: a leading `**/` needs a directory (`**/x` doesn't
// match `x`), `{}` (and an unclosed `{`) matches nothing, and `**` matches no directory only in `prefix/**/suffix` made of plain text
// (gobwas lets the two overlap on the `/`), so `src/**/*.go` doesn't match `src/x.go` but `release/**/hotfix` matches
// `release/hotfix`. Branch protection rules and branch-name exceptions use it, because a broader match would let the
// first matching rule shadow a stricter one.
func CompileExact(pattern string, separators ...rune) (*regexp.Regexp, error) {
	return compile(pattern, true, separators)
}

func compile(pattern string, exact bool, separators []rune) (*regexp.Regexp, error) {
	tree, err := syntax.Parse(pattern)
	if err != nil {
		return nil, err
	}
	nonSep := `(?s:.)`
	if len(separators) > 0 {
		nonSep = `[^` + class(string(separators)) + `]`
	}
	var b strings.Builder
	b.WriteString(`\A(?:`)
	if err := write(&b, tree, nonSep, exact); err != nil {
		return nil, err
	}
	b.WriteString(`)\z`)
	return regexp.Compile(b.String())
}

// class returns the runes of s escaped for a character class.
func class(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\x{%x}`, r)
	}
	return b.String()
}

func write(b *strings.Builder, n *ast.Node, nonSep string, exact bool) error {
	switch n.Kind {
	case ast.KindPattern:
		segmentStart := n.Parent == nil // the start of the whole pattern starts a path segment
		for i := 0; i < len(n.Children); i++ {
			c := n.Children[i]
			// `**` as a whole path segment matches zero or more directories, as in gitignore and CODEOWNERS: a
			// leading `**/` and `/**/` also match no directory at all
			if (!exact || plainSandwich(n)) && c.Kind == ast.KindSuper && segmentStart && i+1 < len(n.Children) && n.Children[i+1].Kind == ast.KindText {
				if rest, ok := strings.CutPrefix(n.Children[i+1].Value.(ast.Text).Text, "/"); ok {
					b.WriteString(`(?:(?s:.*)/)?` + regexp.QuoteMeta(rest))
					segmentStart = strings.HasSuffix(rest, "/")
					i++
					continue
				}
			}
			if err := write(b, c, nonSep, exact); err != nil {
				return err
			}
			segmentStart = c.Kind == ast.KindText && strings.HasSuffix(c.Value.(ast.Text).Text, "/")
		}
	case ast.KindAnyOf:
		if len(n.Children) == 1 && len(n.Children[0].Children) == 0 { // `{}`
			b.WriteString(`[^\x00-\x{10FFFF}]`) // matches nothing
		}
		b.WriteString(`(?:`)
		for i, c := range n.Children {
			if i > 0 {
				b.WriteByte('|')
			}
			if err := write(b, c, nonSep, exact); err != nil {
				return err
			}
		}
		b.WriteByte(')')
	case ast.KindText:
		b.WriteString(regexp.QuoteMeta(n.Value.(ast.Text).Text))
	case ast.KindAny:
		b.WriteString(nonSep + `*`)
	case ast.KindSuper:
		b.WriteString(`(?s:.*)`)
	case ast.KindSingle:
		b.WriteString(nonSep)
	case ast.KindList:
		l := n.Value.(ast.List)
		writeClass(b, l.Not, class(l.Chars))
	case ast.KindRange:
		r := n.Value.(ast.Range)
		writeClass(b, r.Not, class(string(r.Lo))+`-`+class(string(r.Hi)))
	default:
		return fmt.Errorf("unexpected glob node %s", n.Kind)
	}
	return nil
}

func writeClass(b *strings.Builder, not bool, chars string) {
	if not {
		b.WriteString(`[^` + chars + `]`)
	} else {
		b.WriteString(`[` + chars + `]`)
	}
}

// plainSandwich reports whether n is plain text, `**`, plain text, the shape gobwas matches with overlapping ends.
func plainSandwich(n *ast.Node) bool {
	c := n.Children
	return n.Parent == nil && len(c) == 3 && c[0].Kind == ast.KindText && c[1].Kind == ast.KindSuper && c[2].Kind == ast.KindText
}
