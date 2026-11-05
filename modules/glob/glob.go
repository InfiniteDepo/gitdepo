// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package glob matches glob patterns in linear time. A pattern means what it means to github.com/gobwas/glob,
// whose parser it uses, except that `**` as a whole path segment also matches no directory, but it is matched by a Go regular expression (RE2), whose time grows linearly with the
// name, where gobwas tries every split of the name between the wildcards.
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
	if err := write(&b, tree, nonSep); err != nil {
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

func write(b *strings.Builder, n *ast.Node, nonSep string) error {
	switch n.Kind {
	case ast.KindPattern:
		segmentStart := n.Parent == nil // the start of the whole pattern starts a path segment
		for i := 0; i < len(n.Children); i++ {
			c := n.Children[i]
			// `**` as a whole path segment matches zero or more directories, as in gitignore and CODEOWNERS: a
			// leading `**/` and `/**/` also match no directory at all
			if c.Kind == ast.KindSuper && segmentStart && i+1 < len(n.Children) && n.Children[i+1].Kind == ast.KindText {
				if rest, ok := strings.CutPrefix(n.Children[i+1].Value.(ast.Text).Text, "/"); ok {
					b.WriteString(`(?:(?s:.*)/)?` + regexp.QuoteMeta(rest))
					segmentStart = strings.HasSuffix(rest, "/")
					i++
					continue
				}
			}
			if err := write(b, c, nonSep); err != nil {
				return err
			}
			segmentStart = c.Kind == ast.KindText && strings.HasSuffix(c.Value.(ast.Text).Text, "/")
		}
	case ast.KindAnyOf:
		b.WriteString(`(?:`)
		for i, c := range n.Children {
			if i > 0 {
				b.WriteByte('|')
			}
			if err := write(b, c, nonSep); err != nil {
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
