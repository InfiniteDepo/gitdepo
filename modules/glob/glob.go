// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// Package glob matches glob patterns in linear time. A pattern means what it means to github.com/gobwas/glob,
// whose parser it uses, but it is matched by a Go regular expression (RE2), whose time grows linearly with the
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
// run of non-separators, `**` anything, `?` one non-separator, `{a,b}` either pattern, `[abc]`, `[!abc]` and `[a-z]`
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
		for _, c := range n.Children {
			if err := write(b, c, nonSep); err != nil {
				return err
			}
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
