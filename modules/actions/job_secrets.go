// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"strings"

	"github.com/rhysd/actionlint"
	"go.yaml.in/yaml/v3"
)

// ReferencedSecrets reads the payload of a job, the yaml the runner gets, and returns the names (upper case) of the
// secrets it reads by a literal name: `secrets.NAME` and `secrets['NAME']` in an `${{ }}` expression. dynamic is true
// when it reads secrets in any way that can't be resolved here (`toJSON(secrets)`, `secrets[expr]`, `secrets.*`, `secrets`
// passed to a function) or hands them on (`secrets: inherit`), or when an expression that mentions secrets can't be
// parsed: such a job can reach any secret it is given, so the caller gives it no environment secrets at all.
func ReferencedSecrets(payload []byte) (names []string, dynamic bool, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return nil, false, err
	}
	found := map[string]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.ScalarNode:
			if secretsOfExpressions(n.Value, found) {
				dynamic = true
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k, v := n.Content[i], n.Content[i+1]; k.Value == "secrets" && v.Kind == yaml.ScalarNode && v.Value == "inherit" {
					dynamic = true
				}
				walk(n.Content[i])
				walk(n.Content[i+1])
			}
		case yaml.SequenceNode, yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c)
			}
		}
		// an alias points at a node that was walked where it is anchored
	}
	walk(&doc)
	for name := range found {
		names = append(names, name)
	}
	return names, dynamic, nil
}

// secretsOfExpressions adds the literal secret names the `${{ }}` expressions of s read to found, and reports if one
// reads secrets in another way.
func secretsOfExpressions(s string, found map[string]bool) (dynamic bool) {
	for {
		_, rest, ok := strings.Cut(s, "${{")
		if !ok {
			return dynamic
		}
		lex := actionlint.NewExprLexer(rest)
		root, perr := actionlint.NewExprParser().Parse(lex)
		if perr != nil {
			// not an expression the runner can evaluate either; stay safe if it mentions secrets at all
			return dynamic || strings.Contains(strings.ToLower(rest), "secrets")
		}
		actionlint.VisitExprNode(root, func(n, parent actionlint.ExprNode, entering bool) {
			v, isVar := n.(*actionlint.VariableNode)
			if !entering || !isVar || !strings.EqualFold(v.Name, "secrets") {
				return
			}
			switch p := parent.(type) {
			case *actionlint.ObjectDerefNode:
				found[strings.ToUpper(p.Property)] = true
			case *actionlint.IndexAccessNode:
				if lit, ok := p.Index.(*actionlint.StringNode); ok && p.Operand == n {
					found[strings.ToUpper(lit.Value)] = true
					return
				}
				dynamic = true
			default:
				dynamic = true
			}
		})
		s = rest[lex.Offset():]
	}
}
