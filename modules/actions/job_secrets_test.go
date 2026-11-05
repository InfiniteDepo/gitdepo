// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReferencedSecrets(t *testing.T) {
	for name, tc := range map[string]struct {
		payload string
		names   []string
		dynamic bool
	}{
		"none":               {payload: "jobs:\n  a:\n    steps:\n      - run: echo hi\n"},
		"dot":                {payload: "jobs:\n  a:\n    steps:\n      - run: echo ${{ secrets.Deploy_Key }}\n", names: []string{"DEPLOY_KEY"}},
		"index":              {payload: "jobs:\n  a:\n    steps:\n      - run: echo ${{ secrets['TOKEN'] }}\n", names: []string{"TOKEN"}},
		"double quoted":      {payload: "jobs:\n  a:\n    steps:\n      - run: echo ${{ secrets[\"TOKEN\"] }}\n", dynamic: true}, // not valid in an expression
		"env":                {payload: "jobs:\n  a:\n    env:\n      X: ${{ secrets.A }}\n    steps:\n      - with:\n          y: x${{ secrets.B }}-${{ secrets.C || secrets.D }}\n", names: []string{"A", "B", "C", "D"}},
		"workflow env":       {payload: "env:\n  TOKEN: ${{ secrets.WF }}\njobs:\n  a:\n    steps: []\n", names: []string{"WF"}},
		"upper case":         {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ SECRETS.X }}\n", names: []string{"X"}},
		"another context":    {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ vars.secrets }} ${{ github.secrets.X }} ${{ env.SECRETS }}\n"},
		"toJSON":             {payload: "jobs:\n  a:\n    steps:\n      - run: echo '${{ toJSON(secrets) }}'\n", dynamic: true},
		"fromJSON toJSON":    {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ fromJSON(toJSON(secrets)).A }}\n", dynamic: true},
		"expression index":   {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ secrets[format('{0}', 'A')] }}\n", dynamic: true},
		"matrix index":       {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ secrets[matrix.name] }}\n", dynamic: true},
		"star":               {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ secrets.* }}\n", dynamic: true},
		"as an argument":     {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ contains(secrets, 'x') }}\n", dynamic: true},
		"literal and toJSON": {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ secrets.A }} ${{ toJSON(secrets) }}\n", names: []string{"A"}, dynamic: true},
		"inherit":            {payload: "jobs:\n  a:\n    uses: ./x.yml\n    secrets: inherit\n", dynamic: true},
		"inherit as text":    {payload: "jobs:\n  a:\n    steps:\n      - run: echo\n        env:\n          secrets: inherit-ish\n"},
		"bad expression":     {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ secrets.A + }}\n", dynamic: true},
		"bad without":        {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ github.sha + }}\n"},
		"key":                {payload: "jobs:\n  a:\n    env:\n      ${{ toJSON(secrets) }}: x\n    steps: []\n", dynamic: true},
	} {
		t.Run(name, func(t *testing.T) {
			names, dynamic, err := ReferencedSecrets([]byte(tc.payload))
			require.NoError(t, err)
			slices.Sort(names)
			assert.Equal(t, tc.names, names)
			assert.Equal(t, tc.dynamic, dynamic)
		})
	}
	_, _, err := ReferencedSecrets([]byte("a: [unclosed"))
	require.Error(t, err)
}

// Safety property: unless the job is dynamic, the names found are exactly the literal names the job writes. Forms that
// hide a read (an alias of inherit, an `if:` without braces, a name that folds onto another) fail safe.
func TestReferencedSecretsSafety(t *testing.T) {
	for name, tc := range map[string]struct {
		payload     string
		names       []string
		mustDynamic bool
	}{
		"if without braces, toJSON": {payload: "jobs:\n  a:\n    steps:\n      - if: contains(toJSON(secrets), 'x')\n        run: echo ${{ secrets.A }}\n", mustDynamic: true},
		"if without braces, deref":  {payload: "jobs:\n  a:\n    steps:\n      - if: secrets.B != ''\n        run: echo ${{ secrets.A }}\n", names: []string{"A", "B"}},
		"parenthesised":             {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ (secrets).A }}\n", names: []string{"A"}},
		"nested literal index":      {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ format('{0}', secrets['A']) }}\n", names: []string{"A"}},
		"expr text in a string":     {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ '${{' }} ${{ toJSON(secrets) }}\n", mustDynamic: true},
		"closing braces in string":  {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ format('}}{0}', toJSON(secrets)) }}\n", mustDynamic: true},
		"yaml escape":               {payload: "jobs:\n  a:\n    steps:\n      - run: \"\\u0024{{ toJSON(secrets) }}\"\n", mustDynamic: true},
		"long s folds to S":         {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ secrets.\u017fECRET }}\n", mustDynamic: true},
		"index of index":            {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ secrets['A']['B'] }}\n", names: []string{"A"}},
		"secrets index as operand":  {payload: "jobs:\n  a:\n    steps:\n      - run: ${{ fromJSON('{}')[secrets.A] }}\n", names: []string{"A"}},
		"inherit in a flow map":     {payload: "jobs: {a: {uses: ./x.yml, secrets: inherit}}\n", mustDynamic: true},
		"inherit via alias":         {payload: "x: &i inherit\njobs:\n  a:\n    uses: ./x.yml\n    secrets: *i\n", mustDynamic: true},
		"inherit with a tag":        {payload: "jobs:\n  a:\n    uses: ./x.yml\n    secrets: !!str inherit\n", mustDynamic: true},
	} {
		t.Run(name, func(t *testing.T) {
			names, dynamic, err := ReferencedSecrets([]byte(tc.payload))
			require.NoError(t, err)
			slices.Sort(names)
			if tc.mustDynamic {
				assert.True(t, dynamic)
			} else {
				assert.False(t, dynamic)
				assert.Equal(t, tc.names, names)
			}
		})
	}
}
