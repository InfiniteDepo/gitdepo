// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package v1

import (
	"net/http"
	"strings"
	"testing"

	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"
	apiv1_permissions_testhelpers "forgejo.org/routers/api/v1/permissions/testhelpers"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRepoRouteParity checks that every repository route exists at each address of a repository (mountRepoRoutes)
// with the same middlewares and permission checks, so a route added outside the mounts fails here.
func TestRepoRouteParity(t *testing.T) {
	defer test.MockVariableValue(&setting.IsInTesting, true)()
	routes := Routes()

	families := []struct{ forms []string }{
		{[]string{"/repos/{username}/{reponame}", "/repos/{username}/{groupname}/{reponame}/-", "/repositories/{repo_id}"}},
		{[]string{"/user/starred/{username}/{reponame}", "/user/starred/{username}/{groupname}/{reponame}/-"}},
	}
	// split returns the family, the form and the rest of the pattern of a repository route
	split := func(pattern string) (family, form int, rest string, ok bool) {
		for f, family := range families {
			for i, prefix := range family.forms {
				if pattern == prefix || strings.HasPrefix(pattern, prefix+"/") {
					return f, i, strings.TrimPrefix(pattern, prefix), true
				}
			}
		}
		return 0, 0, "", false
	}
	type key struct {
		family  int
		methods string
		rest    string
	}

	// the full middleware chain of each route, by its number of middlewares
	chains := map[key]map[int]int{}
	require.NoError(t, chi.Walk(routes.R, func(method, route string, _ http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		if family, form, rest, ok := split(route); ok {
			k := key{family, method, rest}
			if chains[k] == nil {
				chains[k] = map[int]int{}
			}
			chains[k][form] = len(middlewares)
		}
		return nil
	}))
	require.NotEmpty(t, chains)
	for k, forms := range chains {
		for form := range families[k.family].forms {
			if assert.Contains(t, forms, form, "%s %s missing at %s", k.methods, k.rest, families[k.family].forms[form]) {
				assert.Equal(t, forms[0], forms[form], "%s %s: middlewares differ at %s", k.methods, k.rest, families[k.family].forms[form])
			}
		}
	}

	// the permission checks of each route
	signatures := map[key]map[int]string{}
	for methodsAndPattern, sequence := range apiv1_permissions_testhelpers.GetMethodsAndPatternToSignatures() {
		methods, pattern, _ := strings.Cut(methodsAndPattern, " ")
		if family, form, rest, ok := split(pattern); ok {
			k := key{family, methods, rest}
			if signatures[k] == nil {
				signatures[k] = map[int]string{}
			}
			signatures[k][form] = apiv1_permissions_testhelpers.SignaturesToString(sequence)
		}
	}
	require.NotEmpty(t, signatures)
	for k, forms := range signatures {
		for form := range families[k.family].forms {
			if assert.Contains(t, forms, form, "%s %s missing at %s", k.methods, k.rest, families[k.family].forms[form]) {
				assert.Equal(t, forms[0], forms[form], "%s %s", k.methods, k.rest)
			}
		}
	}
}
