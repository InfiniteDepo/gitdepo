// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"forgejo.org/modules/private"
	"forgejo.org/services/migrations"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestBitbucketImportToken(t *testing.T) {
	var names []string
	for _, f := range subcmdBitbucketImport().Flags {
		assert.NotContains(t, f.Names(), "token", "the token is never a command-line argument")
		names = append(names, f.Names()...)
	}
	assert.Contains(t, names, "key-expiry")

	cmd := subcmdBitbucketImport()
	var params private.BitbucketImportParams
	cmd.Action = func(_ context.Context, c *cli.Command) error {
		params = bitbucketImportParams(c, "tok")
		return nil
	}
	require.NoError(t, cmd.Run(t.Context(), []string{"bitbucket-import", "--server", "https://bb.example.com", "--org", "org3", "--doer", "user2", "--key-expiry", "2030-01-02", "--project", "PAY", "--skip-unmapped"}))
	assert.Equal(t, private.BitbucketImportParams{Doer: "user2", Org: "org3", Server: "https://bb.example.com", Token: "tok", Projects: []string{"PAY"}, PullRequests: true, KeyExpiry: "2030-01-02", SkipUnmapped: true}, params)

	t.Setenv("BITBUCKET_TOKEN", "")
	_, err := bitbucketToken("")
	require.Error(t, err)

	t.Setenv("BITBUCKET_TOKEN", "from-env")
	token, err := bitbucketToken("")
	require.NoError(t, err)
	assert.Equal(t, "from-env", token)

	file := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(file, []byte("from-file\n"), 0o600))
	token, err = bitbucketToken(file)
	require.NoError(t, err)
	assert.Equal(t, "from-file", token, "the file wins")
}

func TestBitbucketImportOutput(t *testing.T) {
	report := &migrations.BitbucketImportReport{Items: []*migrations.BitbucketImportItem{
		{Kind: "project", Bitbucket: "PAY", Name: "org3/pay", Status: "planned"},
		{Kind: "repository", Bitbucket: "PAY/api", Name: "org3/pay/api", Status: "conflict", Reason: "bad\x1b[2Jname\r\n", OldSSH: "=HYPERLINK(\"x\")", OldHTTP: "https://bb.example.com/scm/pay/api.git"},
		{Kind: "repository", Bitbucket: "PAY/web", Name: "org3/pay/web", Status: "created", NewHTTP: "https://gitdepo.example.com/org3/pay/web.git"},
		{Kind: "key", Bitbucket: "PAY key 1", Name: "ci", Target: "org3/pay", Status: "planned", Access: "read", Expires: "2030-01-02"},
	}}

	var out bytes.Buffer
	printBitbucketReport(&out, report)
	assert.NotContains(t, out.String(), "\x1b")
	assert.Equal(t, 4, strings.Count(out.String(), "\n"), "one line per item")
	assert.Contains(t, out.String(), "on org3/pay, read, expires 2030-01-02")
	assert.Contains(t, out.String(), "https://gitdepo.example.com/org3/pay/web.git", "the new URL is printed")

	out.Reset()
	require.NoError(t, writeBitbucketCSV(&out, report))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 4, "a header and a row per project and repository")
	assert.True(t, strings.HasPrefix(lines[0], "kind,"))
	assert.True(t, strings.HasPrefix(lines[1], "project,PAY,"))
	assert.Contains(t, lines[2], `'=HYPERLINK`)
	assert.Contains(t, lines[2], "https://bb.example.com/scm/pay/api.git")
}
