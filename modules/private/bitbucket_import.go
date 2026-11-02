// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package private

import (
	"context"
	"fmt"
	"time"
)

// BitbucketImportParams are the parameters of a Bitbucket import run by the server.
type BitbucketImportParams struct {
	Doer         string
	Org          string
	Server       string
	Username     string
	Token        string
	Projects     []string
	DryRun       bool
	PullRequests bool
	KeyExpiry    string
	SkipUnmapped bool
}

// String never prints the token.
func (p BitbucketImportParams) String() string {
	return fmt.Sprintf("{doer: %s, org: %s, server: %s, projects: %v, dry run: %t}", p.Doer, p.Org, p.Server, p.Projects, p.DryRun)
}

// GoString never prints the token.
func (p BitbucketImportParams) GoString() string {
	return p.String()
}

// BitbucketImport asks the server to plan, and unless it is a dry run, to run a Bitbucket import; it returns the
// report as JSON.
func BitbucketImport(ctx context.Context, params BitbucketImportParams) (string, ResponseExtra) {
	req := newInternalRequest(ctx, "/api/internal/bitbucket_import", "POST", params)
	req.SetTimeout(3*time.Second, 0) // an import takes long: no timeout
	report, extra := requestJSONResp(req, &ResponseText{})
	if extra.HasError() {
		return "", extra
	}
	return report.Text, extra
}
