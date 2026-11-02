// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package common

import (
	"net/http"
	"time"

	repo_model "forgejo.org/models/repo"
	"forgejo.org/modules/httplib"
	"forgejo.org/services/context"
	dependency_service "forgejo.org/services/dependency"

	"github.com/google/uuid"
)

// ServeSBOM writes the SBOM of the scanned repository as a download in the given format (spdx or cyclonedx) and
// records it in the audit log. The document is made from the stored dependencies only. It returns false, having
// written nothing, if the document can't be made.
func ServeSBOM(ctx *context.Base, repo *repo_model.Repository, sbom *dependency_service.SBOM, format string) bool {
	var (
		body []byte
		err  error
	)
	switch format {
	case dependency_service.FormatCycloneDX:
		body, err = sbom.GenerateCycloneDX(time.Now(), uuid.New())
	default:
		format = dependency_service.FormatSPDX
		body, err = sbom.GenerateSPDX(time.Now(), uuid.New())
	}
	if err != nil {
		return false
	}
	size := int64(len(body))
	httplib.ServeSetHeaders(ctx.Resp, &httplib.ServeHeaderOptions{
		ContentType:   "application/json",
		Filename:      dependency_service.SBOMFileName(repo, format),
		ContentLength: &size,
	})
	ctx.Resp.WriteHeader(http.StatusOK)
	_, _ = ctx.Resp.Write(body)
	RecordDownload(ctx, repo, "sbom", sbom.Scan.CommitSHA)
	return true
}
