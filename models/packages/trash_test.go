// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package packages_test

import (
	"testing"

	"forgejo.org/models/db"
	packages_model "forgejo.org/models/packages"
	container_model "forgejo.org/models/packages/container"
	"forgejo.org/models/unittest"
	container_module "forgejo.org/modules/packages/container"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Packages linked to a repository in the trash can't be found, listed, pulled or described, even though their
// owner is still there; a package that isn't linked keeps working.
func TestPackagesOfTrashedRepository(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()

	p, err := packages_model.TryInsertPackage(ctx, &packages_model.Package{OwnerID: 2, RepoID: 3, Name: "img", LowerName: "img", Type: packages_model.TypeContainer})
	require.NoError(t, err)
	pv, err := packages_model.GetOrInsertVersion(ctx, &packages_model.PackageVersion{PackageID: p.ID, Version: "latest", LowerVersion: "latest", CreatorID: 2})
	require.NoError(t, err)
	_, err = packages_model.TryInsertFile(ctx, &packages_model.PackageFile{VersionID: pv.ID, BlobID: 1, Name: container_model.ManifestFilename, LowerName: container_model.ManifestFilename})
	require.NoError(t, err)
	_, err = packages_model.InsertProperty(ctx, packages_model.PropertyTypeVersion, pv.ID, container_module.PropertyManifestTagged, "true")
	require.NoError(t, err)

	found := func() map[string]bool {
		res := map[string]bool{}
		tags, err := container_model.GetImageTags(ctx, 2, "img", 10, "")
		require.NoError(t, err)
		res["tags"] = len(tags) > 0
		pvs, err := container_model.GetManifestVersions(ctx, &container_model.BlobSearchOptions{OwnerID: 2, Image: "img", IsManifest: true})
		require.NoError(t, err)
		res["manifests"] = len(pvs) > 0
		pvs, _, err = packages_model.SearchVersions(ctx, &packages_model.PackageSearchOptions{OwnerID: 2, Type: packages_model.TypeContainer})
		require.NoError(t, err)
		res["versions"] = len(pvs) > 0
		pfs, _, err := packages_model.SearchFiles(ctx, &packages_model.PackageFileSearchOptions{VersionID: pv.ID})
		require.NoError(t, err)
		res["files by version"] = len(pfs) > 0
		pfs, _, err = packages_model.SearchFiles(ctx, &packages_model.PackageFileSearchOptions{OwnerID: 2, PackageType: packages_model.TypeContainer})
		require.NoError(t, err)
		res["files by owner"] = len(pfs) > 0
		_, err = packages_model.GetPackageByName(ctx, 2, packages_model.TypeContainer, "img")
		res["package"] = err == nil
		return res
	}

	for name, ok := range found() {
		assert.True(t, ok, "%s before trashing", name)
	}

	_, err = db.GetEngine(ctx).Exec("UPDATE `repository` SET trashed_unix = 1 WHERE id = 3")
	require.NoError(t, err)

	for name, ok := range found() {
		assert.False(t, ok, "%s after trashing", name)
	}
	_, err = packages_model.GetPackageDescriptor(ctx, pv)
	require.ErrorIs(t, err, packages_model.ErrPackageNotExist)
}
