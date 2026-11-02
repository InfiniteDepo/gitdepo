// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package structs

import "time"

// Dependency is a package that a manifest of the repository's default branch declares.
// swagger:model
type Dependency struct {
	// The ecosystem, named as OSV names it: Go, npm, PyPI, Maven, NuGet, crates.io, RubyGems or Packagist
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// The version, empty if the manifest doesn't fix it
	Version string `json:"version"`
	// The version range the manifest declares when it doesn't fix the version (a manifest without a lock file)
	Requirement string `json:"requirement,omitempty"`
	// The package URL (purl) of the dependency
	PURL string `json:"purl"`
	// The path of the manifest in the repository
	ManifestPath string `json:"manifest_path"`
	// Whether the project itself declares it, not only another dependency
	Direct bool `json:"direct"`
	// The license as the manifest states it, empty if it doesn't
	License string `json:"license"`
}

// SkippedManifest is a manifest that was not read, or (code partially_read) read only in part.
// swagger:model
type SkippedManifest struct {
	Path string `json:"path"`
	// parse_error, manifest_too_large, too_many_manifests, too_many_dependencies, too_many_entries, invalid_path,
	// read_error or partially_read
	Code string `json:"code"`
	// partially_read: the lines naming a dependency that could not be read
	Lines int `json:"lines,omitempty"`
}

// DependencyScan is the state of the last scan of a repository.
// swagger:model
type DependencyScan struct {
	// pending (never scanned), ok or failed
	Status string `json:"status"`
	// The reason of a failed last scan: timeout, tree_too_large, git_error or internal_error. The dependencies of
	// the last good scan are kept.
	Error string `json:"error,omitempty"`
	// The commit of the default branch the dependencies were read from
	CommitSHA string `json:"commit_sha,omitempty"`
	// swagger:strfmt date-time
	ScannedAt        *time.Time        `json:"scanned_at,omitempty"`
	ManifestCount    int               `json:"manifest_count"`
	DependencyCount  int               `json:"dependency_count"`
	SkippedManifests []SkippedManifest `json:"skipped_manifests"`
}

// DependencyList is a page of the dependencies of a repository and the state of its scan.
// swagger:model
type DependencyList struct {
	Scan         DependencyScan `json:"scan"`
	Dependencies []*Dependency  `json:"dependencies"`
}

// DependencyRepository names a repository in a search result.
// swagger:model
type DependencyRepository struct {
	ID int64 `json:"id"`
	// The full name: owner/name, or owner/project/name for a repository in a project
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
	Private  bool   `json:"private"`
}

// DependencyUsage is a dependency of one repository in the result of an organization or instance search.
// swagger:model
type DependencyUsage struct {
	Repository DependencyRepository `json:"repository"`
	// The ecosystem, named as OSV names it
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// The version, empty if the manifest doesn't fix it
	Version string `json:"version"`
	// The version range the manifest declares when it doesn't fix the version
	Requirement  string `json:"requirement,omitempty"`
	ManifestPath string `json:"manifest_path"`
	Direct       bool   `json:"direct"`
	// Set by a range search for a row without a version whose requirement overlaps the range
	Uncertain bool `json:"uncertain"`
}
