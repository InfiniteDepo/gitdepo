// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the dependency graph of repositories",
		Upgrade:     addRepoDependency,
	})
}

type v18zzjRepoDependency struct {
	ID           int64  `xorm:"pk autoincr"`
	RepoID       int64  `xorm:"INDEX NOT NULL"`
	Ecosystem    string `xorm:"VARCHAR(16) INDEX(ecosystem_name) NOT NULL"`
	Name         string `xorm:"VARCHAR(512) INDEX(ecosystem_name) NOT NULL"`
	Version      string `xorm:"VARCHAR(256) NOT NULL DEFAULT ''"`
	Requirement  string `xorm:"VARCHAR(256) NOT NULL DEFAULT ''"`
	ManifestPath string `xorm:"VARCHAR(1024) NOT NULL DEFAULT ''"`
	Direct       bool   `xorm:"NOT NULL DEFAULT false"`
	License      string `xorm:"VARCHAR(256) NOT NULL DEFAULT ''"`
}

func (v18zzjRepoDependency) TableName() string {
	return "repo_dependency"
}

type v18zzjRepoDependencyScan struct {
	ID              int64  `xorm:"pk autoincr"`
	RepoID          int64  `xorm:"UNIQUE NOT NULL"`
	CommitSHA       string `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	ScannedUnix     int64  `xorm:"NOT NULL DEFAULT 0"`
	Status          string `xorm:"VARCHAR(16) NOT NULL DEFAULT ''"`
	Error           string `xorm:"VARCHAR(32) NOT NULL DEFAULT ''"`
	ManifestCount   int    `xorm:"NOT NULL DEFAULT 0"`
	DependencyCount int    `xorm:"NOT NULL DEFAULT 0"`
	Skipped         string `xorm:"TEXT"`
}

func (v18zzjRepoDependencyScan) TableName() string {
	return "repo_dependency_scan"
}

// v18zzjRepository adds the repository's own switch of the dependency graph.
type v18zzjRepository struct {
	DependencyGraphDisabled bool `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzjRepository) TableName() string {
	return "repository"
}

func addRepoDependency(x *xorm.Engine) error {
	return x.Sync(new(v18zzjRepoDependency), new(v18zzjRepoDependencyScan), new(v18zzjRepository))
}
