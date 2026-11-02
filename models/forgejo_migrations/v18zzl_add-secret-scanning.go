// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the secret scanning state, alerts and locations, and the repository's own switch",
		Upgrade:     addSecretScanning,
	})
}

type v18zzlSecretScan struct {
	ID           int64  `xorm:"pk autoincr"`
	RepoID       int64  `xorm:"UNIQUE(repo_kind) NOT NULL"`
	Kind         string `xorm:"VARCHAR(8) UNIQUE(repo_kind) NOT NULL"`
	ScannedTips  string `xorm:"LONGTEXT"`
	Status       string `xorm:"VARCHAR(16) NOT NULL DEFAULT ''"`
	Error        string `xorm:"VARCHAR(32) NOT NULL DEFAULT ''"`
	Blobs        int64  `xorm:"NOT NULL DEFAULT 0"`
	Bytes        int64  `xorm:"NOT NULL DEFAULT 0"`
	SkippedLarge int64  `xorm:"NOT NULL DEFAULT 0"`
	Version      int64  `xorm:"NOT NULL DEFAULT 0"`
	FailCount    int    `xorm:"NOT NULL DEFAULT 0"`
	RetryUnix    int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	Holes        int64  `xorm:"NOT NULL DEFAULT 0"`
	UpdatedUnix  int64  `xorm:"INDEX updated"`
}

func (v18zzlSecretScan) TableName() string {
	return "secret_scan"
}

type v18zzlSecretScanningAlert struct {
	ID            int64  `xorm:"pk autoincr"`
	RepoID        int64  `xorm:"UNIQUE(repo_rule_fingerprint) UNIQUE(repo_index) INDEX(repo_state) NOT NULL"`
	Index         int64  `xorm:"UNIQUE(repo_index) NOT NULL"`
	RuleID        string `xorm:"VARCHAR(64) UNIQUE(repo_rule_fingerprint) NOT NULL"`
	SecretType    string `xorm:"VARCHAR(32) NOT NULL DEFAULT ''"`
	Fingerprint   string `xorm:"VARCHAR(64) UNIQUE(repo_rule_fingerprint) NOT NULL"`
	KeyVersion    int    `xorm:"SMALLINT NOT NULL DEFAULT 1"`
	State         string `xorm:"VARCHAR(16) INDEX(repo_state) NOT NULL DEFAULT 'open'"`
	Reason        string `xorm:"VARCHAR(16) NOT NULL DEFAULT ''"`
	Comment       string `xorm:"TEXT"`
	ClosedByID    int64  `xorm:"NOT NULL DEFAULT 0"`
	ClosedUnix    int64  `xorm:"NOT NULL DEFAULT 0"`
	LocationCount int    `xorm:"NOT NULL DEFAULT 0"`
	ViaPull       bool   `xorm:"NOT NULL DEFAULT false"`
	CreatedUnix   int64  `xorm:"created"`
	UpdatedUnix   int64  `xorm:"updated"`
}

func (v18zzlSecretScanningAlert) TableName() string {
	return "secret_scanning_alert"
}

type v18zzlSecretScanningLocation struct {
	ID        int64  `xorm:"pk autoincr"`
	AlertID   int64  `xorm:"UNIQUE(alert_location) NOT NULL"`
	RepoID    int64  `xorm:"INDEX NOT NULL"`
	Kind      string `xorm:"VARCHAR(8) UNIQUE(alert_location) NOT NULL"`
	BlobID    string `xorm:"VARCHAR(64) UNIQUE(alert_location) NOT NULL"`
	Path      string `xorm:"TEXT"`
	PathHash  string `xorm:"VARCHAR(64) UNIQUE(alert_location) NOT NULL"`
	StartLine int    `xorm:"UNIQUE(alert_location) NOT NULL DEFAULT 0"`
	EndLine   int    `xorm:"NOT NULL DEFAULT 0"`
	CommitID  string `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	// AuthorName and AuthorEmail are the commit's text, for display only
	AuthorName  string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	AuthorEmail string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	CommitUnix  int64  `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzlSecretScanningLocation) TableName() string {
	return "secret_scanning_location"
}

// v18zzlSecretScanningAlertIndex is the per-repository alert number, like issue_index.
type v18zzlSecretScanningAlertIndex struct {
	GroupID  int64 `xorm:"pk"`
	MaxIndex int64 `xorm:"index"`
}

func (v18zzlSecretScanningAlertIndex) TableName() string {
	return "secret_scanning_alert_index"
}

// v18zzlRepository adds the repository's own switch of secret scanning.
type v18zzlRepository struct {
	SecretScanningDisabled bool `xorm:"NOT NULL DEFAULT false"`
}

func (v18zzlRepository) TableName() string {
	return "repository"
}

func addSecretScanning(x *xorm.Engine) error {
	if err := x.Sync(new(v18zzlSecretScan), new(v18zzlSecretScanningAlert), new(v18zzlSecretScanningLocation), new(v18zzlSecretScanningAlertIndex)); err != nil {
		return err
	}
	// v18zzlRepository names one column: without the options, Sync would drop the indexes and unique keys of the
	// repository table
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true, IgnoreConstrains: true}, new(v18zzlRepository))
	return err
}
