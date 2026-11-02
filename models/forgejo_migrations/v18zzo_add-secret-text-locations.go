// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add the places of secrets found in issue and comment text",
		Upgrade:     addSecretTextLocations,
	})
}

// v18zzoSecretScanningLocation is the whole table, so that Sync keeps its unique key; the new columns are the last five.
type v18zzoSecretScanningLocation struct {
	ID          int64  `xorm:"pk autoincr"`
	AlertID     int64  `xorm:"UNIQUE(alert_location) NOT NULL"`
	RepoID      int64  `xorm:"INDEX NOT NULL"`
	Kind        string `xorm:"VARCHAR(8) UNIQUE(alert_location) NOT NULL"`
	BlobID      string `xorm:"VARCHAR(64) UNIQUE(alert_location) NOT NULL"`
	Path        string `xorm:"TEXT"`
	PathHash    string `xorm:"VARCHAR(64) UNIQUE(alert_location) NOT NULL"`
	StartLine   int    `xorm:"UNIQUE(alert_location) NOT NULL DEFAULT 0"`
	EndLine     int    `xorm:"NOT NULL DEFAULT 0"`
	CommitID    string `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	AuthorName  string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	AuthorEmail string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
	CommitUnix  int64  `xorm:"NOT NULL DEFAULT 0"`

	// of a place in the text of an issue, pull request or comment (kinds "issue" and "comment")
	SourceID    int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	IssueID     int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	Field       string `xorm:"VARCHAR(8) NOT NULL DEFAULT ''"`
	PosterID    int64  `xorm:"NOT NULL DEFAULT 0"`
	RemovedUnix int64  `xorm:"NOT NULL DEFAULT 0"`
}

func (v18zzoSecretScanningLocation) TableName() string {
	return "secret_scanning_location"
}

func addSecretTextLocations(x *xorm.Engine) error {
	return x.Sync(new(v18zzoSecretScanningLocation))
}
