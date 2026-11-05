// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package forgejo_migrations

import (
	"code.forgejo.org/xorm/xorm"
)

func init() {
	registerMigration(&Migration{
		Description: "add Actions environments, their deployments, secrets and variables",
		Upgrade:     addActionsEnvironments,
	})
}

type v18zzpActionEnvironment struct {
	ID                int64  `xorm:"pk autoincr"`
	OwnerID           int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	RepoID            int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	Name              string `xorm:"VARCHAR(255) NOT NULL"`
	LowerName         string `xorm:"VARCHAR(255) UNIQUE(owner_repo_name) NOT NULL"`
	RefPolicy         int    `xorm:"NOT NULL DEFAULT 0"`
	RefPatterns       string `xorm:"JSON TEXT"`
	WaitTimerMinutes  int    `xorm:"NOT NULL DEFAULT 0"`
	PreventSelfReview bool   `xorm:"NOT NULL DEFAULT false"`
	RunnerLabels      string `xorm:"JSON TEXT"`
	Created           int64  `xorm:"created"`
	Updated           int64  `xorm:"updated"`
}

func (v18zzpActionEnvironment) TableName() string {
	return "action_environment"
}

type v18zzpActionDeployment struct {
	ID               int64  `xorm:"pk autoincr"`
	RepoID           int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	EnvironmentID    int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	RunID            int64  `xorm:"NOT NULL DEFAULT 0"`
	JobID            int64  `xorm:"UNIQUE(job_attempt) NOT NULL DEFAULT 0"`
	Attempt          int64  `xorm:"UNIQUE(job_attempt) NOT NULL DEFAULT 0"`
	Ref              string `xorm:"VARCHAR(255)"`
	CommitSHA        string `xorm:"VARCHAR(64)"`
	URL              string `xorm:"VARCHAR(1024)"`
	TriggerUserID    int64  `xorm:"NOT NULL DEFAULT 0"`
	Status           int    `xorm:"INDEX NOT NULL DEFAULT 0"`
	Reason           string `xorm:"VARCHAR(64)"`
	ReleaseAfterUnix int64  `xorm:"NOT NULL DEFAULT 0"`
	Created          int64  `xorm:"created"`
	Updated          int64  `xorm:"updated"`
}

func (v18zzpActionDeployment) TableName() string {
	return "action_deployment"
}

type v18zzpSecret struct {
	ID            int64  `xorm:"pk autoincr"`
	OwnerID       int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL"`
	GroupID       int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	RepoID        int64  `xorm:"INDEX UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	EnvironmentID int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	Name          string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
}

func (v18zzpSecret) TableName() string {
	return "secret"
}

type v18zzpActionVariable struct {
	ID            int64  `xorm:"pk autoincr"`
	OwnerID       int64  `xorm:"UNIQUE(owner_repo_name)"`
	GroupID       int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	RepoID        int64  `xorm:"INDEX UNIQUE(owner_repo_name)"`
	EnvironmentID int64  `xorm:"UNIQUE(owner_repo_name) NOT NULL DEFAULT 0"`
	Name          string `xorm:"UNIQUE(owner_repo_name) NOT NULL"`
}

func (v18zzpActionVariable) TableName() string {
	return "action_variable"
}

type v18zzpActionRunJob struct {
	ID              int64  `xorm:"pk autoincr"`
	EnvironmentName string `xorm:"VARCHAR(255) NOT NULL DEFAULT ''"`
}

func (v18zzpActionRunJob) TableName() string {
	return "action_run_job"
}

func addActionsEnvironments(x *xorm.Engine) error {
	// the name is unique per owner, project, repository and environment: recreate the indexes with environment_id
	for _, table := range []string{"secret", "action_variable"} {
		if err := dropIndexIfExists(x, table, "UQE_"+table+"_owner_repo_name"); err != nil {
			return err
		}
	}
	_, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true},
		new(v18zzpActionEnvironment), new(v18zzpActionDeployment), new(v18zzpSecret), new(v18zzpActionVariable), new(v18zzpActionRunJob))
	return err
}
