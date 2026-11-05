// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package cron

import (
	"context"
	"time"

	"forgejo.org/models"
	git_model "forgejo.org/models/git"
	user_model "forgejo.org/models/user"
	"forgejo.org/models/webhook"
	"forgejo.org/modules/git"
	"forgejo.org/modules/setting"
	actions_service "forgejo.org/services/actions"
	audit_service "forgejo.org/services/audit"
	"forgejo.org/services/auth"
	automerge_service "forgejo.org/services/automerge"
	dependency_service "forgejo.org/services/dependency"
	logshipping_service "forgejo.org/services/logshipping"
	"forgejo.org/services/mailer"
	mergequeue_service "forgejo.org/services/mergequeue"
	"forgejo.org/services/migrations"
	mirror_service "forgejo.org/services/mirror"
	packages_cleanup_service "forgejo.org/services/packages/cleanup"
	repo_service "forgejo.org/services/repository"
	archiver_service "forgejo.org/services/repository/archiver"
	secretscan_service "forgejo.org/services/secretscan"
	vulnerability_service "forgejo.org/services/vulnerability"
)

func registerUpdateMirrorTask() {
	type UpdateMirrorTaskConfig struct {
		BaseConfig
		PullLimit int
		PushLimit int
	}

	RegisterTaskFatal("update_mirrors", &UpdateMirrorTaskConfig{
		BaseConfig: BaseConfig{
			Enabled:    true,
			RunAtStart: false,
			Schedule:   "@every 10m",
		},
		PullLimit: 50,
		PushLimit: 50,
	}, func(ctx context.Context, _ *user_model.User, cfg Config) error {
		umtc := cfg.(*UpdateMirrorTaskConfig)
		return mirror_service.Update(ctx, umtc.PullLimit, umtc.PushLimit)
	})
}

func registerRepoHealthCheck() {
	type RepoHealthCheckConfig struct {
		BaseConfig
		Timeout time.Duration
		Args    []string `delim:" "`
	}
	RegisterTaskFatal("repo_health_check", &RepoHealthCheckConfig{
		BaseConfig: BaseConfig{
			Enabled:    true,
			RunAtStart: false,
			Schedule:   "@midnight",
		},
		Timeout: time.Duration(setting.Git.Timeout.Default) * time.Second,
		Args:    []string{},
	}, func(ctx context.Context, _ *user_model.User, config Config) error {
		rhcConfig := config.(*RepoHealthCheckConfig)
		// the git args are set by config, they can be safe to be trusted
		return repo_service.GitFsckRepos(ctx, rhcConfig.Timeout, git.ToTrustedCmdArgs(rhcConfig.Args))
	})
}

func registerCheckRepoStats() {
	RegisterTaskFatal("check_repo_stats", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@midnight",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return models.CheckRepoStats(ctx)
	})
}

func registerArchiveCleanup() {
	RegisterTaskFatal("archive_cleanup", &OlderThanConfig{
		BaseConfig: BaseConfig{
			Enabled:    true,
			RunAtStart: true,
			Schedule:   "@midnight",
		},
		OlderThan: 24 * time.Hour,
	}, func(ctx context.Context, _ *user_model.User, config Config) error {
		acConfig := config.(*OlderThanConfig)
		return archiver_service.DeleteOldRepositoryArchives(ctx, acConfig.OlderThan)
	})
}

func registerSyncExternalUsers() {
	RegisterTaskFatal("sync_external_users", &UpdateExistingConfig{
		BaseConfig: BaseConfig{
			Enabled:    true,
			RunAtStart: false,
			Schedule:   "@midnight",
		},
		UpdateExisting: true,
	}, func(ctx context.Context, _ *user_model.User, config Config) error {
		realConfig := config.(*UpdateExistingConfig)
		return auth.SyncExternalUsers(ctx, realConfig.UpdateExisting)
	})
}

func registerDeletedBranchesCleanup() {
	RegisterTaskFatal("deleted_branches_cleanup", &OlderThanConfig{
		BaseConfig: BaseConfig{
			Enabled:    true,
			RunAtStart: true,
			Schedule:   "@midnight",
		},
		OlderThan: 24 * time.Hour,
	}, func(ctx context.Context, _ *user_model.User, config Config) error {
		realConfig := config.(*OlderThanConfig)
		git_model.RemoveOldDeletedBranches(ctx, realConfig.OlderThan)
		return nil
	})
}

func registerUpdateMigrationPosterID() {
	RegisterTaskFatal("update_migration_poster_id", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@midnight",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return migrations.UpdateMigrationPosterID(ctx)
	})
}

func registerCleanupAuditLog() {
	RegisterTaskFatal("cleanup_audit_log", &BaseConfig{
		Enabled:    true,
		RunAtStart: false,
		Schedule:   "@midnight",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return audit_service.Cleanup(ctx)
	})
}

func registerDependencyGraphScan() {
	RegisterTaskFatal("dependency_graph_scan", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 1h",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		// the rows of repositories the dependency graph is off for (all of them while the site switch is off) go
		// first: a switch change deletes only a bounded number at once, and a scan may have written after it
		for more := true; more; {
			var err error
			if more, err = dependency_service.PurgeDisabled(ctx, 50); err != nil {
				return err
			}
		}
		return dependency_service.EnqueueUnscanned(ctx) // does nothing while the site switch is off
	})
}

func registerSecretScanningScan() {
	RegisterTaskFatal("secret_scanning_scan", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 1h",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return secretscan_service.EnqueueUnscanned(ctx) // does nothing while the site switch is off
	})
}

func registerVulnerabilityMirrorUpdate() {
	RegisterTaskFatal("vulnerability_mirror_update", &BaseConfig{
		Enabled:    true,
		RunAtStart: false,
		Schedule:   "@every 1h",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		// UPDATE_INTERVAL decides which ecosystems are due; nothing happens while the dependency graph is off
		return vulnerability_service.UpdateDue(ctx)
	})
}

func registerCleanupHookTaskTable() {
	RegisterTaskFatal("cleanup_hook_task_table", &CleanupHookTaskConfig{
		BaseConfig: BaseConfig{
			Enabled:    true,
			RunAtStart: false,
			Schedule:   "@midnight",
		},
		CleanupType:  "OlderThan",
		OlderThan:    168 * time.Hour,
		NumberToKeep: 10,
	}, func(ctx context.Context, _ *user_model.User, config Config) error {
		realConfig := config.(*CleanupHookTaskConfig)
		return webhook.CleanupHookTaskTable(ctx, webhook.ToHookTaskCleanupType(realConfig.CleanupType), realConfig.OlderThan, realConfig.NumberToKeep)
	})
}

func registerCleanupPackages() {
	RegisterTaskFatal("cleanup_packages", &OlderThanConfig{
		BaseConfig: BaseConfig{
			Enabled:    true,
			RunAtStart: true,
			Schedule:   "@midnight",
		},
		OlderThan: 24 * time.Hour,
	}, func(ctx context.Context, _ *user_model.User, config Config) error {
		realConfig := config.(*OlderThanConfig)
		return packages_cleanup_service.CleanupTask(ctx, realConfig.OlderThan)
	})
}

func registerStartScheduledAutoMerges() {
	RegisterTaskFatal("start_scheduled_auto_merges", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 1m",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return automerge_service.StartDueScheduledAutoMerges(ctx)
	})
}

func registerProcessMergeQueues() {
	RegisterTaskFatal("process_merge_queues", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 1m",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return mergequeue_service.TriggerAll(ctx)
	})
	RegisterTaskFatal("delete_stale_merge_queue_branches", &BaseConfig{
		Enabled:    true,
		RunAtStart: false,
		Schedule:   "@every 24h",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return mergequeue_service.DeleteStaleBranches(ctx)
	})
}

func registerStartScheduledDispatches() {
	RegisterTaskFatal("start_scheduled_dispatches", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 1m",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return actions_service.StartDueScheduledDispatches(ctx)
	})
}

func registerStartDueDeployments() {
	RegisterTaskFatal("start_due_deployments", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 1m",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return actions_service.StartDueDeployments(ctx)
	})
}

func registerExpireDeploymentReviews() {
	RegisterTaskFatal("expire_deployment_reviews", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 1h",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return actions_service.ExpireDeploymentReviews(ctx)
	})
}

func registerReloadLogShipping() {
	RegisterTaskFatal("reload_log_shipping", &BaseConfig{
		Enabled:    true,
		RunAtStart: true,
		Schedule:   "@every 30s",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return logshipping_service.Reload(ctx)
	})
}

func registerCredentialExpiryNotices() {
	RegisterTaskFatal("credential_expiry_notices", &BaseConfig{
		Enabled:    true,
		RunAtStart: false,
		Schedule:   "@every 1h",
	}, func(ctx context.Context, _ *user_model.User, _ Config) error {
		return mailer.SendCredentialExpiryNotices(ctx)
	})
}

func initBasicTasks() {
	if setting.Mirror.Enabled {
		registerUpdateMirrorTask()
	}
	registerRepoHealthCheck()
	registerCredentialExpiryNotices()
	registerCheckRepoStats()
	registerArchiveCleanup()
	registerSyncExternalUsers()
	registerDeletedBranchesCleanup()
	if !setting.Repository.DisableMigrations {
		registerUpdateMigrationPosterID()
	}
	registerCleanupHookTaskTable()
	registerCleanupAuditLog()
	registerDependencyGraphScan()
	registerSecretScanningScan()
	registerVulnerabilityMirrorUpdate()
	registerStartScheduledAutoMerges()
	registerProcessMergeQueues()
	registerStartScheduledDispatches()
	registerStartDueDeployments()
	registerExpireDeploymentReviews()
	registerReloadLogShipping()
	if setting.Packages.Enabled {
		registerCleanupPackages()
	}
}
