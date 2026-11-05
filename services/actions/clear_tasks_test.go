// Copyright 2026 The Forgejo Authors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package actions

import (
	"testing"

	actions_model "forgejo.org/models/actions"
	"forgejo.org/models/db"
	"forgejo.org/models/unittest"
	"forgejo.org/modules/timeutil"
	notify_service "forgejo.org/services/notify"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCancelAbandonedJobs(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestCancelAbandonedJobs")()
	require.NoError(t, unittest.PrepareTestDatabase())

	notifier := notify_service.NewMockNotifier(t)
	notifier.On("Run").Return().Maybe()
	notifier.On("WorkflowJobCompleted", mock.Anything, mock.Anything, mock.Anything).Return()
	notifier.On("WorkflowRunStatusChanged", mock.Anything, mock.Anything, mock.Anything).Return()

	notify_service.RegisterNotifier(notifier)
	defer notify_service.UnregisterNotifier(notifier)

	require.NoError(t, CancelAbandonedJobs(t.Context()))

	// status waiting, too long, ready to be abandoned
	job := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 600})
	assert.Equal(t, actions_model.StatusCancelled, job.Status)

	// status blocked, too long, ready to be abandoned
	job = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 601})
	assert.Equal(t, actions_model.StatusCancelled, job.Status)

	// status blocked, *not* too long, not to be abandoned
	job = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 602})
	assert.Equal(t, actions_model.StatusBlocked, job.Status)

	// status running, not to be abandoned
	job = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 603})
	assert.Equal(t, actions_model.StatusRunning, job.Status)

	// related run needs approval, not to be abandoned
	job = unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 604})
	assert.Equal(t, actions_model.StatusWaiting, job.Status)

	notifier.AssertNumberOfCalls(t, "WorkflowJobCompleted", 2)
	notifier.AssertNumberOfCalls(t, "WorkflowRunStatusChanged", 1)
	notifier.AssertCalled(
		t, "WorkflowJobCompleted", mock.Anything,
		mock.MatchedBy(func(job *actions_model.ActionRunJob) bool {
			return job.ID == 600 && job.Status == actions_model.StatusCancelled
		}),
		actions_model.StatusWaiting,
	)
	notifier.AssertCalled(
		t, "WorkflowJobCompleted", mock.Anything,
		mock.MatchedBy(func(job *actions_model.ActionRunJob) bool {
			return job.ID == 601 && job.Status == actions_model.StatusCancelled
		}),
		actions_model.StatusBlocked,
	)
	notifier.AssertCalled(
		t, "WorkflowRunStatusChanged", mock.Anything,
		mock.MatchedBy(func(run *actions_model.ActionRun) bool {
			return run.ID == 900 && run.Status == actions_model.StatusRunning
		}),
		actions_model.StatusUnknown,
	)
}

// A job that the wait timer of its environment holds is not abandoned, however long ago it was created.
func TestCancelAbandonedJobsKeepsHeldJob(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestCancelAbandonedJobs")()
	require.NoError(t, unittest.PrepareTestDatabase())

	notifier := notify_service.NewMockNotifier(t)
	notifier.On("Run").Return().Maybe()
	notifier.On("WorkflowJobCompleted", mock.Anything, mock.Anything, mock.Anything).Return()
	notifier.On("WorkflowRunStatusChanged", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	notify_service.RegisterNotifier(notifier)
	defer notify_service.UnregisterNotifier(notifier)

	// job 601 is blocked and long past ABANDONED_JOB_TIMEOUT; its deployment waits for the timer
	held := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 601})
	require.NoError(t, db.Insert(t.Context(), &actions_model.ActionDeployment{
		RepoID: held.RepoID, RunID: held.RunID, JobID: held.ID, Attempt: held.Attempt,
		Status: actions_model.DeploymentWaitingTimer, ReleaseAfterUnix: timeutil.TimeStampNow() + 3600,
	}))

	require.NoError(t, CancelAbandonedJobs(t.Context()))
	assert.Equal(t, actions_model.StatusBlocked, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 601}).Status)
	assert.Equal(t, actions_model.StatusCancelled, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 600}).Status, "others still are")

	// once the deployment no longer waits (here: a refusal), the job is abandoned as before
	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET status = ? WHERE job_id = 601", actions_model.DeploymentRefused)
	require.NoError(t, err)
	require.NoError(t, CancelAbandonedJobs(t.Context()))
	assert.Equal(t, actions_model.StatusCancelled, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 601}).Status)
}

// A held job is the gate's only while its timer runs or a review waits: with the start_due_deployments task off, a job
// whose timer ended is abandoned like any other, and a review has its own expiry.
func TestCancelAbandonedJobsTimerEnded(t *testing.T) {
	defer unittest.OverrideFixtures("services/actions/TestCancelAbandonedJobs")()
	require.NoError(t, unittest.PrepareTestDatabase())

	notifier := notify_service.NewMockNotifier(t)
	notifier.On("Run").Return().Maybe()
	notifier.On("WorkflowJobCompleted", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	notifier.On("WorkflowRunStatusChanged", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	notify_service.RegisterNotifier(notifier)
	defer notify_service.UnregisterNotifier(notifier)

	held := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 601})
	require.NoError(t, db.Insert(t.Context(), &actions_model.ActionDeployment{
		RepoID: held.RepoID, RunID: held.RunID, JobID: held.ID, Attempt: held.Attempt,
		Status: actions_model.DeploymentWaitingReview, ReleaseAfterUnix: timeutil.TimeStampNow() - 3600,
	}))
	require.NoError(t, CancelAbandonedJobs(t.Context()))
	assert.Equal(t, actions_model.StatusBlocked, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 601}).Status, "waiting for a review")

	_, err := db.GetEngine(t.Context()).Exec("UPDATE action_deployment SET status = ? WHERE job_id = 601", actions_model.DeploymentWaitingTimer)
	require.NoError(t, err)
	require.NoError(t, CancelAbandonedJobs(t.Context()))
	assert.Equal(t, actions_model.StatusCancelled, unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunJob{ID: 601}).Status, "the timer ended")
}
