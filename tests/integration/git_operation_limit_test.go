// Copyright 2026 The gitdepo contributors. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

package integration

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"forgejo.org/models/db"
	"forgejo.org/modules/git"
	"forgejo.org/modules/private"
	"forgejo.org/modules/setting"
	"forgejo.org/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitOperationLimit(t *testing.T) {
	defer test.MockVariableValue(&setting.Git.MaxConcurrentOperations, 1)()
	defer test.MockVariableValue(&setting.Git.OperationQueueTimeout, 100*time.Millisecond)()

	onApplicationRun(t, func(t *testing.T, u *url.URL) {
		uploadPack := func() *http.Response {
			req, err := http.NewRequest("POST", u.String()+"user2/repo1.git/git-upload-pack", bytes.NewBufferString("0000"))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			return resp
		}

		t.Run("HTTP", func(t *testing.T) {
			release, err := git.AcquireOperation(t.Context())
			require.NoError(t, err)
			resp := uploadPack()
			release()
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			assert.Equal(t, strconv.Itoa(git.OperationRetryAfter), resp.Header.Get("Retry-After"))

			assert.Equal(t, http.StatusOK, uploadPack().StatusCode)
		})

		t.Run("SSH", func(t *testing.T) {
			release, err := git.AcquireOperation(t.Context())
			require.NoError(t, err)
			_, extra := private.ServOperationSlot(t.Context())
			release()
			assert.Equal(t, http.StatusServiceUnavailable, extra.StatusCode)
			assert.Contains(t, extra.UserMsg, "busy")

			// serv holds the slot until it closes the connection
			release, extra = private.ServOperationSlot(t.Context())
			require.NoError(t, extra.Error)
			_, err = git.AcquireOperation(t.Context())
			require.ErrorIs(t, err, git.ErrServerBusy)
			release()
			assert.Eventually(t, func() bool {
				release, err := git.AcquireOperation(db.DefaultContext)
				if err != nil {
					return false
				}
				release()
				return true
			}, 5*time.Second, 50*time.Millisecond)
		})
	})
}
